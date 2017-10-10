Return Address Verifier
=======================

이번 장에서 ``Zigzi`` 를 활용하여 ``Runtime`` 에 함수의 복귀주소를 검증하는 기법인
``Return Address Verifier`` 를 구현해보고 이를 통해서 ``Zigzi`` 를 기반으로
``Binary Instrumentation`` 을 활용한 기능을 ``Binary`` 에 추가하는 방법을
살펴보겠습니다.


PE
~~~

먼저 Instrumentation 기능을 사용하기 위해 ``PEInstrument`` 모듈을,
``Binary rewriting`` 기능을 사용하기 위해 ``File Manager`` 인 ``PEManager``
모듈을 import 합니다.

.. code-block:: python

    from PEInstrument import *
    from PEManager import *
    from WindowAPIHelper import *

또한 Return Address Verifier 를 통해 함수의 복귀주소가 변조됐을 시에 이를
시각적으로 보여주기 위해서 ``MessageBoxA`` 를 사용할 목적으로 ``WindowAPIHelper``
모듈 또한 import 합니다.

.. code-block:: python

    # PE Manager
    pe_manager = PEManager(filename)
    # add api
    window_api_helper = WindowAPIHelper(pe_manager)
    message_box_fn_rva = window_api_helper.add_message_box()
    # set new instrumentation
    pe_instrument = PEInstrument(pe_manager)

    # instrument return address verifier feature to binary
    do_return_address_verifier(pe_instrument, pe_manager, message_box_fn_rva)

이제 원하는 Binary의 경로와 이름으로 생성된 PEManager와 WindowAPIHelper를 통해
PEInstrument 와 MessageBox API의 Relative Virtual Address 값을 얻습니다.

Return Address Verifier 기능을 구현하는 과정은 아래에서 다룹니다.

.. code-block:: python

    def do_return_address_verifier(pe_instrument, pe_manager, fn_rva):
        simple_instrument_error_handler(pe_instrument, pe_manager, fn_rva)

        # case of relative branch instruction
        pe_instrument.register_after_relative_branch(
            simple_instrument_return_address_at_after_branch
        )
        # case of indirect branch instruction
        pe_instrument.register_after_indirect_branch(
            simple_instrument_return_address_at_after_branch
        )

        # case of return instruction
        pe_instrument.register_pre_return(
            simple_instrument_return_address_verifier_at_pre_return
        )
        pe_instrument.do_instrument()


Return Address Verifier 을 구현하는 과정은 크게 세 단계로 이루어집니다. 첫 번째,
과정으로 함수의 복귀주소 검증이 실패했을시 이를 시각적으로 보여주기 위해서
``MessageBox`` 를 띄우는 API 호출 로직을 추가하는 과정입니다.

.. code-block:: python

    def simple_instrument_error_handler(pe_instrument, pe_manager, fn_rva):
        global code_rva
        fn_va = pe_manager.get_abs_va_from_rva(fn_rva)

        allocation = pe_instrument.falloc(0x1000)
        caption = "Zigzi"
        text = "Failed to Verifying Return Address."

        allocation_va = allocation.get_va()
        caption_start_pos = 0
        text_start_pos = 0x100
        allocation[caption_start_pos:len(caption)] = caption
        allocation[text_start_pos:len(text)] = text

        code = ("push 0;"   # UINT    uType
                "push {};"   # LPCTSTR lpCaption,
                "push {};"   # LPCTSTR lpText,
                "push 0;"   # HWND    hWnd
                "call [{}];").format(allocation_va + caption_start_pos,
                                     allocation_va + text_start_pos,
                                     fn_va)
        code_rva = pe_instrument.append_code(code)
        pe_manager.register_rva_to_relocation(code_rva
                                              + 3   # push 0; push
                                              )
        pe_manager.register_rva_to_relocation(code_rva
                                              + 3   # push 0; push
                                              + 5   # lpCaption;push
                                              )
        pe_manager.register_rva_to_relocation(code_rva
                                              + 3   # push 0; push
                                              + 5   # lpCaption;push
                                              + 4   # lptext
                                              + 2   # push 0;
                                              + 2   # call
                                              )

첫 번째 과정은,
1. MessageBox 에 인자로 사용할 Text ``Zigzi`` 와 ``Failed to Verifying Return Address.``
를 Binary에 삽입 합니다.
2. 1에서 Text가 삽입된 주소와 MessageBox API의 RVA(Relative Virtual Address)를
기반으로 MessageBox를 호출하는 로직을 어셈블리어로 코딩하여 추가합니다.
3. Text들과 MessageBox의 RVA는 상대주소이므로 Relocation 목록에 추가합니다.
로 이루어지게 됩니다.

위의 과정을 통해서 MessageBox를 호출하는 함수를 Binary에 추가했고 해당 함수의
RVA를 획득합니다.

.. code-block:: python

    def simple_instrument_return_address_at_after_branch(instruction):
        code = ("prefetch [{0}]".format(instruction.address
                                        + instruction.size
                                        + 0x1000))
        hex_code = binascii.hexlify(code).decode('hex')
        try:
            # Initialize engine in X86-32bit mode
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
            encoding, count = ks.asm(hex_code)
            return encoding, count
        except KsError as ex:
            print("ERROR: %s" % ex)
        return None, 0

우리가 이미 알다시피 함수를 호출하는 경우에 복귀할 주소는 해당 함수를 호출한 지점의
다음 명령어입니다. 때문에 분기 명령어 계통의 다음 주소는 항상 복귀할 주소입니다.

이 원리에 따라 모든 분기 명령어의 다음에 해당 분기 명령어의 다음 주소(복귀주소)
에 해당 주소의 값을 저장하는 공간을 만듭니다.

실행 간에 영향을 미치지 않도록 이 주소의 값을 저장하기 위해서 우리는 ``prefetch``
명령어를 사용할 것 입니다.


.. code-block:: python

    def simple_instrument_return_address_verifier_at_pre_return(instruction):
        global code_rva
        code = (
            "push ecx;"             # store value
            "mov ecx, [esp+4];"     # load return address to ecx
            "cmp [ecx+3], ecx;"     # compare return address with RAV
            "jne {};"       # if not equal, jump to error handler
            "pop ecx;"              # recover value
        ).format(code_rva - instruction.address - 0x1000
                 + 0xF  # instruction size till end of instruction.
                 )
        hex_code = binascii.hexlify(code).decode('hex')
        try:
            # Initialize engine in X86-32bit mode
            ks = Ks(KS_ARCH_X86, KS_MODE_32)
            encoding, count = ks.asm(hex_code)
            return encoding, count
        except KsError as ex:
            print("ERROR: %s" % ex)
        return None, 0

이제 함수가 호출된 후에 복귀를 하는 시점에, 스택에 저장된 복귀할 주소와 해당 주소에
우리가 instrumentation 한 명령어 ``prefetch`` 의 operand 주소를 비교하면 복귀주소의
검증을 수행할 수 있습니다.


결과는 다음과 같네요.



시연
~~~~

.. raw:: html

    <div style="margin-top:10px;">
      <iframe width="560" height="315" src="https://www.youtube.com/embed/PvMBNOIPZs8" frameborder="0" allowfullscreen></iframe>
    </div>