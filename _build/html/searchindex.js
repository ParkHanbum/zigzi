Search.setIndex({docnames:["index","zigzi"],envversion:52,filenames:["index.rst","zigzi.rst"],objects:{"":{zigzi:[1,0,0,"-"]},"zigzi.CodeManager":{CodeManager:[1,1,1,""]},"zigzi.CodeManager.CodeManager":{code_handled:[1,2,1,""],get_base_rva:[1,2,1,""],get_code:[1,2,1,""],get_data_at_offset:[1,2,1,""],get_data_from_offset_with_format:[1,2,1,""],get_data_from_rva:[1,2,1,""],get_dword_from_offset:[1,2,1,""],get_format_from_size:[1,3,1,""],get_format_from_size_little_endian:[1,3,1,""],instrument:[1,2,1,""],instrument_at_last:[1,2,1,""],instrument_with_replace:[1,2,1,""],is_need_code_handle:[1,2,1,""],need_code_handle:[1,2,1,""],set_data_at_offset_with_format:[1,2,1,""],set_instruction_at_offset:[1,2,1,""]},"zigzi.DataObject":{DataObject:[1,1,1,""]},"zigzi.DataObject.DataObject":{append_byte:[1,2,1,""],append_chunk:[1,2,1,""],append_dword:[1,2,1,""],append_finish:[1,2,1,""],append_word:[1,2,1,""],base_address:[1,4,1,""],declare_byte:[1,2,1,""],declare_dword:[1,2,1,""],declare_word:[1,2,1,""],get_current_base_pos:[1,2,1,""],get_variable_reference:[1,2,1,""],get_variable_value:[1,2,1,""],init_byte_order:[1,2,1,""],is_append_not_finish:[1,2,1,""],save_local_variable:[1,2,1,""],set_variable_value:[1,2,1,""],size:[1,4,1,""]},"zigzi.DataSegment":{Chunk:[1,1,1,""]},"zigzi.DataSegment.Chunk":{get_va:[1,2,1,""]},"zigzi.Disassembler":{Disassembler:[1,1,1,""]},"zigzi.Disassembler.Disassembler":{disassemble:[1,2,1,""],disassemble_dict_handle:[1,2,1,""],disassemble_list_handle:[1,2,1,""],get_disassemble_dict:[1,2,1,""],get_disassemble_list:[1,2,1,""],get_opcode_length:[1,3,1,""],is_branch:[1,3,1,""],is_call:[1,3,1,""],is_indirect_branch:[1,3,1,""],is_need_handle_disassemble_dict:[1,2,1,""],is_need_handle_disassemble_list:[1,2,1,""],is_relative_branch:[1,3,1,""],is_return:[1,3,1,""],need_handle_disassemble_list:[1,2,1,""],need_handled_disassemble_dict:[1,2,1,""]},"zigzi.Heap":{Heap:[1,1,1,""]},"zigzi.Heap.Heap":{append_element:[1,2,1,""],append_element_finish:[1,2,1,""],append_string:[1,2,1,""]},"zigzi.Log":{Logger:[1,1,1,""],LoggerFactory:[1,1,1,""],Singleton:[1,1,1,""]},"zigzi.Log.Logger":{fin:[1,2,1,""],get_log_path:[1,2,1,""],log:[1,2,1,""]},"zigzi.Log.LoggerFactory":{get_new_logger:[1,2,1,""]},"zigzi.PEAnalyzeTool":{BasicBlock:[1,1,1,""],PEAnalyzer:[1,1,1,""]},"zigzi.PEAnalyzeTool.BasicBlock":{append:[1,2,1,""],getStartAddress:[1,2,1,""],toDotNode:[1,2,1,""]},"zigzi.PEAnalyzeTool.PEAnalyzer":{OPERAND_ABSOLUTE_ADDRESS:[1,4,1,""],OPERAND_FAR_MEMORY:[1,4,1,""],OPERAND_IMMEDIATE:[1,4,1,""],OPERAND_MEMORY:[1,4,1,""],OPERAND_NONE:[1,4,1,""],OPERAND_REGISTER:[1,4,1,""],assignNewBranch:[1,2,1,""],genControlFlowGraph:[1,2,1,""],handleConrolFlow:[1,2,1,""],handle_FC_CALL:[1,2,1,""],handle_FC_CND_BRANCH:[1,2,1,""],handle_FC_NONE:[1,2,1,""],handle_FC_RET:[1,2,1,""],handle_FC_SYS:[1,2,1,""],handle_FC_UNC_BRANCH:[1,2,1,""],parse:[1,2,1,""],parser:[1,2,1,""],removeInstructionFromMap:[1,2,1,""],save_cfg:[1,2,1,""]},"zigzi.PEInstrument":{PEInstrument:[1,1,1,""]},"zigzi.PEInstrument.PEInstrument":{adjust_direct_branches:[1,2,1,""],adjust_instruction_layout:[1,2,1,""],adjust_registers_instruction_operand:[1,2,1,""],append_code:[1,2,1,""],do_instrument:[1,2,1,""],falloc:[1,2,1,""],from_filename:[1,5,1,""],get_code:[1,2,1,""],get_instructions:[1,2,1,""],get_instrumented_pos:[1,2,1,""],get_instrumented_size:[1,2,1,""],get_instrumented_total_size:[1,2,1,""],get_instrumented_vector_size:[1,2,1,""],get_pe_manager:[1,2,1,""],handle_overflowed_instrument:[1,2,1,""],instrument:[1,2,1,""],is_after_indirect_branch_instrument_exist:[1,2,1,""],is_after_relative_branch_instrument_exist:[1,2,1,""],is_after_return_instrument_exist:[1,2,1,""],is_pre_indirect_branch_instrument_exist:[1,2,1,""],is_pre_relative_branch_instrument_exist:[1,2,1,""],is_pre_return_instrument_exist:[1,2,1,""],merge_adjust_pos_with_prev:[1,2,1,""],register_after_indirect_branch:[1,2,1,""],register_after_relative_branch:[1,2,1,""],register_after_return:[1,2,1,""],register_pre_indirect_branch:[1,2,1,""],register_pre_relative_branch:[1,2,1,""],register_pre_return:[1,2,1,""],save_instrument_history:[1,2,1,""],writefile:[1,2,1,""]},"zigzi.PEManager":{PEManager:[1,1,1,""]},"zigzi.PEManager.PEManager":{adjust_TLS:[1,2,1,""],adjust_bound_imports:[1,2,1,""],adjust_data_in_range:[1,2,1,""],adjust_debug:[1,2,1,""],adjust_delay_import:[1,2,1,""],adjust_directories:[1,2,1,""],adjust_export:[1,2,1,""],adjust_file_layout:[1,2,1,""],adjust_iat:[1,2,1,""],adjust_import:[1,2,1,""],adjust_load_config:[1,2,1,""],adjust_relocation:[1,2,1,""],adjust_relocation_directories:[1,2,1,""],adjust_relocation_offset:[1,2,1,""],adjust_resource:[1,2,1,""],append_data_to_file:[1,2,1,""],append_relocation_entry_to_block:[1,2,1,""],append_section_to_file:[1,2,1,""],create_new_data_section:[1,2,1,""],create_new_executable_section:[1,2,1,""],gen_new_empty_import_descriptor:[1,2,1,""],gen_new_empty_import_thunk:[1,2,1,""],gen_new_relocation_block:[1,2,1,""],gen_new_relocation_entry:[1,2,1,""],get_abs_va_from_offset:[1,2,1,""],get_abs_va_from_rva:[1,2,1,""],get_aligned_offset:[1,2,1,""],get_aligned_rva:[1,2,1,""],get_bytes_at_offset:[1,2,1,""],get_cloned_section_header:[1,3,1,""],get_data_directory_address_range:[1,2,1,""],get_data_section:[1,2,1,""],get_entry_point_rva:[1,2,1,""],get_file_data:[1,2,1,""],get_image_base:[1,2,1,""],get_image_size:[1,2,1,""],get_import_address_table_address_range:[1,2,1,""],get_import_descriptor_address_range:[1,2,1,""],get_import_structures:[1,2,1,""],get_imports_range_in_structures:[1,2,1,""],get_instrument:[1,2,1,""],get_new_empty_thunk:[1,2,1,""],get_relocation:[1,2,1,""],get_relocation_directories:[1,2,1,""],get_relocation_from_structures:[1,2,1,""],get_section_alignment:[1,2,1,""],get_section_belong_rva:[1,2,1,""],get_section_raw_data:[1,2,1,""],get_structure_from_rva:[1,2,1,""],get_text_section:[1,2,1,""],get_text_section_virtual_address_range:[1,2,1,""],is_executable_section:[1,3,1,""],is_possible_relocation:[1,2,1,""],register_rva_to_relocation:[1,2,1,""],relocation_entry_move_to_appropriate_block:[1,2,1,""],set_dword_at_rva:[1,2,1,""],set_entry_point:[1,2,1,""],set_instrument:[1,2,1,""],writefile:[1,2,1,""],writefile_without_adjust:[1,2,1,""]},"zigzi.SampleReturnVerifier":{simple_instrument_error_handler:[1,6,1,""],simple_instrument_return_address_at_after_branch:[1,6,1,""],simple_instrument_return_address_verifier_at_pre_return:[1,6,1,""]},"zigzi.Stack":{Stack:[1,1,1,""]},"zigzi.Stack.Stack":{base_point:[1,4,1,""],frame_point:[1,4,1,""],pop:[1,2,1,""],push:[1,2,1,""]},"zigzi.WindowAPIHelper":{WindowAPIHelper:[1,1,1,""]},"zigzi.WindowAPIHelper.WindowAPIHelper":{add_dll_to_import_descriptor:[1,2,1,""],add_function_to_import:[1,2,1,""],add_message_box:[1,2,1,""],adjust_data_directory_size:[1,2,1,""],adjust_references_of_iat:[1,2,1,""],append_import_thunk_to_descriptor:[1,2,1,""],append_import_thunk_to_next_of_descriptor:[1,2,1,""],append_to_iat:[1,2,1,""],gen_new_import_lookup_table:[1,2,1,""],gen_new_import_thunk:[1,2,1,""],gen_new_thunk:[1,2,1,""],gen_separator_thunk:[1,2,1,""],get_iat_rva_with_size:[1,2,1,""],get_last_import_address_thunk:[1,2,1,""],get_last_import_descriptor:[1,2,1,""],get_last_import_descriptor_offset:[1,2,1,""],get_last_import_lookup_thunk:[1,2,1,""],get_last_import_thunk_offset:[1,2,1,""],get_ordinal_from_common_library:[1,2,1,""],is_already_import_dll:[1,2,1,""],is_already_import_function:[1,2,1,""],move_imports_offset_to_new_section:[1,2,1,""],print_imports_offset:[1,2,1,""],save_modified_imports:[1,2,1,""]},zigzi:{CodeManager:[1,0,0,"-"],DataObject:[1,0,0,"-"],DataSegment:[1,0,0,"-"],Disassembler:[1,0,0,"-"],Heap:[1,0,0,"-"],Log:[1,0,0,"-"],PEAnalyzeTool:[1,0,0,"-"],PEInstrument:[1,0,0,"-"],PEManager:[1,0,0,"-"],SampleReturnVerifier:[1,0,0,"-"],Stack:[1,0,0,"-"],WindowAPIHelper:[1,0,0,"-"],do_indirect_branch_counting:[1,6,1,""],do_return_address_verifier:[1,6,1,""],simple_indirect_branch_counting_function_call_instrument:[1,6,1,""],simple_indirect_branch_counting_function_instrument:[1,6,1,""],simple_return_address_save_function:[1,6,1,""]}},objnames:{"0":["py","module","Python module"],"1":["py","class","Python class"],"2":["py","method","Python method"],"3":["py","staticmethod","Python static method"],"4":["py","attribute","Python attribute"],"5":["py","classmethod","Python class method"],"6":["py","function","Python function"]},objtypes:{"0":"py:module","1":"py:class","2":"py:method","3":"py:staticmethod","4":"py:attribute","5":"py:classmethod","6":"py:function"},terms:{"4byte":1,"5byte":1,"6byte":1,"byte":1,"case":1,"class":1,"function":1,"import":1,"int":1,"new":1,"return":1,"static":1,"true":1,"while":1,For:1,JNS:1,SYS:1,The:1,_code_manag:1,_str:1,absolut:1,absolutememori:1,absolutememoryaddress:1,accord:1,add:1,add_dll_to_import_descriptor:1,add_function_to_import:1,add_message_box:1,added:1,address:1,adjust:1,adjust_bound_import:1,adjust_data_directory_s:1,adjust_data_in_rang:1,adjust_debug:1,adjust_delay_import:1,adjust_direct_branch:1,adjust_directori:1,adjust_export:1,adjust_file_layout:1,adjust_iat:1,adjust_import:1,adjust_instruction_layout:1,adjust_load_config:1,adjust_references_of_iat:1,adjust_registers_instruction_operand:1,adjust_reloc:1,adjust_relocation_directori:1,adjust_relocation_offset:1,adjust_resourc:1,adjust_section_end:1,adjust_section_start:1,adjust_tl:1,after:1,align:1,aligned_data_len:1,aligned_orig_data_len:1,all:1,alloc:1,alwai:1,analyz:1,api:1,append:1,append_byt:1,append_chunk:1,append_cod:1,append_data_to_fil:1,append_dword:1,append_el:1,append_element_finish:1,append_finish:1,append_import_thunk_to_descriptor:1,append_import_thunk_to_next_of_descriptor:1,append_relocation_entry_to_block:1,append_section_to_fil:1,append_str:1,append_to_iat:1,append_word:1,appli:1,appropri:1,archiv:1,argument:1,asm:1,assembl:1,assign:1,assignnewbranch:1,attr_data:1,attribut:1,backward:1,base:1,base_address:1,base_point:1,basic_block:1,basic_block_s:1,basicblock:1,becaus:1,befor:1,being:1,belong:1,binari:1,block:1,block_index:1,block_rva:1,bool:1,box:1,branch:1,broken:1,bytearrai:1,calcul:1,call:1,can:1,capston:1,caus:1,cfi:1,chang:1,check:1,chunk:1,classmethod:1,clone:1,code:1,code_handl:1,codemanag:0,com:1,common:1,compil:1,contain:1,content:0,contion:1,control:1,convert:1,copi:1,copyright:1,correct:1,count:1,cover:1,creat:1,create_new_data_sect:1,create_new_executable_sect:1,current:1,data:1,data_directori:1,data_list:1,dataobject:0,dataseg:0,debug:1,declar:1,declare_byt:1,declare_dword:1,declare_word:1,decod:1,descriptor:1,destin:1,detail:1,determin:1,dict:1,direct:1,directori:1,disassembl:0,disassemble_dict_handl:1,disassemble_list_handl:1,dispatch:1,disssembl:1,distribut:1,dll:1,dll_import_descriptor:1,dll_name:1,dll_name_rva:1,do_indirect_branch_count:1,do_instru:1,do_return_address_verifi:1,dst_adjust_dict:1,due:1,dure:1,dword:1,element:1,empti:1,end:1,engin:1,entri:1,entry_nam:1,entry_point_va:1,entry_va:1,error:1,exampl:1,exce:1,exclud:1,execut:1,execute_sect:1,execute_section_data:1,exist:1,expand:1,extend:1,falloc:1,fals:1,far:1,farmemori:1,featur:1,file:1,file_path:1,filenam:1,fill:1,fin:1,find:1,finish:1,first:1,first_thunk_rva:1,fix:1,flow:1,fn_name:1,fn_rva:1,follow:1,format:1,formula:1,frame_point:1,from:1,from_filenam:1,futur:1,gap_siz:1,gen_new_empty_import_descriptor:1,gen_new_empty_import_thunk:1,gen_new_import_lookup_t:1,gen_new_import_thunk:1,gen_new_relocation_block:1,gen_new_relocation_entri:1,gen_new_thunk:1,gen_separator_thunk:1,gencontrolflowgraph:1,gener:1,get:1,get_abs_va_from_offset:1,get_abs_va_from_rva:1,get_aligned_offset:1,get_aligned_rva:1,get_base_rva:1,get_bytes_at_offset:1,get_cloned_section_head:1,get_cod:1,get_current_base_po:1,get_data_at_offset:1,get_data_directory_address_rang:1,get_data_from_offset_with_format:1,get_data_from_rva:1,get_data_sect:1,get_disassemble_dict:1,get_disassemble_list:1,get_dword_from_offset:1,get_entry_point_rva:1,get_file_data:1,get_format_from_s:1,get_format_from_size_little_endian:1,get_iat_rva_with_s:1,get_image_bas:1,get_image_s:1,get_import_address_table_address_rang:1,get_import_descriptor_address_rang:1,get_import_structur:1,get_imports_range_in_structur:1,get_instru:1,get_instruct:1,get_instrumented_po:1,get_instrumented_s:1,get_instrumented_size_with_vector:1,get_instrumented_total_s:1,get_instrumented_vector_s:1,get_last_import_address_thunk:1,get_last_import_descriptor:1,get_last_import_descriptor_offset:1,get_last_import_lookup_thunk:1,get_last_import_thunk_offset:1,get_log_path:1,get_new_empty_thunk:1,get_new_logg:1,get_opcode_length:1,get_ordinal_from_common_librari:1,get_pe_manag:1,get_reloc:1,get_relocation_directori:1,get_relocation_from_structur:1,get_section_align:1,get_section_belong_rva:1,get_section_raw_data:1,get_structure_from_rva:1,get_text_sect:1,get_text_section_virtual_address_rang:1,get_va:1,get_variable_refer:1,get_variable_valu:1,getstartaddress:1,given:1,gmail:1,hanbum:1,handl:1,handle_fc_cal:1,handle_fc_cnd_branch:1,handle_fc_non:1,handle_fc_ret:1,handle_fc_si:1,handle_fc_unc_branch:1,handle_overflowed_instru:1,handleconrolflow:1,handled_overflowed_pos_dict:1,handler:1,has:1,header:1,heap:0,helper:1,hex:1,iat:1,iat_rva:1,ilt:1,imag:1,image_base_reloc:1,image_base_relocation_entri:1,image_directory_entry_basereloc:1,image_directory_entry_bound_import:1,image_directory_entry_debug:1,image_directory_entry_delay_import:1,image_directory_entry_export:1,image_directory_entry_import:1,image_directory_entry_load_config:1,image_directory_entry_resourc:1,image_directory_entry_tl:1,image_import_descriptor:1,image_thunk_data:1,immedi:1,implement:1,import_descriptor:1,import_thunk:1,includ:1,increas:1,increase_s:1,independ:1,index:[0,1],indirect:1,info:1,inform:1,init_byte_ord:1,init_valu:1,insert:1,inst:1,instruct:1,instrument:1,instrument_at_last:1,instrument_instruct:1,instrument_pos_dict:1,instrument_with_replac:1,instrumented_pos_dict:1,instrumentor:1,integr:1,iret:1,is_after_indirect_branch_instrument_exist:1,is_after_relative_branch_instrument_exist:1,is_after_return_instrument_exist:1,is_already_import_dl:1,is_already_import_funct:1,is_append_not_finish:1,is_branch:1,is_cal:1,is_executable_sect:1,is_indirect_branch:1,is_need_code_handl:1,is_need_handle_disassemble_dict:1,is_need_handle_disassemble_list:1,is_possible_reloc:1,is_pre_indirect_branch_instrument_exist:1,is_pre_relative_branch_instrument_exist:1,is_pre_return_instrument_exist:1,is_relative_branch:1,is_return:1,its:1,jae:1,jbe:1,jcxz:1,jge:1,jle:1,jmp:1,jno:1,jnp:1,jnz:1,kese111:1,keyston:1,kind:1,last:1,last_el:1,later:1,layout:1,length:1,librari:1,like:1,list:1,locat:1,log:0,log_nam:1,logger:1,loggerfactori:1,lookup:1,loop:1,loopnz:1,loopz:1,mai:1,make:1,manag:1,map:1,match:1,mean:1,memori:1,merg:1,merge_adjust_pos_with_prev:1,messag:1,messageboxa:1,method:1,migrat:1,modifi:1,modul:0,move:1,move_imports_offset_to_new_sect:1,msg:1,must:1,name:1,necessari:1,need:1,need_code_handl:1,need_handle_disassemble_list:1,need_handled_disassemble_dict:1,neg:1,newobject:1,next:1,none:1,notic:1,number:1,object:1,occur:1,offset:1,offset_end:1,offset_start:1,offset_stop:1,one:1,opcod:1,operand:1,operand_absolute_address:1,operand_far_memori:1,operand_immedi:1,operand_memori:1,operand_non:1,operand_regist:1,order:1,ordin:1,origin:1,origin_instruction_s:1,origin_section_end:1,origin_section_start:1,otherwis:1,overflow:1,own:1,packag:0,page:0,param:1,paramet:1,park:1,pars:1,parser:1,part:1,pass:1,path:1,pe_instru:1,pe_manag:1,peanalyz:1,peanalyzetool:0,peinstrument:0,pemanag:0,platform:1,point:1,pop:1,portabl:1,posit:1,possibl:1,previou:1,print_imports_offset:1,push:1,rang:1,rav:1,raw:1,reach:1,redirect:1,refer:1,reflect:1,regist:1,register_after_indirect_branch:1,register_after_relative_branch:1,register_after_return:1,register_pre_indirect_branch:1,register_pre_relative_branch:1,register_pre_return:1,register_rva_to_reloc:1,rel:1,relat:1,reloc:1,relocation_entry_move_to_appropriate_block:1,removeinstructionfrommap:1,repres:1,reserv:1,result:1,ret:1,retf:1,right:1,root:1,rva:1,sampl:1,samplereturnverifi:0,save_cfg:1,save_instrument_histori:1,save_local_vari:1,save_modified_import:1,save_path:1,scope:1,search:0,section:1,secur:1,see:1,segment:1,separ:1,sequenc:1,set:1,set_data_at_offset_with_format:1,set_dword_at_rva:1,set_entry_point:1,set_instru:1,set_instruction_at_offset:1,set_variable_valu:1,simple_indirect_branch_counting_function_call_instru:1,simple_indirect_branch_counting_function_instru:1,simple_instrument_error_handl:1,simple_instrument_return_address_at_after_branch:1,simple_instrument_return_address_verifier_at_pre_return:1,simple_return_address_save_funct:1,sinc:1,singleton:1,size:1,small:1,sort:1,sourc:1,space:1,specif:1,src_adjust_dict:1,stack:0,stack_siz:1,start:1,start_va:1,str:1,string:1,structur:1,submodul:0,support:1,syscal:1,sysent:1,sysexit:1,sysret:1,tabl:1,target:1,text:1,thi:1,thing:1,thunk:1,todotnod:1,too:1,tool:1,total:1,total_count:1,tupl:1,type:1,uncondit:1,until:1,use:1,user:1,util:1,valu:1,variabl:1,variable_nam:1,verifi:1,virtual:1,when:1,where:1,whether:1,which:1,window:1,windowapihelp:0,word:1,work:1,write:1,writefil:1,writefile_without_adjust:1,x86:1,yet:1,zero:1},titles:["Welcome to zigzi\u2019s documentation!","zigzi package"],titleterms:{codemanag:1,content:1,dataobject:1,dataseg:1,disassembl:1,document:0,heap:1,indic:0,log:1,modul:1,packag:1,peanalyzetool:1,peinstrument:1,pemanag:1,samplereturnverifi:1,stack:1,submodul:1,tabl:0,welcom:0,windowapihelp:1,zigzi:[0,1]}})