import PEUtil
from PEAnalyzeTool import PEAnalyzer

if __name__ == '__main__':
    #peutil = PEUtil.PEUtil("C:\\Program Files (x86)\\Mozilla Firefox\\crashreporter.exe")
    peutil = PEUtil.PEUtil('C:\\Program Files (x86)\Adobe\\Acrobat Reader DC\\Reader\\AcroRd32.exe')
    execute_section = peutil.get_executable_section()
    execute_section_data = peutil.get_section_raw_data(execute_section)
    entry_point_va = peutil.get_entry_point_va()

    peanalyzer = PEAnalyzer(execute_section, execute_section_data, entry_point_va)
    peanalyzer.gen_control_flow_graph()
    peanalyzer.save_cfg("C:\\work\\cfg.test", peutil.get_pe_name())
