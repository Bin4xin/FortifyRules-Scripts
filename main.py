#  Copyright (c) 2023.
#
#  @Bin4xin. SENTINEL CYBER SEC All Rights Reserved.
#  @Link https://github.com/Bin4xin
import sys


# fileDir = "C:\\Users\\607\\iCloudDrive\\pythonProject\\workspace\\Fortify-ruls-xml\\zh-cn"
# targetDir = "C:\\Users\\607\\iCloudDrive\\pythonProject\\workspace\\Fortify-ruls-xml\\zh-cn-csv"
fileDir = sys.argv[1]
targetDir = sys.argv[2]
# TODO: get fileDir and targetDir from console line. \
#  e.g. python3 main.py $fileDir $targetDir


if __name__ == '__main__':
    try:
        # xml.dom.minidom.parseString()
        from Fortify_JavaRulesParse_test import testFilesToParser
        testFilesToParser(fileDir)
        """
        Step1、传入转换文件文件夹、生成文件文件夹，并根据文件夹内的文件名生成对应的csv文件，这里需要的是：
            - 1.1、规则库对应的规则语言；（写入csv文件中，对应行：”语言“）
            - 1.2、返回转换前的文件的名称。（解析对应转换前的文件的内容）
            @:param fileDir、targetDir
            @:return 
                - AbsolutelyFilePath = fileDir+targetFile
                - langUpperColumns

        Step2、传入解析函数
            - 2.1、解析文件绝对/相对路径可以得到对应列的值；
            - 2.2、获得的值应包含：lang<UpperColumns> | ruleID | vulnCateForAll
            @:param AbsolutelyFilePath | langUpperColumns
            @:return
                - lang<UpperColumns> <head>    | ruleID <head>    | vulnCateForAll <head>
                - lang<UpperColumns> <columns> | ruleID <columns> | vulnCateForAll <columns>
                - lang<UpperColumns> <columns> | ruleID <columns> | vulnCateForAll <columns>

        Step3、写入表格文件，需考虑写入形式
            ? 单列写入
            ? 或多列共同写入
        """

        # from utils import insert_csv_data
        # insert_csv_data.insertData(extendWithFullName, lang.upper())

        # TODO: prepare to send a parameter from console that include a dir path, then could \
        #  get all xml files from this dir.
        # initCVS(extName)
        # main(extName)
    except:
        print('ERROR: Failed to convert the data.')
        raise
    print("OK, conversion is done.")
