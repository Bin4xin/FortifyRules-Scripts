#  Copyright (c) 2022.
#
#  @Bin4xin. SENTINEL CYBER SEC All Rights Reserved.
#  @Link https://github.com/Bin4xin


try:
    import xml.etree.cElementTree as et
except ImportError:
    import xml.etree.ElementTree as et
from xml.dom.minidom import parse
import xml.dom.minidom
import csv
import os
import re
from main import targetDir


class ExceptionRaise(Exception):
    """解析异常"""
    pass


def testFilesToParser(fileDir):
    # TODO: \
    #  1.1 xml文件存在多个标签包含<VulnCategory>，解析内容存在遗漏；
    #  ruleList = ['DataflowSinkRule', 'CharacterizationRule', 'SemanticRule']
    # [x] 1.2 运行代码时，当下目录会写入相同文件。
    ignoreList = [
        # filename
        ".DS_Store",
        ".gitignore",
        # file extends
        "exe"
    ]
    for filename in os.listdir(fileDir):
        if filename in ignoreList or filename[-3:] in ignoreList:
            raise ExceptionRaise("ERROR: Plz type in a file extend with XML not like {}.".format(filename))
            pass
        else:
            # extended_java_xml.csv
            rule = r'_(.*?)\.'
            langList = re.findall(rule, filename)
            # for lang in langList:
            #     print(lang.upper())
            langUpperColumns = [lang.upper() for lang in langList].pop()
            XmlFilesParseLogic_main(fileDir + filename, langUpperColumns)
            # import insert_csv_data
            # init_csv(targetFileFullName, "Lang")
            # insert_csv_data.insertData(targetFileFullName, lang.upper())


def init_csv(csvName):
    with open(csvName, "w", encoding="utf-8", newline="") as file:
        # Write/New a csv File
        head = ["Lang", "rule ID", "Vulnerable Category"]
        # head = ["语言", "规则ID", "漏洞类型"]
        f = csv.writer(file)
        f.writerow(head)
        # TODO: Looks like xml file's available parameter more than 2 rows \
        #   How about write rows by variable length parameter \
        #   ;)


def writeIntoCSV(wirter_FilesPath, langUpperColumns, ruleID, VulnCateForAll):
    with open(wirter_FilesPath, "a+", encoding="utf-8", newline="") as file:
        f = csv.writer(file)
        rows = [(langUpperColumns, ruleID, VulnCateForAll), ]
        f.writerows(rows)


def XmlFilesParseLogic_main(AbsolutelyFilePath, langUpperColumns):
    # print(AbsolutelyFilePath, langUpperColumns)
    targetFile = os.path.split(AbsolutelyFilePath)[1]
    # extended_java.xml
    extendWithFullName = targetFile.replace(".xml", "_xml") + ".csv"
    wirter_FilesPath = targetDir + extendWithFullName
    print("{}[:::]{}".format(AbsolutelyFilePath, wirter_FilesPath))
    """
    @:return 
        - AbsolutelyFilePath = fileDir+targetFile
        - langUpperColumns
    """
    DOMTree = xml.dom.minidom.parse(AbsolutelyFilePath)
    collection = DOMTree.documentElement
    if "extended_config.xml" in AbsolutelyFilePath:
        Rules = collection.getElementsByTagName("ConfigurationRule")
    elif "extended_javascript.xml" in AbsolutelyFilePath \
            or "comm_php.xml" in AbsolutelyFilePath \
            or "comm_cloud.xml" in AbsolutelyFilePath \
            or "core_annotations.xml" in AbsolutelyFilePath:
        Rules = collection.getElementsByTagName("StructuralRule")
        # comm_cloud.xml
        # comm_php.xml
        # extended_content.xml
        # extended_javascript.xml
    elif "extended_content.xml" in AbsolutelyFilePath:
        Rules = collection.getElementsByTagName("ContentRule")
    elif "comm_universal.xml" in AbsolutelyFilePath \
            or "core_universal.xml" in AbsolutelyFilePath:
        Rules = collection.getElementsByTagName("RegexRule")
        # comm_universal.xml
        # core_universal.xml
    else:
        ruleList = ['DataflowSinkRule', 'CharacterizationRule', 'SemanticRule']
    for rule in ruleList:
        print(rule)
        Rules = collection.getElementsByTagName(rule)
    # Here is a single label to parser. Could parser files like a para.
    # init_csv(wirter_FilesPath)
        for Rule in Rules:
            """
            @:param:
             - 漏洞名称 VulnCateForAll = VulnCategory.childNodes[0].data + /
                        Rule.getElementsByTagName('VulnSubcategory')[0].childNodes[0].data
                <VulnCategory 标签解析，位于DataflowSinkRule/RegexRule/etc..父标签下；>
             - 漏洞ID ruleID = Rule.getElementsByTagName('RuleID')[0]
             - 漏洞描述
            """
            # VulnCategory = Rule.getElementsByTagName('VulnCategory')[0]
            ruleID = Rule.getElementsByTagName('RuleID')[0].childNodes[0].data
            try:
                print(ruleID)
                """
                if VulnCategory and Rule.getElementsByTagName('VulnSubcategory')[0] != '':
                    VulnCateForAll = VulnCategory.childNodes[0].data + ": " + \
                                     Rule.getElementsByTagName('VulnSubcategory')[0].childNodes[0].data
                    print(langUpperColumns, ruleID.childNodes[0].data, VulnCateForAll)
                    # writeIntoCSV(wirter_FilesPath, langUpperColumns, ruleID.childNodes[0].data, VulnCateForAll)
                else:
                    print("VulnCategory and VulnSubcategory is null!")
                    continue
                """
            except:
                print("unsuccess")
                # print(langUpperColumns, ruleID.childNodes[0].data, VulnCategory.childNodes[0].data)
                # writeIntoCSV(wirter_FilesPath, langUpperColumns, ruleID.childNodes[0].data, VulnCategory.childNodes[0].data)
        if len(Rules) > 0:
            print("length======", len(Rules))
        else:
            print("Sorry, rule file {} there is None for {}, Plz Check.".format(AbsolutelyFilePath, Rules))