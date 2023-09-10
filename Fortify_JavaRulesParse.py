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
    """
    TODONE
     1.1 xml文件存在多个标签包含<VulnCategory>，解析内容存在遗漏；
     ruleList = ['DataflowSinkRule', 'CharacterizationRule', 'SemanticRule']
    [x] 1.2 运行代码时，当下目录会写入相同文件。
    """
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
            rule = r'_(.*?)\.'
            langList = re.findall(rule, filename)
            langUpperColumns = [lang.upper() for lang in langList].pop()
            XmlFilesParseLogic_main(fileDir + filename, langUpperColumns)


def init_csv(csvName):
    with open(csvName, "w", encoding="utf-8", newline="") as file:
        head = ["Lang", "rule ID", "Vulnerable Category"]
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
    targetFile = os.path.split(AbsolutelyFilePath)[1]
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
        ruleList = ['ConfigurationRule']
    elif "extended_javascript.xml" in AbsolutelyFilePath \
            or "comm_php.xml" in AbsolutelyFilePath \
            or "comm_cloud.xml" in AbsolutelyFilePath \
            or "core_annotations.xml" in AbsolutelyFilePath:
        ruleList = ['StructuralRule']
    elif "extended_content.xml" in AbsolutelyFilePath:
        ruleList = ['ContentRule']
    elif "comm_universal.xml" in AbsolutelyFilePath \
            or "core_universal.xml" in AbsolutelyFilePath:
        ruleList = ['RegexRule']
    else:
        ruleList = ['DataflowSinkRule', 'CharacterizationRule', 'SemanticRule']
    for rule in ruleList:
        Rules = collection.getElementsByTagName(rule)
    # Here is a single label to parser. Could parser files like a para.
    # init_csv(wirter_FilesPath)
        if len(Rules) > 0:
            print("{} length ====== {}".format(rule, len(Rules)))
        else:
            print("Sorry, rule file {} there is None for {}, Plz Check.".format(AbsolutelyFilePath, Rules))
        for Rule in Rules:
            """
            @:param:
             - 漏洞名称 VulnCateForAll = VulnCategory.childNodes[0].data + /
                        Rule.getElementsByTagName('VulnSubcategory')[0].childNodes[0].data
                <VulnCategory 标签解析，位于DataflowSinkRule/RegexRule/etc..父标签下；>
             - 漏洞ID ruleID = Rule.getElementsByTagName('RuleID')[0]
             - 漏洞描述
            """
            ruleID = Rule.getElementsByTagName('RuleID')[0].childNodes[0].data

            VulnCategoryTag = Rule.getElementsByTagName('VulnCategory')
            VulnSubCategoryTag = Rule.getElementsByTagName('VulnSubcategory')
            try:
                if VulnCategoryTag is not None:
                    VulnCategory = Rule.getElementsByTagName('VulnCategory')[0].childNodes[0].data
                    try:
                        if VulnSubCategoryTag is not None:
                            VulnSubCategory = Rule.getElementsByTagName('VulnSubcategory')[0].childNodes[0].data
                            VulnCateForAll = VulnCategory + ": " + VulnSubCategory
                            writeIntoCSV(wirter_FilesPath, langUpperColumns, ruleID, VulnCateForAll)
                    except:
                        print("VulnSubcategory is null! Pass.")
                        pass
                    writeIntoCSV(wirter_FilesPath, langUpperColumns, ruleID, VulnCategory)
            except:
                print("VulnCategory is null! Pass.")
                pass
