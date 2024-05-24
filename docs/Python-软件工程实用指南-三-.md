# Python 软件工程实用指南（三）

> 原文：[`zh.annas-archive.org/md5/7ADF76B4555941A3D7672888F1713C3A`](https://zh.annas-archive.org/md5/7ADF76B4555941A3D7672888F1713C3A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：测试业务对象

一旦定义和测试了核心业务对象，它们可以作为其他包中的基础类使用，以提供具体的类功能。采用这种方法至少有两个优点：

+   核心类将处理数据类型、数据结构和数据验证的所有代码放在一个地方，这减少了依赖它们的其他代码库的复杂性

+   一旦为核心对象创建了通过的单元测试，它们提供的所有功能就不需要在其他地方进行测试

+   这些测试可以按需执行，并集成到最终构建过程中，提供一套完整的回归测试，以确保未来的更改不会在执行构建之前破坏现有功能

使用之前提到的测试扩展来构建这些单元测试的过程虽然不难，但一开始会很耗时。在本章中将审查整个过程，建立一些测试模式，我们将在后面的章节中重复使用这些模式，然后将它们整合到包构建过程中。

本章涵盖以下内容：

+   测试业务对象

+   分发和安装考虑

+   质量保证和验收

+   操作/使用、维护和停用考虑

# 开始单元测试过程

使用我们在上一章中定义的标准单元测试结构/框架，可以让我们快速、轻松地开始对任何代码库进行单元测试。它也非常适合迭代测试开发过程。一旦配置项在其中被一对搜索和替换操作设置好，起始点测试模块立即开始报告测试用例和方法的情况。我们的初始测试模块只是以下内容（为了保持列表的简洁，删除了一些注释）：

```py
#!/usr/bin/env python
"""
Defines unit-tests for the module at hms_core.
"""
#######################################
# Standard library imports needed     #
#######################################

import os
import sys
import unittest

#######################################
# Local imports needed                #
#######################################

from idic.unit_testing import *

#######################################
# Module-level Constants              #
#######################################

LocalSuite = unittest.TestSuite()

#######################################
# Import the module being tested      #
#######################################
```

```py
import hms_core as hms_core

#######################################
# Code-coverage test-case and         #
# decorator-methods                   #
#######################################

class testhms_coreCodeCoverage(ModuleCoverageTest):
    # - Class constants that point to the namespace and module 
    #   being tested
    _testNamespace = 'hms_core'
    _testModule = hms_core

LocalSuite.addTests(
    unittest.TestLoader().loadTestsFromTestCase(
        testhms_coreCodeCoverage
    )
)

#######################################
# Test-cases in the module            #
#######################################

#######################################
# Code to execute if file is called   #
# or run directly.                    #
#######################################

if __name__ == '__main__':
    import time
    results = unittest.TestResult()
    testStartTime = time.time()
    LocalSuite.run(results)
    results.runTime = time.time() - testStartTime
    PrintTestResults(results)
    if not results.errors and not results.failures:
        SaveTestReport(results, 'hms_core',
            'hms_core.test-results')
```

执行测试模块产生以下结果：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/fdda75b1-6beb-4c27-b077-a5e6635de534.png)

然后，测试运行输出告诉我们，我们需要为被测试模块中定义的六个类生成测试用例类；具体来说，我们需要创建`testAddress`、`testBaseArtisan`、`testBaseCustomer`、`testBaseOrder`、`testBaseProduct`和`testHasProducts`测试用例类。3

为了利用标准单元测试结构提供的属性和方法覆盖测试，每个测试方法都应该使用`testhms_coreCodeCoverage`提供的`AddMethodTesting`和`AddPropertyTesting`装饰器进行装饰：

```py
#######################################
# Test-cases in the module            #
#######################################

@testhms_coreCodeCoverage.AddMethodTesting
@testhms_coreCodeCoverage.AddPropertyTesting
class testAddress(unittest.TestCase):
    pass
LocalSuite.addTests(
    unittest.TestLoader().loadTestsFromTestCase(
        testAddress
    )
)

@testhms_coreCodeCoverage.AddMethodTesting
@testhms_coreCodeCoverage.AddPropertyTesting
class testBaseArtisan(unittest.TestCase):
    pass
LocalSuite.addTests(
    unittest.TestLoader().loadTestsFromTestCase(
        testBaseArtisan
    )
)

@testhms_coreCodeCoverage.AddMethodTesting
@testhms_coreCodeCoverage.AddPropertyTesting
class testBaseCustomer(unittest.TestCase):
    pass
LocalSuite.addTests(
    unittest.TestLoader().loadTestsFromTestCase(
        testBaseCustomer
    )
)
```

```py
@testhms_coreCodeCoverage.AddMethodTesting
@testhms_coreCodeCoverage.AddPropertyTesting
class testBaseOrder(unittest.TestCase):
    pass
LocalSuite.addTests(
    unittest.TestLoader().loadTestsFromTestCase(
        testBaseOrder
    )
)
@testhms_coreCodeCoverage.AddMethodTesting
@testhms_coreCodeCoverage.AddPropertyTesting
class testBaseProduct(unittest.TestCase):
    pass
LocalSuite.addTests(
    unittest.TestLoader().loadTestsFromTestCase(
        testBaseProduct
    )
)

@testhms_coreCodeCoverage.AddMethodTesting
@testhms_coreCodeCoverage.AddPropertyTesting
class testHasProducts(unittest.TestCase):
    pass
LocalSuite.addTests(
    unittest.TestLoader().loadTestsFromTestCase(
        testHasProducts
    )
)
```

一旦这些测试就位，重新运行测试模块将生成一个（很长的！）需要在测试策略测试通过之前解决的项目清单。需求的完整清单足够长，直接包含在书中只会导致 2-3 页的项目符号列表。然而，完整的结果包含在`hms_core`代码库的`miscellany/initial-test-run.txt`中。整个初始输出太长，无法在此处完整重现，但输出的开头和结尾如下，并指定了需要在六个测试用例类中实现的总共 105 个测试方法：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/0b23808a-ce7e-43e8-bae3-fb0017a96bf4.png)

从那时起，测试编写过程只是重复以下循环，直到所有测试通过为止：

+   选择需要编写的缺失测试方法或一组测试方法

+   将测试方法添加到适用的测试用例类中，并设置为失败，因为它们尚未实现

+   运行测试模块以验证测试是否按预期失败

+   对于每个测试方法：

+   在方法中编写真实的测试代码

+   执行测试模块，并确保该方法中唯一的失败是添加的显式失败，纠正任何出现的问题

+   删除显式失败

即使有标准单元测试过程提供的指导，也不可否认为编写模块的所有单元测试，即使是相对较短的`hms_core`模块，可能会非常乏味。然而，有一些方法可以使这个过程至少变得更快一些，因为我们知道有一些我们期望的常见值类型和格式。我们将首先为`Address`类编写测试，该类具有我们将要处理的最大属性集合之一。随着这些测试的建立，一些常见的（可重复使用的）测试值将开始出现。

这次单元测试过程还将产生一个测试用例类模板文件（`test-case-class.py`），该文件将包含在书籍的代码模板目录中。

# 对 Address 类进行单元测试

`Address`类的测试最初报告需要编写以下测试方法：

+   **方法：** `test__init__`，`test_del_building_address`，`test_del_city`，`test_del_country`，`test_del_postal_code`，`test_del_region`，`test_del_street_address`，`test_get_building_address`，`test_get_city`，`test_get_country`，`test_get_postal_code`，`test_get_region`，`test_get_street_address`，`test_set_building_address`，`test_set_city`，`test_set_country`，`test_set_postal_code`，`test_set_region`，`test_set_street_address`和`test_standard_address`

+   **属性：** `testbuilding_address`，`testcity`，`testcountry`，`testpostal_code`，`testregion`和`teststreet_address`

对被测试类的属性的测试方法的主要关注点可以说是确保属性使用适当的方法进行其 getter、setter 和 deleter 功能。如果这一点被确认为正确，那么处理属性及其值的实际过程可以仅在这些方法的测试方法中进行测试。考虑到这一点，`Address`的大部分属性测试将如下所示：

```py
def testproperty_name(self):
   # Tests the property_name property of the Address class
   # - Assert that the getter is correct:
     self.assertEqual(
         Address.property_name.fget, 
         Address._get_property_name, 
        'Address.property_name is expected to use the '
        '_get_property_name method as its getter-method'
     )
      # - If property_name is not expected to be publicly                       # settable,
      #   the second item here 
      #   (Address._set_property_name) should 
      #   be changed to None, and the failure message           #   adjusted 
      #   accordingly:
           self.assertEqual(
            Address.property_name.fset, 
            Address._set_property_name, 
           'Address.property_name is expected to use the '
           '_set_property_name method as its setter-method'
        )
    #   If property_name is not expected to be publicly     #   deletable,
    #   the second item here (Address._del_property_name)     #   should 
    #   be changed to None, and the failure message         #   adjusted 
     #   accordingly:
       self.assertEqual(
          Address.property_name.fdel, 
          Address._del_property_name, 
          'Address.property_name is expected to use the '
          '_del_property_name method as its deleter-method'
      )
```

通过在代码块中切换模板化的`property_name`为实际的属性名称，可以相当快速地创建单个属性测试，例如，实现`testbuilding_address`：

```py
def testbuilding_address(self):
# Tests the building_address property of the Address class
# - Assert that the getter is correct:
     self.assertEqual(
        Address.building_address.fget, 
        Address._get_building_address, 
       'Address.building_address is expected to use the '
       '_get_building_address method as its getter-method'
     )
# - Assert that the setter is correct:
     self.assertEqual(
        Address.building_address.fset, 
        Address._set_building_address, 
       'Address.building_address is expected to use the '
       '_set_building_address method as its setter-method'
     )
# - Assert that the deleter is correct:
       self.assertEqual(
       Address.building_address.fdel, 
       Address._del_building_address, 
      'Address.building_address is expected to use the '
      '_del_building_address method as its deleter-method'
     )
```

获取器和删除器方法的测试通常也会非常简单 - 它们最终只需要确保它们从正确的内部存储属性中检索数据，并将该属性的值设置为预期的默认值。`test_del_building_address`测试方法作为一个例子：

```py
def test_del_building_address(self):
# Tests the _del_building_address method of the Address 
# class
   test_object = Address('street address', 'city')
    self.assertEqual(
       test_object.building_address, None, 
       'An Address object is expected to have None as its default '
       'building_address value if no value was provided'
    )
# - Hard-set the storage-property's value, call the 
#   deleter-method, and assert that it's what's expected 
#   afterwards:
    test_object._building_address = 'a test value'
    test_object._del_building_address()
    self.assertEqual(
      test_object.building_address, None, 
      'An Address object is expected to have None as its '
      'building_address value after the deleter is called'
    )
```

值得注意的是，为了测试删除器方法（以及后来的获取器和设置器方法），我们实际上必须创建被测试对象的实例 - 这就是测试方法的第三行所做的事情（`test_object = Address…`）。一旦创建了该实例，如果正在测试的属性在测试对象的创建中不是必需的或作为其一部分提供，我们还可以（并且应该）测试实例的默认/删除值。即使为测试对象提供了一个值，通过设置底层存储属性中的值，调用删除器方法，并在之后验证结果，删除过程的测试在几乎所有情况下都将保持不变。

测试相应的 getter 方法将是类似的；它实际上只需要提供属性是否从正确的存储属性中检索数据：

```py
def test_get_building_address(self):
# Tests the _get_building_address method of the Address 
# class
  test_object = Address('street address', 'city')
  expected = 'a test-value'
  test_object._building_address = expected
  actual = test_object._get_building_address()
  self.assertEqual(
    actual, expected, 
   'Address._get_building_address was expected to return '
   '"%s" (%s), but returned "%s" (%s) instead' % 
   (
       expected, type(expected).__name__,
       actual, type(actual).__name__,
   )
)
```

通常有用的是设置可以传递给测试的核心断言的`expected`和`actual`值，特别是如果检索这些值涉及使用方法或函数。这不会产生功能上的差异，但以后阅读起来会更容易，保持易于理解和可读性是非常重要的，比保持被测试代码可读和可理解更重要——毕竟，测试代码是质量保证工作，不应该因为加密结构而出现错误。

值得注意的是，`city`和`street_address`属性的测试方法略有不同，因为它们都是在实例创建期间设置的属性。

```py
def test_del_city(self):
   # Tests the _del_city method of the Address class
   expected = 'city'
   test_object = Address('street address', expected)
   self.assertEqual(
     test_object.city, expected, 
    'An Address object is expected to have "%s" (%s) as its '
    'current city value, since that value was provided' % 
       (expected, type(expected).__name__)
     )
# - Since we have a value, just call the deleter-method, 
#   and 
#   assert that it's what's expected afterwards:
     test_object._del_city()
       self.assertEqual(
         test_object.city, None, 
         'An Address object is expected to have None as its '
         'city value after the deleter is called'
     )
```

不同之处在于，由于预期创建的测试对象将提供一个值，因此我们在创建测试对象之前设置了预期值进行测试，然后使用该预期值创建测试对象，然后测试以确保删除器在对象创建期间不会删除最初设置的值。尽管如此，明确告知时它被删除的测试本质上是相同的。

一旦使用这些模式建立了所有 getter 和 deleter 方法的测试，测试模块运行开始显示进展。正在运行的 29 个测试之一（也是失败的一个）是代码覆盖测试，它正在捕捉`BaseArtisan`和其他`hms_core`类的缺失测试用例类，这些类已经被注释掉，以便更轻松地处理`testAddress`测试方法的结果输出。剩下的八个失败中，有六个是`testAddress`的设置方法测试，我们将在下一步实现，另外两个是`test__init__`和`teststandard_address`，我们将最后看一下：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/d7ceabc3-6f66-44b3-a371-19e7187bb245.png)

与 getter 和 deleter 方法对应的测试方法很简单，因为被测试的方法本身相当简单。它们（到目前为止）不做任何决定，也不对值进行任何操作；它们只是返回当前值，或者在不需要对替换值做任何决定的情况下进行替换。此外，它们也没有参数需要处理。

设置方法更复杂；它们会做出决策，会有参数（即使只有一个），并且可能预期根据这些参数的类型和值而表现出不同的行为。因此，相应的测试方法可能也会因此而变得更复杂，这种期望是有根据的。对于良好设计的测试来说，测试复杂性将随着输入复杂性的增加而增长，因为这些测试必须检查输入的所有逻辑变体。当我们测试属性的设置方法时，这将开始变得明显，首先从`Address.building_address`开始。

良好设计的单元测试需要做几件事情，其中并非所有事情一开始就显而易见。最明显的事项可能是测试所有快乐路径输入可能性：预期类型和预期有效值的输入，应该在没有错误的情况下执行并产生预期的结果，无论这些结果是什么。也许不那么明显的是，单元测试还应该使用一组已知的坏值进行代表性样本集的测试，这些值预计会引发错误并阻止被测试的过程完成错误数据。让我们再次以此为基础来看一下`Address`的`_set_building_address`方法：

```py
def _set_building_address(self, value:(str,None)) -> None:
    if value != None:
 # - Type-check: If the value isn't None, then it has to 
 #   be a non-empty, single-line string without tabs
    if type(value) != str:
       raise TypeError(
       '%s.building_address expects a single-line, '
       'non-empty str value, with no whitespace '
       'other than spaces or None, but was passed '
       '"%s" (%s)' % 
          (
             self.__class__.__name__, value, 
             type(value).__name__
          )
                )
  # - Value-check: no whitespace other than " "
         bad_chars = ('\n', '\r', '\t')
         is_valid = True
         for bad_char in bad_chars:
            if bad_char in value:
               is_valid = False
               break
 # - If it's empty or otherwise not valid, raise error
     if not value.strip() or not is_valid:
         raise ValueError(
         '%s.building_address expects a single-line, '
         'non-empty str value, with no whitespace '
         'other than spaces or None, but was passed '
         '"%s" (%s)' % 
           (
              self.__class__.__name__, value, 
              type(value).__name__
           )
        )
 # - If this point is reached without error, then the 
 #   string-value is valid, so we can just exit the if
      self._building_address = value
```

可以合理测试的良好值包括以下内容：

+   `None`——如果将`None`作为值传递，则它将简单地通过并设置在内部存储属性中。

+   任何单行非空字符串，不包含制表符或空格字符以外的其他空白字符。

可行的坏值包括以下内容：

+   任何不是字符串的值。

+   空字符串。

+   包含任何换行字符或任何不是空格的空白的字符串。

+   一个什么都不是的空格字符的字符串；这个项目不太明显，但是代码会引发`ValueError`，因为这样的输入会被值检查代码中的`if not value.strip()`捕获。对仅包含空格的字符串调用`.strip()`的结果是一个空字符串，这将被评估为`False`（-ish），从而引发错误。

`_set_building_address`方法不会尝试进行任何内容验证，因此我们目前不必担心；我们默认假设，如果有人费心输入一个格式良好的`building_address`值，那么输入的值将是准确的。

早些时候，`business_address`属性被归类为标准可选文本行属性。如果这个分类是正确的，那么生成一个好的标准可选文本行属性值的单一列表将是可能的，也是有利的，这样这些值就可以被用于逻辑上适用于所有属性测试的所有属性。这个列表，作为测试模块中的一个常量，可能会像这样：

```py
GoodStandardOptionalTextLines = [
    'word', 'hyphenated-word', 'short phrase', 
    'A complete sentence.', 
    'A short paragraph. This\'s got some punctuation, '
    'including "quoted text."',
    None # Because optional items are allowed to be None
]
```

然后，测试`test_set_business_address`中的好值就变得很简单，只需要遍历该值列表，调用 setter 方法，并断言在设置值后 getter 方法的结果与预期值匹配：

```py
# - Create an object to test with:
test_object = Address('street address', 'street_address')
# - Test all permutations of "good" argument-values:
  for expected in GoodStandardOptionalTextLines:
     test_object._set_building_address(expected)
     actual = test_object._get_building_address()
     self.assertEqual(
        expected, actual, 
        'Address expects a building_address value set to '
        '"%s" (%s) to be retrieved with a corresponding '
        'getter-method call, but "%s" (%s) was returned '
        'instead' % 
     (
```

```py
expected, type(expected).__name__, 
         actual, type(actual).__name__, 
     )
  )
```

如果我们已经在其他地方测试了属性与 getter 方法相关联，那么也可以对属性进行断言，而不是对 getter 方法进行断言。

对应的坏值列表将包括之前列出的所有坏项，并且看起来会像这样：

```py
BadStandardOptionalTextLines = [
    # Bad string values
    'multiple\nlines', 'also multiple\rlines', 
    'text\twith\tabs',
    # Values that aren't strings at all
    1, True, 0, False, object(), 
    # empty and whitespace-only strings
    '', '  ',
]
```

相应的坏值测试与之前显示的好值迭代类似，只是它们将专门寻找执行预期失败的情况，并且如果这些情况没有发生或以意外的方式发生，则会失败：

```py
# - Test all permutations of "bad" argument-values:
for value in BadStandardOptionalTextLines:
   try:
      test_object._set_building_address(value)
     # - If this setter-call succeeds, that's a 
     #   test-failure!
      self.fail(
         'Address._set_business_address should raise '
         'TypeError or ValueError if passed "%s" (%s), '
         'but it was allowed to be set instead.' % 
                (value, type(value).__name__)
        )
    except (TypeError, ValueError):
    # - This is expected, so it passes
         pass
    except Exception as error:
        self.fail(
          'Address._set_business_address should raise '
          'TypeError or ValueError if passed an invalid '
          'value, but %s was raised instead: %s.' % 
                (error.__class__.__name__, error)
        )
```

通过使用`try`...`except`块，这个测试过程将执行以下操作：

+   如果 setter 方法允许设置坏值而不引发错误，则明确失败

+   如果坏值在测试对象中设置时引发预期的错误（在大多数情况下是`TypeError`或`ValueError`），则通过

+   如果在执行期间 setter 方法引发了除了预期的两种类型之外的任何错误，则失败

相同的测试方法结构可以用于`Address`的所有标准可选文本行值/类型的属性，而不需要更改 setter 方法名称。基本上，`Address`的所有属性 setter，除了标准必需文本行项目`city`和`street_address`之外，都是相同的，只是名称不同。

然而，可选文本行属性和必需文本行属性之间唯一的区别是，可选项可以允许`None`作为有效参数，而必需项则不行。如果我们为这些差异创建单独的测试值列表，并更改测试方法使用的列表，那么相同的结构，只是具有不同的好和坏值，仍然可以工作：

```py
GoodStandardRequiredTextLines = [
    'word', 'hyphenated-word', 'short phrase', 
    'A complete sentence.', 
    'A short paragraph. This\'s got some punctuation, '
    'including "quoted text."',
]
BadStandardRequiredTextLines = [
    # Bad string values
    'multiple\nlines', 'also multiple\rlines', 
    'text\twith\tabs',
    # Values that aren't strings at all
    1, True, 0, False, object(), 
    # empty and whitespace-only strings
    '', '  ',
    None # Because optional items are NOT allowed to be None
]

# ... 

def test_set_city(self):
    # Tests the _set_city method of the Address class
    # - Create an object to test with:
    test_object = Address('street address', 'street_address')
    # - Test all permutations of "good" argument-values:
    for expected in GoodStandardRequiredTextLines:
        test_object._set_city(expected)
        actual = test_object._get_city()
        self.assertEqual(
            expected, actual, 
            'Address expects a city value set to '
            '"%s" (%s) to be retrieved with a corresponding '
            'getter-method call, but "%s" (%s) was returned '
            'instead' % 
            (
                expected, type(expected).__name__, 
                actual, type(actual).__name__, 
            )
        )
    # - Test all permutations of "bad" argument-values:
    for value in BadStandardRequiredTextLines:
        try:
            test_object._set_city(value)
            # - If this setter-call succeeds, that's a 
            #   test-failure!
            self.fail(
                'Address._set_business_address should raise '
                'TypeError or ValueError if passed "%s" (%s), '
                'but it was allowed to be set instead.' % 
                (value, type(value).__name__)
            )
        except (TypeError, ValueError):
            # - This is expected, so it passes
            pass
        except Exception as error:
            self.fail(
                'Address._set_business_address should raise '
                'TypeError or ValueError if passed an invalid '
                'value, but %s was raised instead: %s.' % 
                (error.__class__.__name__, error)
            )
```

在所有 setter 方法测试就位后，重新运行测试模块显示只有三个测试失败：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/edd082df-d88b-4ac3-bd39-5d47d0818650.png)

除了其他测试用例类的覆盖测试之外，只剩下`__init__`和`standard_address`方法需要测试。

测试`__init__`方法并不困难。它真正需要建立的是在创建新对象实例的初始化过程中，适当调用各种属性设置器。其他测试已经证实了属性连接到它们预期的 getter/setter/deleter 方法，并且这些方法正在按照预期进行。由于我们有预定义的良好值列表，可以迭代这些值，所以可以简单地设置一个（大）嵌套循环集来检查这些值的所有可能组合，因为它们适用于每个属性。循环的嵌套级别非常深（足够深，以至于以下代码每行只缩进两个空格以适应页面），但它有效：

```py
def test__init__(self):
  # Tests the __init__ method of the Address class
  # - Test all permutations of "good" argument-values:
  for building_address in GoodStandardOptionalTextLines:
    for city in GoodStandardRequiredTextLines:
      for country in GoodStandardOptionalTextLines:
        for postal_code in GoodStandardOptionalTextLines:
          for region in GoodStandardOptionalTextLines:
            for street_address in GoodStandardRequiredTextLines:
              test_object = Address(
                street_address, city, building_address,
                region, postal_code, country
              )
              self.assertEqual(test_object.street_address, street_address)
              self.assertEqual(test_object.city, city)
              self.assertEqual(test_object.building_address, building_address)
              self.assertEqual(test_object.region, region)
              self.assertEqual(test_object.postal_code, postal_code)
              self.assertEqual(test_object.country, country)
```

同样的方法在实现`teststandard_address`时同样有效：

```py
def teststandard_address(self):
  # Tests the standard_address method of the Address class
  # - Test all permutations of "good" argument-values:
  for street_address in GoodStandardRequiredTextLines:
    for building_address in GoodStandardOptionalTextLines:
      for city in GoodStandardRequiredTextLines:
        for region in GoodStandardOptionalTextLines:
          for postal_code in GoodStandardOptionalTextLines:
            for country in GoodStandardOptionalTextLines:
              test_object = Address.standard_address(
                street_address, building_address, 
                city, region, postal_code, 
                country
              )
              self.assertEqual(test_object.street_address, street_address)
              self.assertEqual(test_object.building_address, building_address)
              self.assertEqual(test_object.city, city)
              self.assertEqual(test_object.region, region)
              self.assertEqual(test_object.postal_code, postal_code)
              self.assertEqual(test_object.country, country)
```

这样，`Address`类的测试就完成了：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/c8386b3e-09ed-4860-a4fd-a8cfb1a261fe.png)

模块的单元测试过程的平衡实际上包括重新激活其他测试用例类，为它们创建基线失败的测试方法，然后运行测试模块并编写和纠正测试，正如前面所述。由于测试过程的执行方式，生成的输出将按照每个测试用例类的每个测试方法按字母顺序排列。因此，`HasProducts`的测试用例类将最后执行，在其中，`testproducts`方法之后是`test_del_products`，`test_get_products`和`test_set_products`。在输出中，处理最后失败的测试用例所需的时间比滚动整个输出查找正在处理的单个特定测试方法要少，因此剩下的测试将按照这个顺序进行处理和讨论。

# 单元测试 HasProducts

`products`属性的测试方法`testproducts`必须考虑属性的只读性质——记住`products`属性设置为防止或至少最小化对底层`list`值的随意操作的可能性。除了对 setter 和 deleter 方法分配的测试的更改之外，它基本上与以前的属性测试方法相同：

```py
def testproducts(self):
    # Tests the products property of the HasProducts class
    # - Assert that the getter is correct:
    self.assertEqual(
        HasProducts.products.fget, 
        HasProducts._get_products, 
        'HasProducts.products is expected to use the '
        '_get_products method as its getter-method'
    )
    # - Assert that the setter is correct:
    self.assertEqual(
        HasProducts.products.fset, None, 
        'HasProducts.products is expected to be read-only, with '
        'no associated setter-method'
    )
    # - Assert that the deleter is correct:
    self.assertEqual(
        HasProducts.products.fdel, None, 
        'HasProducts.products is expected to be read-only, with '
        'no associated deleter-method'
    )
```

对于像`HasProducts`这样的 ABC 的方法进行测试，在某种程度上，与像`Address`这样的具体类的过程相同：必须创建一个作为 ABC 实例的测试对象，然后将相关的测试值传递给方法并断言它们的结果。但是，如果 ABC 具有抽象成员，则无法实例化，因此必须定义并使用一个具有抽象成员最小实现的一次性派生类来代替具体类来创建测试对象。为了测试`HasProducts`的成员方法，该类是`HasProductsDerived`，它看起来像这样：

```py
class HasProductsDerived(HasProducts):
    def __init__(self, *products):
        HasProducts.__init__(self, *products)
# NOTE: These do NOT have to actually *do* anything, they
# merely have to *exist* in order to allow an instance 
    #       to be created:
    def add_product(self, product):
        pass
    def remove_product(self, product):
        pass
```

定义了该类后，可以创建`_get_products`，`_set_products`和`_del_products`的测试，这些测试是迄今为止使用的测试策略的直接变体，尽管它们首先需要使用`throwaway`类定义`GoodProducts`和`BadProducts`。

```py
#  Since we needed this class in order to generate good #  product-
#   setter test-values, but it wasn't defined until now, #   we'll 
#   create the GoodProducts test-values here...
GoodProducts = [
    [
        BaseProductDerived('test1', 'summary1', True, True),
        BaseProductDerived('test2', 'summary2', True, True),
    ],
    (
        BaseProductDerived('test3', 'summary3', True, True),
        BaseProductDerived('test4', 'summary4', True, True),
    ),
]
BadProducts = [
    object(), 'string', 1, 1.0, True, None,
    ['list','with','invalid','values'],
    [
        BaseProductDerived('test4', 'summary4', True, True), 
        'list','with','invalid','values'
    ],
    ('tuple','with','invalid','values'),
    (
        BaseProductDerived('test4', 'summary4', True, True), 
        'tuple','with','invalid','values'
    ),
]
```

一旦这些也就位了，测试方法如下：

```py
def test_del_products(self):
# Tests the _del_products method of the HasProducts class
   test_object = HasProductsDerived()
   self.assertEqual(test_object.products, (),
   'HasProducts-derived instances are expected to return '
   'an empty tuple as a default/deleted value'
   )
# - Test all permutations of "good" argument-values:
        test_object._set_products(GoodProducts[0])
        self.assertNotEqual(test_object.products, ())
        test_object._del_products()
        self.assertEqual(test_object.products, ())

def test_get_products(self):
 # Tests the _get_products method of the HasProducts class
        test_object = HasProductsDerived()
 # - Test all permutations of "good" argument-values:
        expected = GoodProducts[1]
        test_object._products = expected
        self.assertEqual(test_object._get_products(), expected)

    def test_set_products(self):
# Tests the _set_products method of the HasProducts class
        test_object = HasProductsDerived()
# - Test all permutations of "good" argument-values:
        for expected in GoodProducts:
            test_object._set_products(expected)
            if type(expected) != tuple:
                expected = tuple(expected)
            self.assertEqual(expected, test_object._get_products())
# - Test all permutations of each "bad" argument-value 
#   set against "good" values for the other arguments:
        for value in BadProducts:
            try:
                test_object._set_products(value)
                self.fail(
                    'HasProducts-derived classes should not allow '
                    '"%s" (%s) as a valid products value, but it '
                    'was allowed to be set.' % 
                    (str(value), type(value).__name__)
                )
            except (TypeError, ValueError):
                pass
```

`HasProducts.__init__`的测试方法使用了与`test_set_products`相同类型的方法：

```py
def test__init__(self):
  # Tests the __init__ method of the HasProducts class
  # - Test all permutations of "good" argument-values:
        for expected in GoodProducts:
            test_object = HasProductsDerived(*expected)
            if type(expected) != tuple:
                expected = tuple(expected)
            self.assertEqual(test_object.products, expected)
```

由于`HasProducts`在其`add_product`和`remove_product`方法背后隐藏了具体功能，因此也可以以同样的方式测试该功能，但是根据我们的测试策略，任何调用这些方法的派生类方法仍然必须单独进行测试，因此在这个时候额外的努力并没有太大意义。

# 单元测试 BaseProduct

`BaseProduct`的属性测试方法不需要任何新的东西；它们遵循与具有完整 get/set/delete 功能的属性相同的方法，除了对`metadata`属性的测试，它测试为只读属性，就像我们刚刚展示的对`HasProducts.products`的测试一样。

`BaseProduct`的许多测试方法也将遵循先前建立的模式——测试标准必需和可选文本行的好值和坏值变体，但也有一些需要新的或至少是变体的方法。

`set_metadata`和`remove_metadata`方法的测试与以前的测试有足够的不同，值得更仔细地检查。为了测试新的元数据键/值项的添加，有必要跟踪一个预期值，以便可以执行相同的键和值的添加。测试方法中通过创建一个空字典(`expected = {}`)来实现这一点，在调用测试对象的`set_metadata`方法的迭代中对其进行修改。随着每次迭代的进行，预期值相应地被改变，并与实际值进行比较：

```py
def testset_metadata(self):
 # Tests the set_metadata method of the BaseProduct class
  test_object = BaseProductDerived('name', 'summary', True, True)
  expected = {}
 # - Test all permutations of "good" argument-values:
  for key in GoodStandardRequiredTextLines:
      value = '%s value'
      expected[key] = value
      test_object.set_metadata(key, value)
      self.assertEqual(test_object.metadata, expected)
```

对坏键和值集的测试使用一个好值，用于未被测试的任何项，并迭代坏值，确保适当的错误被引发：

```py
    # - Test all permutations of each "bad" argument-value 
    #   set against "good" values for the other arguments:
    value = GoodStandardRequiredTextLines[0]
    for key in BadStandardRequiredTextLines:
        try:
            test_object.set_metadata(key, value)
            self.fail(
              'BaseProduct.set_metadata should not allow '
              '"%s" (%s) as a key, but it raised no error' 
                % (key, type(key).__name__)
            )
        except (TypeError,ValueError):
            pass
        except Exception as error:
           self.fail(
              'BaseProduct.set_metadata should raise TypeError '
              'or ValueError if passed  "%s" (%s) as a key, '
              'but %s was raised instead:\n    %s' % 
                (
                    key, type(key).__name__,
                    error.__class__.__name__, error
                )
            )
    key = GoodStandardRequiredTextLines[0]
    for value in BadStandardRequiredTextLines:
        try:
            test_object.set_metadata(key, value)
            self.fail(
              'BaseProduct.set_metadata should not allow '
              '"%s" (%s) as a value, but it raised no error' 
                % (value, type(value).__name__)
            )
        except (TypeError,ValueError):
            pass
        except Exception as error:
            self.fail(
                'BaseProduct.set_metadata should raise TypeError '
                'or ValueError if passed  "%s" (%s) as a value, '
                'but %s was raised instead:\n    %s' % 
                (
                    value, type(value).__name__,
                    error.__class__.__name__, error
                )
            )
```

`BaseProduct`的`remove_metadata`方法的测试方法使用了类似的策略来跟踪预期值，以便将测试结果与之进行比较。唯一的显著区别是，预期值（以及测试对象的`metadata`）需要在尝试删除任何`metadata`值之前进行填充：

```py
def testremove_metadata(self):
    # Tests the remove_metadata method of the BaseProduct class
    # - First we need sopme meadata to remove
    test_object = BaseProductDerived('name', 'summary', True, True)
    expected = {
        'materials':'wood',
        'material-names':'cherry,oak',
        'finish':'gloss'
    }
    for key in expected:
        test_object.set_metadata(key, expected[key])
    self.assertEqual(test_object.metadata, expected)
    # - Test all permutations of "good" argument-values:
    keys = list(expected.keys())
    for key in keys:
        del expected[key]
        test_object.remove_metadata(key)
        self.assertEqual(test_object.metadata, expected)
```

`BaseProduct`的布尔值属性`available`和`store_available`的 setter 方法的测试仍然使用了在其他地方使用的相同的好值和坏值迭代方法，只是它们需要一个不同的好值和坏值列表来进行测试：

```py
GoodBooleanOrIntEquivalents = [
    True, False, 1, 0
]
```

```py
BadBooleanOrIntEquivalents = [
    'true', '', (1,2), tuple()
]
```

同样，对`_set_shipping_weight`的测试方法需要另一组值列表，对`_set_metadata`的测试方法也是如此：

```py
GoodWeights = [
    0, 1, 2, 0.0, 1.0, 2.0, 1.5
]
BadWeights = [
    -1, -1.0, object(), 'true', '', (1,2), tuple()
]
GoodMetadataDicts = [
    {},
    {'spam':'eggs'}
]
BadMetadataDicts = [
    -1, -1.0, object(), 'true', '', (1,2), tuple()
]
```

对`_set_shipping_weight`的初始测试运行也促使对构成有效运输重量的假设进行审查。经过反思，而且在这一点上并不知道测量单位是什么，这些值很可能需要允许浮点值，特别是如果最终需要允许磅、千克甚至吨的运输，尽管这可能是不太可能的。

系统不应该对有效的运输重量设置任何限制，除了确保它是一个数字（因为它总是会是）并且不是负数。毕竟，产品可能包括像一张书法作品或一张纸上的插图这样的东西，这些东西重量都不会很重。另一方面，几十磅到一吨或更多的重量范围内的大理石半身像甚至大型金属雕塑也同样可能。

考虑到所有这些因素，`_set_shipping_weight`被修改为允许更广泛的值类型，并且还允许零值：

```py
def _set_shipping_weight(self, value:(int,float)):
    if type(value) not in (int, float):
        raise TypeError(
            '%s.shipping_weight expects a non-negative numeric '
            'value, but was passed "%s" (%s)' % 
            (
                self.__class__.__name__, 
                value, type(value).__name__
            )
        )
    if value < 0:
        raise ValueError(
            '%s.shipping_weight expects a non-negative numeric '
            'value, but was passed "%s" (%s)' % 
            (
                self.__class__.__name__, 
                value, type(value).__name__
            )
        )
    self._shipping_weight = value
```

对`_set_description`的测试还需要一个额外的新值列表来测试坏值；描述可以是任何字符串值，因为它目前是这样实现的，目前还没有适当捕捉坏值的坏值列表：

```py
BadDescriptions = [
    # Values that aren't strings at all
    1, True, 0, False, object(), 
    # empty and whitespace-only strings
    '', '  ',
]
```

# 对 BaseOrder 进行单元测试

根据覆盖测试，对`BaseOrder`进行单元测试只关注测试`customer`属性以及与该属性交互的任何方法。这是因为`BaseOrder`继承自`HasProducts`。由于`HasProducts`的成员没有在`BaseOrder`中被覆盖，它们仍然属于`HasProducts`，并且已经进行了相应的测试：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/7178970e-6fc8-45a0-8238-871b45c6975d.png)

像`BaseProduct`和`HasProducts`的测试过程一样，测试`BaseOrder`需要创建一个一次性的派生类，用于测试方法成员。由于`BaseOrder`还期望在对象构造期间提供客户实例，因此我们还需要创建一个`BaseCustomer`派生类来提供这样的对象，并且需要良好和不良的客户值进行测试：

```py
class BaseCustomerDerived(BaseCustomer):
    pass

GoodCustomers = [
    BaseCustomerDerived('customer name', Address('street-address', 'city'))
]
BadCustomers = [
    '', 'string', 1, 0, True, False, 1.0, 0.0, object(), [],
]
```

`BaseCustomerDerived`类不需要实现任何内容，因为`BaseCustomer`本身没有抽象成员，这引发了一个有趣的想法：如果它没有任何抽象成员，为什么我们一开始就将其定义为抽象类呢？这一决定背后的最初想法是，预计客户对象在系统的不同组件之间可以做的事情以及允许的数据访问可能会有很大的变化。

自我们最初的实现以来，这种期望没有改变，因此仍然有效。与此同时，可以创建一个`BaseCustomer`的实际实例，因为它没有定义抽象成员，这至少有可能在某个地方引入错误；如果我们相信`BaseCustomer`确实是抽象的，即使它没有提供抽象成员，创建它的具体实例也不应该被允许。至少可以通过在`BaseCustomer`的`__init__`方法中添加几行代码来管理，尽管这样做可能会感觉有些尴尬：

```py
def __init__(self, 
  name:(str,), billing_address:(Address,), 
  shipping_address:(Address,None)=None
):

   # ...

   # - Prevent a direct instantiation of this class - it's 
        #   intended to be abstract, even though it has no 
        #   explicitly-abstract members:
        if self.__class__ == BaseCustomer:
            raise NotImplementedError(
                'BaseCustomer is intended to be an abstract class, '
                'even though it does not have any explicitly '
                'abstract members, and should not be instantiated.'
            )
```

这本质上检查了正在创建的对象的类类型，并且如果正在创建的对象是抽象类本身的实例，则引发`NotImplementedError`。当我们为该类编写`test__init__`方法时，我们将不得不记住测试这一点，因此现在在测试方法中值得注意一下，以免以后遗失：

```py
def test__init__(self):
    # Tests the __init__ method of the BaseCustomer class
    # - Test to make sure that BaseCustomer can't be 
    #   instantiated on its own!
    # - Test all permutations of "good" argument-values:
    # - Test all permutations of each "bad" argument-value 
    #   set against "good" values for the other arguments:
    self.fail('test__init__ is not yet implemented')
```

除此之外，创建`BaseCustomerDerived`类和`GoodCustomers`和`BadCustomers`值列表以进行测试，允许所有`testBaseOrder`测试用例类的测试结构遵循到目前为止一直在使用的通常模式。

# 对 BaseCustomer 进行单元测试

`BaseCustomer`的所有属性 getter、setter 和 deleter 方法测试都遵循典型的模式，尽管通常最好在每个测试中创建单独的实例来处理`test_object`。否则，很快就会导致一个测试对共同对象进行更改，从而使其他测试失败，并且为每个测试创建单独的测试对象可以很好地解决这个问题：

```py
test_object = BaseCustomer(
    'customer name', Address('street-address', 'city')
)
```

`__init__`的测试需要明确测试是否可以创建`BaseCustomer`对象，正如前面所述，这仍然是以前测试用例类中建立的测试结构的典型代表：

```py
def test__init__(self):
# Tests the __init__ method of the BaseCustomer class
# - BaseCustomer is an abstract class, but has no abstract 
#   members, so this was set up to keep it from being 
#   accidentally used in an inappropriate fashion
    try:
       test_object = BaseCustomer(
       'customer name', Address('street-address', 'city')
       )
       self.fail(
          'BaseCustomer is expected to raise '
          'NotImplementedError if instantiated directly, '
                'but did not do so'
       )
     except NotImplementedError:
            pass
```

测试方法的其余部分符合以前测试的预期，对一组相关的良好值进行迭代，并断言它们在实例化时按预期传递到属性中：

```py
# - Test all permutations of "good" argument-values:
    for name in GoodStandardRequiredTextLines:
       for billing_address in GoodAddresses:
          # - Testing without a shipping-address first
            test_object = BaseCustomerDerived(
                name, billing_address
            )
            self.assertEqual(test_object.name, name)
            self.assertEqual(
                test_object.billing_address, 
                billing_address
             )
            for shipping_address in GoodAddresses:
               test_object = BaseCustomerDerived(
                  name, billing_address, 
                   shipping_address
             )
             self.assertEqual(
                test_object.shipping_address, 
                shipping_address
             )
```

# 对 BaseArtisan 进行单元测试

到目前为止，我们已经建立了应该用于所有针对`BaseArtisan`的测试的模式：

+   它是一个抽象类，因此我们需要为测试目的创建一个派生类（`BaseArtisanDerived`）

+   所有的属性 getter、setter 和 deleter 方法都遵循已经建立的模式之一：

+   所有的 getter 和 deleter 方法测试都是标准的

+   `address`几乎是对`BaseCustomer`中的账单和送货地址属性的测试的直接复制，并且使用相同的`GoodAddresses`/`BadAddresses`值列表

+   `company_name`是一个标准的可选文本行测试，就像我们已经测试过的许多其他属性一样

+   `contact_email`和`website`的 setter 方法也遵循标准模式，尽管它们需要新的良好和不良值列表进行测试

+   `contact_name`是一个标准的必需文本行属性，并且像所有其他这样的属性一样进行测试

以下演示了良好和不良值列表的示例：

```py
GoodEmails = [
    'someone@somewhere.com',
    'brian.allbee+hosewp@gmail.com',
]
BadEmails = [
    '', 'string', -1, -1.0, object(), 'true', '', (1,2), tuple()
]
GoodURLs = [
    'http://www.google.com',
    'https://www.google.com',
]
BadURLs = [
    '', 'string', -1, -1.0, object(), 'true', '', (1,2), tuple()
]
```

然而，对`BaseArtisan`的测试揭示了在`__init__`方法中没有提供`website`参数，也没有在构造对象期间支持传递`website`，因此相应地进行了修改：

```py
def __init__(self, 
    contact_name:str, contact_email:str, 
    address:Address, company_name:str=None, 
    website:(str,)=None, 
    **products
    ):

    # ...

    # - Call parent initializers if needed
    HasProducts.__init__(self, *products)
    # - Set default instance property-values using _del_... methods
    self._del_address()
    self._del_company_name()
    self._del_contact_email()
    self._del_contact_name()
    self._del_website()
    # - Set instance property-values from arguments using 
    #   _set_... methods
    self._set_contact_name(contact_name)
    self._set_contact_email(contact_email)
    self._set_address(address)
    if company_name:
        self._set_company_name(company_name)
    if website:
        self._set_website(website)
```

最后，这样就完成了系统的第一个模块的 118 个测试：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/a273aadd-b13d-40ea-ba1b-3dbfd0afa0ca.png)

# 到目前为止已经建立的单元测试模式

对系统中第一个模块的单元测试进行了大量探索，这种探索已经建立了一些模式，这些模式将经常出现在编写的其他系统代码的单元测试中，因此除非它们有重大的新方面，否则从这一点开始它们将不会被重新审查。

这些模式如下：

+   迭代好和坏的值列表，这些值对于正在测试的成员是有意义的：

+   标准可选文本行值

+   标准必需的文本行值

+   布尔值（及其数值等价物）

+   元数据值

+   非负数值（例如重量值）

+   验证属性方法关联——到目前为止，在每种情况下都是 getter 方法，以及在预期的地方是 setter 和 deleter 方法

+   验证 getter 方法是否检索其底层存储属性值

+   验证 deleter 方法是否按预期重置其底层存储属性值

+   验证 setter 方法是否按预期强制执行类型和值检查

+   验证初始化方法（`__init__`）是否按预期调用所有的 deleter 和 setter 方法

# 分发和安装考虑因素

默认的`setup.py`，添加了`hms_core`的包名称并删除了注释，非常基本，但仍然提供了构建可部署的 Python 包所需的一切`hms_core`代码库。它还提供了执行为包创建的所有单元测试的能力，给定它们所在的路径，并且能够找到已经使用的单元测试扩展：

```py
#!/usr/bin/env python

# - Provide an import-path for the unit-testing standards we're using:
import sys
sys.path.append('../standards')

# - Standard setup.py import and structure
from setuptools import setup

# The actual setup function call:
setup(
    name='HMS-Core',
    version='0.1.dev0',
    author='Brian D. Allbee',
    description='',
    package_dir={
        '':'src',
    },
    packages=[
        'hms_core',
    ],
    test_suite='tests.test_hms_core',
)
```

执行以下操作：

```py
python setup.py test
```

这将执行项目的`tests/test_hms_core`目录中的整个测试套件：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/59708536-a496-4faa-a9b3-f0e4d73c5b74.png)

执行以下操作：

```py
python setup.py sdist
```

这将创建包的源分发，然后可以使用以下命令安装：

```py
pip install HMS-Core-0.1.dev0.tar.gz
```

这可以在包文件所在的目录的终端会话中完成。

此时，`setup.py`构建过程将引发一些错误，但这些错误都不会阻止包的构建或安装：

+   `警告：sdist：未找到标准文件：应该有 README、README.rst、README.txt 之一`

+   `警告：检查：缺少必需的元数据：url`

+   `警告：检查：缺少元数据：如果提供了'author'，则必须同时提供'author_email'`

安装后，`hms_core`包可以像任何其他 Python 包一样使用：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/64790796-2e0b-4549-afa9-b5147ba1816d.png)

在这个迭代中，最初的三个故事集中在`hms_core`和其他组件项目库之间的构建和部署过程如何交互，目前尚未解决：

+   作为一名工匠，我需要业务对象库与我的应用程序一起安装，以便应用程序能够按需工作，而无需我安装其依赖组件

+   作为中央办公室用户，我需要业务对象库与我的应用程序一起安装，以便应用程序能够按需工作，而无需我安装其依赖组件

+   作为系统管理员，我需要业务对象库与工匠网关服务一起安装，以便它能够按需工作，而无需我安装其依赖组件

在这一点上，因为我们没有其他库可以进行测试，实际上不能对其进行执行——我们将不得不等待至少一个可安装软件包的实际实现，然后才能处理这些问题，因此它们将被放回待办事项，并在实际可以处理时再次处理。

# 质量保证和验收

由于该库提供的功能是基础性的，旨在被其他库使用，因此在正式的质量保证（QA）过程中，实际上没有太多公共功能可以进行有意义的测试。如果这个迭代中涉及到正式的 QA 过程，最多只能执行单元测试套件，并验证这些测试是否能够正常执行而没有失败或错误。

同样，由于迭代中涉及的大部分故事都是为了开发人员的利益，因此几乎不需要外部验收；库中各种类存在并按预期运行应该足以接受这些故事。

+   作为开发人员，我需要系统中表示地址的通用定义和功能结构，以便我可以将它们纳入需要它们的系统部分。

+   作为开发人员，我需要系统中表示工匠的通用定义和功能结构，以便我可以将它们纳入需要它们的系统部分。

+   作为开发人员，我需要系统中表示客户的通用定义和功能结构，以便我可以将它们纳入需要它们的系统部分。

+   作为开发人员，我需要系统中表示订单的通用定义和功能结构，以便我可以将它们纳入需要它们的系统部分。

+   作为开发人员，我需要系统中表示产品的通用定义和功能结构，以便我可以将它们纳入需要它们的系统部分。

目前，安装方面的故事有点奇怪——它们特别关注各种最终用户的单个可安装软件包，这目前是这样，但随着开发的进展，其他库中将会有更多功能。就目前情况而言，可以说这些故事满足了所有陈述的要求，只因为只有一个组件安装：

+   作为 Artisan，我需要将业务对象库与我的应用程序一起安装，以便应用程序能够按需工作，而无需我安装其依赖组件。

+   作为中央办公室用户，我需要将业务对象库与我的应用程序一起安装，以便应用程序能够按需工作，而无需我安装其依赖组件。

+   作为系统管理员，我需要将业务对象库与 Artisan Gateway 服务一起安装，以便它能够按需工作，而无需我安装其依赖组件。

也可以说，尽管这些故事在此时此刻是完整的，但它们将不得不在尚未构建的各种应用程序和服务组件的开发周期中重复。在这些组件有自己的代码、构建和包之前，就没有需要处理的依赖关系。

# 操作/使用、维护和停用考虑

考虑到这个软件包的简单性，以及它没有外部依赖，对于软件包的操作和使用，或者停用它，都没有明显的考虑或潜在的关注点。在后一种情况下，停用将只是卸载软件包（`pip uninstall HMS-Core`）。维护考虑也将同样限制在更新软件包本身，只需通过重新运行原始安装过程并使用新的软件包文件来管理。

# 总结

这次迭代已经定义了代表系统重要功能方面的基本业务对象，这些对象代表了最终系统的数据元素。然而，它们都只提供了基本的结构和一些关于构成这些元素有效结构的业务规则，除此之外，还没有存储这些元素、检索它们或与它们进行交互的机制，除了直接在代码中通过它们的属性。

下一次迭代章节将深入研究系统应用程序和服务层所需的存储和状态数据持久性。


# 第十章：考虑业务对象数据持久性

大多数程序和系统都需要存储和检索数据以进行操作。毕竟，将数据嵌入代码本身是不切实际的。涉及的数据存储形式可以根据底层存储机制、应用程序或服务的特定需求，甚至名义上的非技术约束（如不需要用户安装其他软件）而大相径庭，但无论这些因素加起来是什么，根本需求始终是一样的。

`hms_sys`的各个组件项目/子系统也不例外：

+   **Artisan** **Application**需要允许**Artisan**用户管理**Artisan**正在创建和销售的**products**，并且至少需要管理部分自己的业务实体数据

+   **Artisan** **Gateway**服务可能至少需要为**artisans**、**products**和**orders**以及相关的**Customer**和**Address**对象分阶段数据，因为这些对象包含的数据会通过各种流程移动

+   **Central Office Application**需要能够管理**Artisan**和**Product**的部分数据，并且可能需要读取订单数据，即使只是出于故障排除目的

到目前为止，还没有具体的要求说明这些数据将如何持久化，甚至在哪里，尽管**Artisan Application**可能需要在本地保留数据并将其传播到**Artisan Gateway**或通过**Central Office Application**访问，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/3153758b-360e-4547-8b76-8a2ecadae869.png)

本次迭代将通过对`hms_sys`中各个组件项目的数据持久性机制的需求、实施和测试进行分析，从而开始一些基本的分析。然而，目前我们甚至不清楚后端数据存储是什么样子，因此我们无法编写任何有用的指导如何实现数据持久性的故事。显然，这需要更多的调查工作才能在规划和执行本次迭代之前进行。

本章将研究以下主题：

+   迭代（敏捷）过程通常如何处理没有足够信息来执行的故事

+   一般有哪些数据存储和持久性选项

+   在决定各种`hms_sys`组件项目如何处理数据访问之前，应该检查哪些数据访问策略

# 迭代是（在某种程度上）灵活的

在许多敏捷方法中，有特定的工件和/或流程旨在处理这种迭代开始的情况——即存在某种功能的需求，即使只是暗示性的，但实际上没有足够的信息来对这种需求进行任何开发进展。甚至可能已经有一些看似完整的故事，但缺少了一些开发所需的细节。在这种情况下，这些故事可能类似于以下内容：

+   作为**Artisan**，我需要我的**Product**数据被本地存储，这样我就可以在不必担心连接到可能无法立即访问的外部系统的情况下使用它。

+   作为**产品经理**/**批准人**，我需要能够访问任何/所有**artisans**的**Product**信息，以便我可以在网店中管理这些产品的可用性

+   作为**系统管理员**，我需要**Artisan Gateway**将**Product**和相关数据与主**Web Store**应用程序分开存储，以便在发布到公共站点之前可以安全地分阶段处理

所有这些故事看起来可能都是完整的，因为它们定义了每个用户的需求，但它们缺乏关于这些功能应如何运作的任何信息。

进入 Spike。

尖峰，起源于 XP 方法论，并已被其他几种敏捷方法论（正式或非正式地）采纳，本质上是为了研究并返回其他故事可用的计划细节的故事。理想情况下，需要围绕它们生成尖峰的故事将在进入迭代之前被识别出来 - 如果这种情况没有发生，信息不足的故事将是无法工作的，并且不可避免地会发生某种洗牌，以推迟不完整的故事直到它们的尖峰完成，或者将尖峰及其结果纳入修订后的迭代计划中。前者往往更有可能发生，因为没有来自尖峰的信息，估算目标故事将是非常困难的，甚至可能是不可能的。与我们之前提到的原始故事相关的尖峰故事可能会被写成这样：

+   作为开发人员，我需要知道 Artisan 应用程序数据的存储和检索方式，以便我可以为这些过程编写代码

+   作为开发人员，我需要知道中央办公应用程序数据的存储和检索方式，以便我可以为这些过程编写代码

+   作为开发人员，我需要知道 Artisan Gateway 数据的存储和检索方式，以便我可以为这些过程编写代码

为了解决这些问题并完成本次迭代的故事，了解可用的选项将是有帮助的。一旦这些选项被探索，它们可以在应用程序和系统的服务层的背景下进行权衡，并可以做出一些最终的实施方法决策，以及编写一些最终的故事来应对。

# 数据存储选项

所有将受到认真考虑的选项都具有一些共同的特性：

+   他们将允许数据脱机存储，这样应用程序或服务程序不需要持续运行以确保相关数据不会丢失

+   它们必须允许应用程序和服务执行至少四个标准 CRUD 操作中的三个：

+   创建：允许存储新对象的数据。

+   读取：允许访问现有对象的数据，一次一个，一次全部，可能还带有一些过滤/搜索功能。

+   更新：允许在需要时更改现有数据。

+   删除：允许（也许）删除不再相关的对象的数据。至少，标记这样的数据，以便它不会普遍可用也可以。

它们还应该根据 ACID 特性进行检查和评估，尽管这些属性中并非所有都可能在`hms_sys`的数据需求背景下是必不可少的。然而，没有一个是不可实现的：

+   原子性：数据交易应该是全有或全无的，因此如果数据写入的一部分失败，正在写入的整个数据集也应该失败，使数据处于稳定状态

+   一致性：数据交易应始终导致整个数据集中的有效数据状态，遵守和遵守任何存储系统规则（应用级规则是应用程序的责任）

+   隔离性：数据交易应始终导致与它们的组成更改按相同顺序逐个执行时会发生的最终状态相同

+   耐久性：一旦提交，数据交易应以防止由系统崩溃、断电等原因造成的损失的方式存储

# 关系数据库

**关系数据库管理系统**（**RDBMSes**）是可用于应用程序的更成熟的数据存储方法之一，其选项已经普遍使用了几十年。它们通常将数据存储为表中的单独记录（有时称为**行**），这些表（或**关系**）定义了所有成员记录的字段名称（**列**）和类型。表通常定义了一个主键字段，为表中的每条记录提供唯一标识符。一个简单的定义用户记录的表的示例可能如下所示：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/5e038e50-4222-4c9f-be26-bedad3bd993e.png)

表中的每条记录都是一致的数据结构，例如在前面的例子中，所有用户都会有`user_id`、`first_name`、`last_name`和`email_address`的值，尽管除`user_id`之外的字段的值可能为空或为`NULL`。任何表中的数据都可以通过查询访问或组装，而无需更改表本身，并且可以在查询中连接表，以便在另一个表中关联拥有的记录，例如订单。

这种结构通常被称为模式，它既定义了结构，又强制执行数据约束，如值类型和大小。

关系数据库最常见的查询语言是**结构化查询语言**（**SQL**）—或者至少是它的某个变体。SQL 是一种 ANSI 标准，但有许多可用的变体。可能还有其他的，但 SQL 几乎肯定是最受欢迎的选择，并且非常成熟和稳定。

SQL 本身就是一个复杂的话题，即使不考虑它在数据库引擎之间的变化，也足以值得一本专门的书。随着`hms_sys`迭代的进行，我们将探讨一些 SQL，并解释发生了什么。

# 优点和缺点

关系数据库数据存储的一个更重要的优势是它能够在单个查询请求中检索相关记录，例如前面提到的用户/订单结构。大多数关系数据库系统还允许在单个请求中进行多个查询，并将每个查询的记录集作为单个结果集返回。例如，可以查询相同的用户和订单表结构，以返回单个用户及该用户的所有订单，这在应用程序对象结构中具有一些优势，其中一个对象类型具有一个或多个与其关联的对象集合。

对于大多数关系数据库引擎来说，另一个可能重要的优势是它们对事务的支持——允许一组潜在复杂的数据更改或插入在任何单个数据操作失败的情况下作为一个整体回滚。这几乎可以保证在任何 SQL RDBMS 中都可以使用，并且在处理金融系统时是非常重要的优势。对于处理资金流动的系统，事务支持可能是一个功能性要求——如果不是，那么很可能值得问一下为什么不是。支持跨多个操作的事务是完全 ACID 兼容性的一个关键方面——如果没有，原子性、一致性和（在某种程度上）隔离标准将受到怀疑。幸运的是，几乎任何值得被称为关系数据库系统的系统都将提供足够满足任何可能出现的需求的事务支持。

许多关系数据库系统还支持创建视图和存储过程/函数，可以使数据访问更快速、更稳定。视图在实际上是预定义的查询，通常跨越多个表，并且通常用于检索与它们绑定的表中的特定数据子集。存储过程和函数可以被视为应用程序函数的近似等价物，接受某些输入，执行一些任务，并可能返回由执行这些任务生成的数据。至少，存储过程可以用来代替编写查询，这具有一些性能和安全性的好处。

大多数关系数据库中表的固有模式可能既是优势也是缺点。由于该模式强制执行数据约束，因此表中存在不良数据的可能性较小。预期为字符串值或整数值的字段将始终是字符串或整数值，因为不可能将字符串字段设置为非字符串值。这些约束确保数据类型的完整性。然而，这种权衡是，值类型（有时甚至是值本身）在进入或离开数据存储时可能需要进行检查和/或转换。

如果关系数据库有一个缺点，那可能是包含数据的表的结构是固定的，因此对这些表进行更改需要更多的时间和精力，而这些更改可能会影响访问它们的代码。例如，在数据库中更改字段名称很可能会破坏引用该字段名称的应用功能。大多数关系数据库系统还需要单独的软件安装和全天候运行的服务器硬件，就像相关的应用程序一样。这可能对任何特定项目是一个问题，也可能不是，但特别是如果该服务器位于他人的基础设施中，这可能是一个成本考虑因素。

扩展关系数据库管理系统可能仅限于为服务器本身增加更多的性能——改进硬件规格、增加内存或将数据库移动到新的更强大的服务器。前述的一些数据库引擎还有额外的软件包，可以提供多服务器规模，例如横向扩展到多个仍然像单个数据库服务器一样的服务器。

# MySQL/MariaDB

MySQL 是一种流行的关系数据库管理系统，始于 1990 年代中期的一个开源项目。MariaDB 是 MySQL 的一个由社区维护的分支，旨在作为 MySQL 的一个可替换的替代品，并且在 MySQL（现在由 Oracle 拥有）停止以开源许可发布时仍然作为一个开源选项可用。在撰写本书时，MySQL 和 MariaDB 是可以互换的。

两者使用相同的 SQL 变体，与标准 SQL 的语法差异通常非常简单。MySQL 是——而 MariaDB 被认为是——更适用于读取/检索数据而不是写入数据，但对于许多应用程序来说，这些优化可能不会明显。

MySQL 和 MariaDB 可以通过使用集群化和/或复制软件附加到基本安装来进行横向扩展，以满足高可用性或负载需求，尽管为了真正有效，需要额外的服务器（真实或虚拟）。

有几个 Python 库可用于连接和与 MySQL 交互，由于 MariaDB 旨在能够直接替代 MySQL，因此预计这些相同的库可以在不修改的情况下用于 MariaDB 访问。

# MS-SQL

微软的 SQL Server 是一种专有的基于 SQL 的数据库管理系统，使用自己的标准 SQL 变体（T-SQL——就像 MySQL 的变体一样，差异通常是微不足道的，至少对于简单到稍微复杂的需求来说）。

MS-SQL 也具有用于高可用性和负载场景的集群和复制选项，需要离散服务器以最大化水平扩展的效果。

至少有两种 Python 选项可用于连接和处理 MS-SQL 数据库：

+   `pymssql`：这专门利用了 MS-SQL 使用的**表格数据流**（**TDS**）协议，并允许更直接地连接到后端引擎

+   `pyodbc`：这通过**开放数据库连接**（**ODBC**）协议提供数据库连接，微软在 2018 年中已经对其表示信心

# PostgresQL

PostgreSQL 是另一个开源数据库选项，是一种设计重点在于符合标准的对象关系数据库系统。作为 ORDBMS，它允许以更面向对象的方式定义数据结构，具有类似于从其他表/类继承的类的功能。它仍然使用 SQL——它自己的变体，但对于大多数开发目的来说，差异基本可以忽略，并且有几种 Python 选项可用于连接和处理数据库。它还具有复制和集群支持，与先前选项的注意事项相同。

# NoSQL 数据库

在撰写本文时，有数十种 NoSQL 数据库选项可用，既作为独立/本地服务安装，也作为云数据库选项。它们设计的主要驱动因素包括以下重点：

+   **支持大量用户：**数以万计的并发用户，也许是数百万，并且应尽可能小地影响其性能

+   **高可用性和可靠性：**即使一个或多个数据库节点完全离线，也能与数据进行交互

+   **支持高度流动的数据结构：**允许结构化数据不受严格的数据模式约束，甚至可以跨同一数据存储集合中的记录

从开发的角度来看，这个列表中的最后一点可能是最重要的，允许根据需要定义几乎任意的数据结构。

如果在关系型数据库管理系统（RDBMS）中，表的概念是一种存储模型，那么在 NoSQL 数据库连续体中有许多替代存储模型：

+   **文档存储：**每个记录等价物都是包含创建时使用的任何数据结构的文档。文档通常是 JSON 数据结构，因此允许在不同数据类型之间进行一些区分——字符串、数字和布尔作为简单值，嵌套列表/数组和对象用于更复杂的数据结构，并且还允许使用正式的`null`值。

+   **键/值存储：**每个记录等价物只是一个值，可以是任何类型，并且由单个唯一键标识。这种方法可以被认为是等同于单个 Python `dict`结构的数据库。

+   **宽列存储：**每个记录可以被认为属于具有非常大（无限？）数量列的 RDBMS 表，也许有主键，也许没有。

还有一些变体感觉像是结合了这些基本模型的方面。例如，在 Amazon 的 DynamoDB 中创建数据存储，首先要定义一个表，需要定义一个键字段，并且还允许定义一个辅助键字段。一旦创建了这些，这些表的内容就像一个文档存储一样。因此，最终的结果就像一个键/文档存储（每个键指向一个文档的键/值存储）。

NoSQL 数据库通常是非关系型的，尽管也有例外。从开发的角度来看，这意味着在处理存储和检索来自 NoSQL 数据存储的应用程序数据时，至少需要考虑三种方法之一：

+   永远不要使用与其他数据相关的数据——确保每个记录都包含作为单个实体所需的一切。这里的折衷是，很难，甚至不可能解决记录（或与记录关联的对象）被两个或更多其他记录/对象共享的情况。一个例子可能是多个用户都是成员的用户组。

+   处理代码中与记录之间的关系。使用刚提到的相同的用户/组概念，这可能涉及到一个`Group`对象，读取所有相关的`User`记录，并在实例化过程中使用来自该数据的`User`对象填充`users`属性。可能会有一些并发更改相互干扰的风险，但不会比在基于关系型数据库的系统中进行相同类型的过程的风险更大。这种方法还意味着数据将按对象类型进行组织——一个独立的`User`对象数据集合和一个独立的`Group`对象数据集合，但任何允许区分不同对象类型的机制都可以工作。

+   选择一个提供某种关系支持的后端数据存储引擎。

NoSQL 数据库也不太可能支持事务，尽管再次有提供完全符合 ACID 的事务能力的选项，处理数据存储级别的事务要求的标准/选项与前面提到的处理关系能力的标准/选项非常相似。即使没有任何事务支持的数据库仍然会对单个记录进行 ACID 兼容——在这个复杂程度上，要求兼容的是记录是否成功存储。

# 优势和缺点

鉴于大多数 NoSQL 选项背后的高可用性和并发用户关注，他们比关系型数据库管理系统更适合于可用性和可扩展性重要的应用程序，这一点应该并不奇怪。这些属性在大数据应用程序和云中更为重要，正如主要云提供商都在这一领域提供自己的产品，并为一些知名的 NoSQL 选项提供起点所证明的那样：

+   亚马逊（AWS）：

+   DynamoDB

+   谷歌：

+   Bigtable（用于大数据需求）

+   数据存储

+   微软（Azure）：

+   Cosmos DB（前身为 DocumentDB）

+   Azure 表存储

在开发过程中，更或多或少地任意定义数据结构的能力也可以是一个重要的优势，因为它消除了定义数据库模式和表的需要。潜在的折衷是，由于数据结构可以同样任意地改变，使用它们的代码必须被编写为容忍这些结构的变化，或者可能必须计划一些有意识的努力来应用这些变化到现有数据项，而不会破坏系统和它们的使用。

例如，考虑之前提到的`User`类 - 如果需要向类添加`password_hash`属性，以提供身份验证/授权支持，实例化代码可能需要考虑它，并且任何现有的用户对象记录可能不会有该字段。在代码方面，这可能并不是什么大问题 - 在初始化期间将`password_hash`作为可选参数处理将允许创建对象，并且如果未设置它，则将其存储为 null 值将处理数据存储方面，但需要计划、设计和实施某种机制以提示用户提供密码以存储真实值。如果在基于 RDBMS 的系统中进行类似更改，将需要发生相同类型的过程，但很可能会有已建立的流程来更改数据库模式，并且这些流程可能包括修改模式和确保所有记录具有已知起始值。

考虑到可用的选项数量，也不足为奇的是它们在执行类似任务时存在差异（有时是显著的）。也就是说，从数据中检索记录，只需提供要检索的项目的唯一标识符（`id_value`），使用不同的库和基于数据存储引擎的语法/结构：

+   在 MongoDB 中（使用`connection`对象）：

+   `connection.find_one({'unique_id':'id_value'})`

+   在 Redis 中（使用`redis connection`）：

+   `connection.get('id_value')`

+   在 Cassandra 中（使用`query`值和`criteria`列表，针对 Cassandra`session`对象执行）：

+   `session.execute(query, criteria)`

每个不同的引擎可能会有其自己独特的执行相同任务的方法，尽管可能会出现一些常见的名称 - 毕竟，对于函数或方法名称，如 get 或 find，只有那么多的替代方案是有意义的。如果系统需要能够与多个不同的数据存储后端引擎一起工作，这些都是设计和实施通用（可能是抽象的）数据存储适配器的良好候选者。

由于关系和事务支持因引擎而异，这种不一致性也可能是 NoSQL 数据存储的一个缺点，尽管如果它们缺乏，至少有一些选项可以追求。

# MongoDB

MongoDB 是一个免费的开源 NoSQL 文档存储引擎 - 也就是说，它将整个数据结构存储为单独的文档，如果不是 JSON，也非常类似于 JSON。在 Python 中发送到和从`MongoDB`数据库检索的数据使用 Python 本机数据类型（`dict`和`list`集合，任何简单类型，如`str`和`int`，可能还有其他标准类型，如`datetime`对象）。

MongoDB 被设计为可用作分布式数据库，支持高可用性、水平扩展和地理分布。

像大多数 NoSQL 数据存储解决方案一样，MongoDB 是无模式的，允许 MongoDB 集合中的文档（大致相当于 RDBMS 中的表）具有完全不同的结构。

# 其他 NoSQL 选项

如前所述，有数十种 NoSQL 数据库选项可供选择。以下是三种具有 Python 驱动程序/支持的本地安装的 NoSQL 数据库的更受欢迎的选项：

+   **Redis**：键/值存储引擎

+   **Cassandra**：宽列存储引擎

+   **Neo4j**：图数据库

# 其他数据存储选项

另一个选项——对于大量数据或在重要并发用户负载下可能效果不佳的选项——是将应用程序数据简单地存储为本地机器上的一对多文件。随着简单结构化数据表示格式（如 JSON）的出现，这可能比乍一看更好，至少对于某些需求来说：特别是 JSON，具有基本值类型支持和表示任意复杂或大型数据结构的能力，是一个合理的存储格式。

最大的障碍是确保数据访问至少具有一定程度的 ACID 兼容性，尽管与 NoSQL 数据库一样，如果所有事务都是单个记录，仍然可以依靠 ACID 兼容性，原因是事务的简单性。

在使用文件存储应用程序数据时必须解决的另一个重要问题是语言或基础操作系统如何处理文件锁定。如果其中一个允许在写入过程中或不完整的情况下读取打开的文件，那么读取不完整数据文件的读取就会误读可用数据，然后将错误数据提交到文件中，可能导致至少数据丢失，甚至可能在过程中破坏整个数据存储。

显然那将是不好的。

访问速度也可能是一个问题，因为文件访问比内存中存储的数据访问速度要慢。

也就是说，有一些策略可以应用于使本地基于文件的数据存储免受这种失败的影响，只要数据只从代码中的单一来源访问。解决潜在的访问速度问题也可以在同一过程中完成，过程如下：

+   使用数据的程序开始：

+   从持久文件系统数据存储中将数据读入内存

+   使用程序，并发生数据访问：

+   从内存中读取数据的副本，并传递给用户

+   以某种方式更改数据：

+   注意到更改，并在返回控制权给用户之前将更改提交到文件系统数据存储

+   关闭程序：

+   在终止之前，将检查所有数据以确保没有仍在等待的更改

+   如果有变化，请等待它们完成

+   如果需要，将所有数据重新写入文件系统数据存储

# 选择数据存储选项

查看`hms_sys`的逻辑架构，并允许**Artisan Application**使用原始图表中不存在的本地数据存储，开发需要关注三个数据库：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/f7054630-6ba8-4568-b1a2-e938bd1bb3e3.png)

**Web-Store Database**连接到**Web-Store Application**，因此无法进行修改。当前的期望是对该数据库中的数据进行修改将通过**Web-Store Application**提供的 API 调用来处理。因此，此时可以搁置对该数据库的数据访问。

另一方面，`artisan` **Database**根本不存在，将必须在开发`hms_sys`的过程中创建。可以安全地假设，鉴于第一次迭代中与安装相关的 artisan 级别的故事，最好尽可能减少他们需要执行的软件安装数量。这反过来又表明，在**Artisan Application**级别，本地文件系统数据存储可能是首选选项。这允许以下操作：

+   数据存储在安装或应用程序的初始设置期间在本地生成

+   **工匠**可以在本地管理他们的数据，即使他们离线

+   **Artisan**无需进行任何额外的软件安装来管理数据存储

由于预计**Artisan 应用程序**将是本地桌面应用程序，这很好地符合之前提到的一组过程，以使基于文件的数据存储安全稳定。如果**Artisan**安装了多个**Artisan 应用程序**（例如在多台机器上各安装一个），则存在一些数据冲突的风险，但实际上任何本地数据存储选项都会存在这种风险 - 除非将数据存储移到共同的在线数据库，否则真的没有办法减轻这种特定的担忧，而这超出了目前`hms_sys`的开发范围。

关于集中数据和应用程序的想法将在以后更详细地进行检查。目前，Artisan 级别的所有内容都将与 Artisan 应用程序本地驻留。

`hms_sys` **数据库**目前也不存在。不像`artisan` **数据库**，它旨在允许多个并发用户 - 任何数量的中央办公室用户可能在任何给定时间审查或管理产品，因为工匠正在提交产品信息进行审查，并且在这些活动进行时，也可以设置相关工匠的订单从网络商店中中继或拉出。综合起来，这足以排除本地文件存储方法 - 它可能仍然可以做到，并且在当前使用水平下甚至可能是可行的，但如果使用/负载增加太多，可能会迅速遇到扩展问题。

考虑到，即使我们不知道将使用什么后端引擎，知道它不会是**Artisan 应用程序**使用的相同存储机制，就确认了之前提到的想法，即我们最好定义一个通用的数据访问方法集，围绕该结构生成某种抽象，并在每个应用程序或服务对象级别定义具体实现。采取这种方法的优势实际上归结为相同的**面向对象设计原则**（**OODP**）的变体：多态。

# 多态（和面向接口编程）

**多态**，简单来说，是对象在代码中可以互换而不会破坏任何东西的能力。为了实现这一点，这些对象必须在整个范围内呈现公共接口成员 - 相同的可访问属性和方法。理想情况下，这些公共接口成员也应该是唯一的接口成员，否则有破坏这些对象互换性的风险。在基于类的结构中，通常最好将该接口定义为一个单独的抽象 - 在 Python 中是一个 ABC，有或没有具体成员。考虑以下一组用于连接和查询各种关系数据库后端的类：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/ce655e2f-48f4-4520-82d8-e47db56b42eb.png)

其中：

+   `BaseDatabaseConnector`是一个抽象类，要求所有派生类实现一个查询方法，并提供`host`，`database`，`user`和`password`属性，这些属性将用于实际连接到给定的数据库

+   具体类`MySQLConnector`，`MSSQLConnector`和`ODBCConnector`分别实现了所需的`query`方法，允许实例实际执行针对连接到的数据库的查询

只要连接属性（`host`，…，`password`）存储在配置文件中（或者实际代码之外的任何地方），并且有一种方法来指定在运行时定义哪种连接器类型，甚至可能在执行期间切换，那么允许在运行时定义这些不同连接类型并不难。

这种可互换性反过来又允许编写代码，而不需要了解进程如何工作，只需要知道应该如何调用以及期望返回什么结果。这是编程到接口而不是到实现的实际示例，这在第五章《hms_sys 系统项目》中提到，以及封装变化的概念。这两者经常同时出现，就像在这种情况下一样。

以这种方式替换对象还有另一个好处，可以称之为未来证明代码库。如果在将来的某个时候，使用先前显示的数据连接器的代码突然需要能够连接到并使用尚未可用的数据库引擎，那么使其可用的工作量将相对较小，前提是它使用了与已经存在的连接参数和类似的连接过程。例如，要创建一个`PostgreSQLConnector`（用于连接到`PostgreSQL`数据库），只需要创建这个类，从`BaseDatabaseConnector`派生，并实现所需的`query`方法。这仍然需要一些开发工作，但不像如果每个数据库连接过程都有自己独特的类那样需要的工作量那么大。

# 数据访问设计策略

在我们开始为这个迭代编写故事之前，我们需要进行的最后一点分析是确定对象数据访问的责任将在哪里。在脚本或其他纯过程化的上下文中，简单地连接到数据源，根据需要读取数据，根据需要修改数据，并将任何更改重新写出可能就足够了，但这只有在整个过程相对静态时才可行。

在`hms_sys`这样的应用程序或服务中，数据使用非常像是随机访问的场景——可能会有常见的程序，甚至看起来很像简单脚本的逐步实现，但这些过程可能（并且将）以完全不可预测的方式启动。

这意味着我们需要具有易于调用和可重复的数据访问过程，而且需要付出最小的努力。考虑到我们已经知道至少会有两种不同的数据存储机制在起作用，如果我们能够设计这些过程，使得无论底层数据存储看起来如何，都可以使用完全相同的方法调用，那么未来的支持和开发也会变得更加容易——再次抽象出这些过程，让代码使用接口而不是实现。

一种可以实现这种抽象的选项是从数据源开始，使每个数据源都意识到正在进行的对象类型，并存储它需要能够为每个对象类型执行 CRUD 操作的信息。这在技术上是可行的实现，但会变得非常复杂，因为需要考虑和维护每种数据存储和业务对象类型的组合。即使初始类集仅限于三种数据存储变体（**Artisan Application**的文件系统数据存储，通用 RDBMS 数据存储和通用 NoSQL 数据存储），也有四种操作（CRUD）跨三种数据存储类型的四种业务对象，总共有 48 种排列组合（4×3×4）需要构建、测试和维护。每添加一个新的操作，比如说，能够搜索业务对象数据存储，以及每个新的需要持久化的业务对象类型和每种新的数据存储类型，都会使排列组合数量成倍增加——每增加一个，数量就增加到 75 个项目（5×3×5），这可能很容易失控。

如果我们退一步思考我们实际需要的所有这些组合，可能存在一种不同且更可管理的解决方案。对于每个需要持久化的业务对象，我们需要能够执行以下操作：

1.  为新对象创建记录。

1.  读取单个对象的记录，以某种方式标识，并返回该项的实例。

1.  在对其进行更改后，更新单个对象的记录。

1.  删除单个对象的记录。

1.  根据某些条件匹配找到并返回零到多个对象。

能够标记对象处于特定状态——活动与非活动，以及已删除（实际上没有删除基础记录）可能也很有用。跟踪创建和/或更新日期/时间也是一种常见做法——这有时对于排序目的很有用，如果没有其他用途的话。

所有 CRUD 操作直接与对象类型本身相关——也就是说，我们需要能够创建、读取、更新、删除和查找`Artisan`对象，以便与它们一起使用。这些实例的各种对象属性可以根据需要在实例创建的上下文中检索和填充，作为实例创建过程的一部分创建，或根据需要与拥有实例或单独更新。考虑到这些从属操作，跟踪对象的记录是否需要创建或更新也可能很有用。最后，我们需要跟踪每个对象状态数据记录在数据存储中的唯一标识符。将所有这些放在一起，以下是`BaseDataObject` ABC 可能看起来像的：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/27441a06-1d8a-4271-a12f-d043113f975b.png)

这些属性都是具体的，在`BaseDataObject`级别内部实现：

+   `oid`是对象的唯一标识符，是一个`UUID`值，在数据访问期间将存储为字符串并转换。

+   `created`和`modified`是 Python `datetime`对象，可能也需要在数据访问期间转换为字符串值表示。

+   `is_active`是一个标志，指示是否应将给定记录视为活动记录，这允许对记录的活动/非活动状态进行一些管理，从而对应该记录的对象进行管理。

+   `is_deleted`是一个类似的标志，指示记录/对象是否应被视为已删除，即使它实际上仍然存在于数据库中。

+   `is_dirty`和`is_new`是标志，用于跟踪对象的相应记录是否需要更新（因为它已更改）或创建（因为它是新的）。它们是本地属性，不会存储在数据库中。

使用 `UUID` 而不是数字序列需要更多的工作，但在网络应用程序和服务实现中具有一些安全优势——`UUID` 值不容易预测，并且有 16³² 个可能的值，使得对它们的自动化利用变得更加耗时。可能存在要求（或至少有一种愿望）永远不真正删除记录。在某些行业或者对于需要满足某些数据审计标准的上市公司来说，希望至少在一段时间内保留所有数据并不罕见。

`BaseDataObject` 定义了两个具体的和三个抽象的实例方法：

+   `create`（抽象和受保护的）将要求派生类实现一个过程，用于创建和写入相关数据库的状态数据记录。

+   `matches`（具体）将在被调用的实例的属性值与传递给它的条件的相应值匹配时返回一个布尔值。这将在 `get` 方法中实现基于条件的过滤中起到关键作用，这将很快讨论。

+   `save`（具体）将检查实例的 `is_dirty` 标志，调用实例的 `update` 方法并在其为 `True` 时退出，然后检查 `is_new` 标志，如果为 `True` 则调用实例的 `create` 方法。这样做的最终结果是，任何继承自 `BaseDataObject` 的对象都可以简单地被告知 `save` 自身，将采取适当的操作，即使它没有任何操作。

+   `to_data_dict`（抽象）将返回对象状态数据的 `dict` 表示，其中的值以可以写入状态数据记录所在的数据库的格式和类型为准。

+   `update`（抽象和受保护的）是 `create` 方法的更新实现对应物，用于更新对象的现有状态数据记录。

`BaseDataObject` 还定义了四个类方法，所有这些方法都是抽象的——因此，这些方法中的每一个都绑定到*类*本身，而不是类的实例，并且必须由从 `BaseDataObject` 派生的其他类实现：

+   `delete` 对由提供的 `*oids` 标识的每条记录执行物理记录删除。

+   `from_data_dict` 返回一个填充有提供的 `data_dict` 中的状态数据的类的实例，这通常是从针对这些记录所在的数据库的查询中得到的。它是 `to_data_dict` 方法的对应物，我们已经描述过了。

+   `get` 是从数据库中检索状态数据的主要机制。它被定义为允许返回特定记录（`*oids` 参数列表）和过滤条件（在 `**criteria` 关键字参数中，这些参数预期将传递给每个对象的匹配条件），并将根据这些值返回一个未排序的对象实例列表。

+   `sort` 接受一个对象列表，并使用传递给 `sort_by` 的回调函数或方法对它们进行排序。

`BaseDataObject` 捕获了所有功能要求和常见属性，这些属性需要存在才能让业务对象类和实例负责其数据存储交互。暂时不考虑任何数据库引擎问题，定义一个数据持久性能力的业务对象类，比如 **Artisan Application** 中的 `Artisan`，变得非常简单——最终的具体 `Artisan` 类只需要继承自 `BaseArtisan` 和 `BaseDataObject`，然后实现这些父类所需的九个抽象方法。

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/3df11c98-040d-47f9-b173-7dd6316a8127.png)

如果可以安全地假定任何给定的应用程序或服务实例将始终为每种业务对象类型使用相同的数据存储后端，那么这种方法就足够了。任何特定于引擎的需求或功能都可以简单地添加到每个最终的具体类中。但是，也可以将特定数据存储引擎（例如 MongoDB 和 MySQL）所需的任何属性收集到一个额外的抽象层中，然后让最终的具体对象从其中一个派生出来：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/cf623f73-1b8e-4027-b16d-50774d8ca167.png)

在这种情况下，最终的`Artisan`类可以从`MongoDataObject`或`MySQLDataObject`中派生出来，并且可以强制执行执行针对这些特定后端引擎的数据访问方法所需的任何数据。这些中间层的 ABC 也可能为每种引擎类型提供一些有用的方法，例如，使用`create_sql`类属性中的模板 SQL，并用`to_data_dict()`结果中的实例数据值填充它，可以创建用于 MySQL 调用创建实例的最终 SQL。这种方法将保持任何给定业务对象类所需的大部分数据访问信息在该类中，并与业务对象本身相关联，这看起来不像一个坏主意，尽管如果需要支持很多组合，它有可能变得复杂。它还将保持向所有数据对象添加新功能所需的工作量（在类树的`BaseDataObject`级别）更可管理——添加新的抽象功能仍然需要在所有派生的具体类中实现，但任何具体的更改将被继承并立即可用。

# 数据访问决策

有了所有这些因素，现在是时候做出一些关于各个组件项目的对象如何跟踪其数据的决定了。为了在所有对象数据访问周围有一个单一的接口，我们将实现先前描述的`BaseDataObject` ABC，或者非常类似它的东西，并从先前迭代中构建的相关业务对象类的组合中派生出我们最终的数据持久化具体类。最终，我们将得到我们所谓的数据对象的类，它们能够读取和写入自己的数据。

在**Artisan Application**中，由于我们不需要担心并发用户同时与数据交互，也不想在没有更好的选择的情况下给**Artisan**用户增加额外的软件安装，我们将使用本地文件来存储对象数据来构建数据持久性机制。

在将在中央办公室环境中运行的代码中，我们将有并发用户，至少可能会有，并且数据存储需要集中在专用数据库系统中。没有明显需要正式的数据库驻留模式（尽管有一个也不是坏事），因此使用 NoSQL 选项应该可以缩短开发时间，并在数据结构需要意外更改时提供一些灵活性。当我们到达开发工作的那部分时，我们将更详细地重新审视这些选项。

# 为什么要从头开始？

这种功能结构将从头开始构建，但在其他情境中可能也有其他可以起作用甚至更好的选择。例如，有几个**对象关系映射器**（**ORM**）包/库可供使用，允许在代码中定义数据库和结构，并传播到数据存储中，其中一些集成到完整的应用程序框架中。这些包括 Django 的`models`模块，它是整体 Django web 应用程序框架的一部分，是开发 Web 应用程序的常见和流行选项。其他变体包括 SQLAlchemy，提供了一个在 SQL 操作上的抽象层和一个用于处理对象数据的 ORM。

还有特定的驱动程序库适用于几种数据库选项（SQL 和 NoSQL 都有），其中一些可能提供 ORM 功能，但所有这些都至少提供连接到数据源并执行查询或对这些数据源执行操作的基本功能。完全可以编写代码，简单地执行针对 RDBMS（如 MySQL 或 MariaDB）的 SQL，或者执行与该 SQL 对应的函数针对 NoSQL 引擎（如 MongoDB）或甚至云驻留数据存储（如 Amazon 的 DynamoDB）。对于简单的应用程序，这实际上可能是一个更好的方法，至少最初是这样。这将减少开发时间，因为迄今为止我们探讨的各种抽象层根本不会出现在图中，而且代码本身会具有一定类型的简单性，因为它所需要做的就是执行基本的 CRUD 操作，甚至可能并非所有这些操作。

正在为`hms_sys`开发的数据对象结构将暴露出许多涉及数据访问框架设计的基本原则，这也是选择从头开始的方法的部分原因。另一个原因是，因为它将处于全面 ORM 方法和低级“执行对连接的查询”实现策略之间的某个地方，它将展示这两种方法的许多相关方面。

# 摘要

数据访问机制和流程有很多选择，虽然偶尔会有要求几乎强制使用其中一种，但可能没有一种方法适用于所有开发工作。特别是，如果时间很重要，寻找现成的解决方案可能是一个很好的起点，但如果要求或其他限制不允许轻松应用其中之一，创建自定义解决方案也是可以的。

在深入研究特定数据存储机制之前，逻辑的起点可能是定义集体数据访问需求的抽象层-即定义`BaseDataObject` ABC-这就是我们接下来要解决的问题。


# 第十一章：数据持久性和 BaseDataObject

本章将专注于`BaseDataObject` ABC（抽象基类）的开发和测试，我们将在`hms_artisan`（**Artisan Application**）和`hms_gateway`（**Artisan Gateway**服务）组件项目中都需要它。`hms_co`（**Central Office Application**）代码库可能也需要利用相同的功能。在后面深入研究`hms_co`代码时，我们将更深入地了解这一点。

目前，我们期望`BaseDataObject`看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/5ea73312-a111-454d-8888-4ee6220ffe0a.png)

之前描述的驱动`BaseDataObject`设计和实现的故事如下：

+   作为开发人员，我需要一个通用的结构来提供整个系统可用的业务对象的状态数据的持久性，以便我可以构建相关的最终类

`BaseDataObject`与`hms_core`中的业务对象定义没有功能上的关联，但它提供的功能仍然需要对所有真实的代码库（应用程序和**Artisan Gateway**服务）可用，因此它应该存在于`hms_core`包中，但可能不应该与上一次迭代的业务对象定义一起。从长远来看，如果`hms_core`的各个成员被组织成将元素分组到共同目的或主题的模块，那么理解和维护`hms_core`包将更容易。在本次迭代结束之前，当前的`hms_core.__init__.py`模块将被重命名为更具指示性的名称，并且它将与一个新模块一起存在，该模块将包含所有数据对象的类和功能：`data_object.py`。

还有两个与`BaseDataObject`结构和功能相关的故事，它们的需求将在开发类的过程中得到满足：

+   作为任何数据使用者，我需要能够创建、读取、更新和删除单个数据对象，以便对这些对象执行基本的数据管理任务。

+   作为任何数据使用者，我需要能够搜索特定的数据对象，以便我可以使用找到的结果项。

# BaseDataObject ABC

`BaseDataObject`的大部分属性都是布尔值，表示类的实例是否处于特定状态的标志。这些属性的实现都遵循一个简单的模式，这个模式已经在上一次迭代中的`BaseProduct`的`available`属性的定义中展示过。这个结构看起来像这样：

```py
###################################
# Property-getter methods         #
###################################

def _get_bool_prop(self) -> (bool,):
    return self._bool_prop

###################################
# Property-setter methods         #
###################################

def _set_bool_prop(self, value:(bool,int)):
    if value not in (True, False, 1, 0):
        raise ValueError(
            '%s.bool_prop expects either a boolean value '
            '(True|False) or a direct int-value equivalent '
            '(1|0), but was passed "%s" (%s)' % 
            (self.__class__.__name__, value, type(value).__name__)
        )
    if value:
        self._bool_prop = True
    else:
        self._bool_prop = False

###################################
# Property-deleter methods        #
###################################

def _del_bool_prop(self) -> None:
    self._bool_prop = False

###################################
# Instance property definitions   #
###################################

bool_prop = property(
    _get_bool_prop, _set_bool_prop, _del_bool_prop, 
    'Gets sets or deletes the flag that indicates whether '
    'the instance is in a particular state'
)
```

这些属性背后的删除方法，因为它们也用于在初始化期间设置实例的默认值，当删除属性时应该产生特定的值（调用这些方法）：

```py
###################################
# Property-deleter methods        #
###################################

def _del_is_active(self) -> None:
    self._is_active = True

def _del_is_deleted(self) -> None:
    self._is_deleted = False

def _del_is_dirty(self) -> None:
    self._is_dirty = False

def _del_is_new(self) -> None:
    self._is_new = True
```

除非被派生类或特定对象创建过程覆盖，从`BaseDataObject`派生的任何实例都将以这些值开始：

+   `is_active == True`

+   `is_deleted == False`

+   `is_dirty == False`

+   `is_new == True`

因此，新创建的实例将是活动的，未删除的，未修改的，新的，假设是创建新对象的过程通常是为了保存一个新的、活动的对象。如果在实例创建之间进行了任何状态更改，这些更改可能会在过程中将`is_dirty`标志设置为`True`，但`is_new`为`True`的事实意味着对象的记录需要在后端数据存储中被创建而不是更新。

与标准布尔属性结构的唯一重大偏差在于它们的定义过程中属性本身的文档：

```py
###################################
# Instance property definitions   #
###################################

is_active = property(
    _get_is_active, _set_is_active, _del_is_active, 
    'Gets sets or deletes the flag that indicates whether '
    'the instance is considered active/available'
)
is_deleted = property(
    _get_is_deleted, _set_is_deleted, _del_is_deleted, 
    'Gets sets or deletes the flag that indicates whether '
    'the instance is considered to be "deleted," and thus '
    'not generally available'
)
is_dirty = property(
    _get_is_dirty, _set_is_dirty, _del_is_dirty, 
    'Gets sets or deletes the flag that indicates whether '
    'the instance\'s state-data has been changed such that '
    'its record needs to be updated'
)
is_new = property(
    _get_is_new, _set_is_new, _del_is_new, 
    'Gets sets or deletes the flag that indicates whether '
    'the instance needs to have a state-data record created'
)
```

`BaseDataObject`的两个属性`created`和`modified`在类图中显示为`datetime`值-表示特定日期的特定时间的对象。`datetime`对象存储日期/时间的年、月、日、小时、分钟、秒和微秒，并提供了一些方便之处，例如，与严格作为时间戳数字值管理的等效值或日期/时间的字符串表示相比。其中一个方便之处是能够从字符串中解析值，允许属性背后的`_set_created`和`_set_modified`setter 方法接受字符串值而不是要求实际的`datetime`。同样，`datetime`提供了从时间戳创建`datetime`实例的能力-从公共起始日期/时间开始经过的秒数。为了完全支持所有这些参数类型，有必要定义一个通用的格式字符串，用于从字符串中解析`datetime`值并将其格式化为字符串。至少目前来看，最好将该值存储为`BaseDataObject`本身的类属性。这样，所有从中派生的类都将默认可用相同的值：

```py
class BaseDataObject(metaclass=abc.ABCMeta):
    """
Provides baseline functionality, interface requirements, and 
type-identity for objects that can persist their state-data in 
any of several back-end data-stores.
"""
    ###################################
    # Class attributes/constants      #
    ###################################

    _data_time_string = '%Y-%m-%d %H:%M:%S'
```

setter 方法比大多数方法要长一些，因为它们处理四种不同的可行值类型，尽管只需要两个子进程来覆盖所有这些变化。setter 过程首先通过类型检查提供的值并确认它是接受的类型之一：

```py
def _set_created(self, value:(datetime,str,float,int)):
    if type(value) not in (datetime,str,float,int):
        raise TypeError(
            '%s.created expects a datetime value, a numeric '
            'value (float or int) that can be converted to '
            'one, or a string value of the format "%s" that '
            'can be parsed into one, but was passed '
            '"%s" (%s)' % 
            (
                self.__class__.__name__, 
                self.__class__._data_time_string, value, 
                type(value).__name__, 
            )
        )
```

处理合法的两种数字类型都相当简单。如果检测到错误，我们应该提供更具体的消息，说明遇到的问题的性质：

```py
 if type(value) in (int, float):
   # - A numeric value was passed, so create a new 
   #   value from it
      try:
         value = datetime.fromtimestamp(value)
      except Exception as error:
         raise ValueError(
             '%s.created could not create a valid datetime '
             'object from the value provided, "%s" (%s) due '
             'to an error - %s: %s' % 
             (
                self.__class__.__name__, value, 
                type(value).__name__, 
                error.__class__.__name__, error
              )
           )
```

处理字符串值的子进程类似，除了调用`datetime.strptime`而不是`datetime.fromtimestamp，并使用`_data_time_string`类属性来定义有效的日期/时间字符串外：

```py
 elif type(value) == str:
    # - A string value was passed, so create a new value 
    #   by parsing it with the standard format
      try:
         value = datetime.strptime(
         value, self.__class__._data_time_string
         )
       except Exception as error:
          raise ValueError(
            '%s.created could not parse a valid datetime '
            'object using "%s" from the value provided, '
            '"%s" (%s) due to an error - %s: %s' % 
             (
                 self.__class__.__name__, 
                 self.__class__._data_time_string, 
                 value, type(value).__name__, 
                 error.__class__.__name__, error
              )
          )
```

如果原始值是`datetime`的实例，那么之前的任何一个子进程都不会被执行。如果它们中的任何一个被执行，那么原始值参数将被替换为`datetime`实例。无论哪种情况，该值都可以存储在底层属性中：

```py
# - If this point is reached without error,then we have a 
#   well-formed datetime object, so store it
self._created = value
```

对于`BaseDataObject`，`created`和`modified`应该始终有一个值，如果在需要时没有可用值（通常只有在保存数据对象的状态数据记录时才需要），则应该为当前值创建一个值，可以在 getter 方法中使用`datetime.now()`来实现：

```py
def _get_created(self) -> datetime:
    if self._created == None:
        self.created = datetime.now()
    return self._created
```

这反过来意味着删除方法应该将属性存储属性的值设置为`None`：

```py
def _del_created(self) -> None:
    self._created = None
```

相应的属性定义是标准的，只是`created`属性不允许直接删除；允许对象删除自己的创建日期/时间是没有意义的：

```py
###################################
# Instance property definitions   #
###################################

created = property(
    _get_created, _set_created, None, 
    'Gets, sets or deletes the date-time that the state-data '
    'record of the instance was created'
)

# ...

modified = property(
    _get_modified, _set_modified, _del_modified, 
    'Gets, sets or deletes the date-time that the state-data '
    'record of the instance was last modified'
)
```

`BaseDataObject`的最后一个属性可能是最关键的`oid`，它旨在唯一标识给定数据对象的状态数据记录。该属性被定义为**通用唯一标识符**（**UUID**）值，Python 在其`uuid`库中提供。使用 UUID 作为唯一标识符而不是一些更传统的方法，例如序列记录号，至少有两个优点：

+   **UUID 不依赖于数据库操作的成功才可用：**它们可以在代码中生成，而无需担心等待 SQL INSERT 完成，例如，或者在 NoSQL 数据存储中可能可用的任何相应机制。这意味着更少的数据库操作，可能也更简单，这样事情就更容易了。

+   **UUID 不容易预测：** UUID 是一系列由 32 个十六进制数字组成的字符串（其中有一些破折号将它们分成了本讨论不相关的部分），例如`ad6e3d5c-46cb-4547-9971-5627e6b3039a`。如果它们是由`uuid`库提供的几个标准函数之一生成的，它们的序列，即使不是真正随机的，也至少足够随机，使得对于恶意用户来说，找到给定值非常困难，有 3.4×10³⁴个可能的值要查找（每个十六进制数字有 16 个值，31 个数字因为其中一个被保留）。

UUID 的不可预测性在具有通过互联网访问的数据的应用程序中尤其有用。通过顺序编号识别记录，使恶意进程更容易命中某种 API 并按顺序检索每个记录，其他条件相同。

然而，还有一些注意事项：

+   并非所有的数据库引擎都会将 UUID 对象识别为可行的字段类型。这可以通过将实际的 UUID 值存储在数据对象中来管理，但是将这些值的字符串表示写入和从数据库中读取。

+   使用 UUID 作为唯一标识符的数据库操作可能会产生非常轻微的性能影响，特别是如果使用字符串表示而不是实际值。

+   它们固有的不可预测性可以使对数据的合法检查变得困难，如果没有其他可以用来查询的标识标准（针对其他标识标准）。

即使将优势放在一边，`BaseDataObject`将使用 UUID 作为对象标识（`oid`属性）的原因是一系列要求和预期的实现的结合：

+   **Artisan Application**将不会有一个真正的数据库支持它。它最终可能会成为一个简单的本地文档存储，因此为任何给定的数据对象生成唯一标识符必须是自包含的，不依赖于应用程序代码库之外的任何东西。

+   **相同的 oid 值需要在**Artisan Application**和**Artisan Gateway**服务之间传播。尝试在任意数量的工匠之间协调身份可能会很快导致身份冲突，而要减轻这种情况可能需要更多的工作（也许是更多），而不会对系统的要求或系统中的各种可安装组件的交互方式进行重大改变。两个随机生成的 UUID 之间发生碰撞的可能性非常低（对于所有实际目的来说几乎不可能），仅仅是因为涉及的可能值的数量。

`oid`属性的实现将遵循与基于`datetime`的属性类似的模式。获取方法将根据需要创建一个，设置方法将接受`UUID`对象或其字符串表示，并在内部创建实际的`UUID`对象，删除方法将将当前存储值设置为`None`：

```py
def _get_oid(self) -> UUID:
    if self._oid == None:
        self._oid = uuid4()
    return self._oid

# ...

def _set_oid(self, value:(UUID,str)):
    if type(value) not in (UUID,str):
        raise TypeError(
            '%s.oid expects a UUID value, or string '
            'representation of one, but was passed "%s" (%s)' % 
            (self.__class__.__name__, value, type(value).__name__)
        )
    if type(value) == str:
        try:
            value = UUID(value)
        except Exception as error:
            raise ValueError(
                '%s.oid could not create a valid UUID from '
                'the provided string "%s" because of an error '
                '%s: %s' % 
                (
                    self.__class__.__name__, value, 
                    error.__class__.__name__, error
                )
            )
    self._oid = value

# ...

def _del_oid(self) -> None:
    self._oid = None
```

`BaseDataObject`的大多数方法都是抽象的，包括所有的类方法。它们都没有任何可能在派生类中重用的具体实现，因此它们都是非常基本的定义。

```py
    ###################################
    # Abstract methods                #
    ###################################

    @abc.abstractmethod
    def _create(self) -> None:
        """
Creates a new state-data record for the instance in the back-end 
data-store
"""
        raise NotImplementedError(
            '%s has not implemented _create, as required by '
            'BaseDataObject' % (self.__class__.__name__)
        )

    @abc.abstractmethod
    def to_data_dict(self) -> (dict,):
        """
Returns a dictionary representation of the instance which can 
be used to generate data-store records, or for criteria-matching 
with the matches method.
"""
        raise NotImplementedError(
            '%s has not implemented _create, as required by '
            'BaseDataObject' % (self.__class__.__name__)
        )

    @abc.abstractmethod
    def _update(self) -> None:
        """
Updates an existing state-data record for the instance in the 
back-end data-store
"""
        raise NotImplementedError(
            '%s has not implemented _update, as required by '
            'BaseDataObject' % (self.__class__.__name__)
        )

    ###################################
    # Class methods                   #
    ###################################

    @abc.abstractclassmethod
    def delete(cls, *oids):
        """
Performs an ACTUAL record deletion from the back-end data-store 
of all records whose unique identifiers have been provided
"""
        raise NotImplementedError(
            '%s.delete (a class method) has not been implemented, '
            'as required by BaseDataObject' % (cls.__name__)
        )

    @abc.abstractclassmethod
    def from_data_dict(cls, data_dict:(dict,)):
        """
Creates and returns an instance of the class whose state-data has 
been populate with values from the provided data_dict
"""
        raise NotImplementedError(
            '%s.from_data_dict (a class method) has not been '
            'implemented, as required by BaseDataObject' % 
            (cls.__name__)
        )

    @abc.abstractclassmethod
    def get(cls, *oids, **criteria):
        """
Finds and returns all instances of the class from the back-end 
data-store whose oids are provided and/or that match the supplied 
criteria
"""
        raise NotImplementedError(
            '%s.get (a class method) has not been implemented, '
            'as required by BaseDataObject' % (cls.__name__)
        )
```

`to_data_dict`实例方法和`from_data_dict`类方法旨在提供机制，将实例的完整状态数据表示为`dict`，并从这样的`dict`表示中创建一个实例。`from_data_dict`方法应该促进记录检索和转换为实际的程序对象，尤其是在 Python 中的标准 RDBMS 连接库中，如果数据库中的字段名与类的属性名相同。在 NoSQL 数据存储中也应该有类似的用法。尽管`to_data_dict`方法在写入数据存储时可能有用，但它将需要根据标准匹配对象（我们马上会讨论的`matches`方法）。

PEP-249，当前的**Python 数据库 API 规范**，定义了符合 PEP 标准的库中的数据库查询的预期，至少会返回元组列表作为结果集。大多数成熟的数据库连接器库还提供了一种方便的机制，以返回一个`dict`记录值列表，其中每个`dict`将字段名映射为源记录的值。

`_create`和`_update`方法只是记录创建和记录更新过程的要求，并最终将被`save`方法调用。然而，单独的记录创建和记录更新过程的需求可能并不适用于所有数据存储引擎；一些，特别是在 NoSQL 领域，已经提供了写入记录的单一机制，并且根本不关心它是否已经存在。其他一些可能提供某种机制，允许首先尝试创建一个新记录，如果失败（因为找到了重复的键，表明记录已经存在），则更新现有记录。这个选项在`MySQL`和`MariaDB`数据库中可用，但可能也存在于其他地方。在任何这些情况下，覆盖保存方法以使用这些单一接触点的过程可能是一个更好的选择。

`delete`类方法是不言自明的，`sort`可能也是如此。

`get`方法需要一些检查，即使没有任何具体的实现。正如前面所述，它旨在成为从数据库检索状态数据并接受零到多个对象 ID（`*oids`参数列表）和过滤标准（在`**criteria`关键字参数中）的主要机制。整个`get`过程实际上的预期工作如下：

+   如果`oids`不为空：

1.  执行所需的任何低级查询或查找以找到与提供的`oids`之一匹配的对象，使用`from_data_dict`处理每个记录并生成对象列表

1.  如果`criteria`不为空，则将当前列表过滤为那些与标准的`matches`结果为`True`的对象

1.  返回结果列表

+   否则，如果`criteria`不为空：

+   执行所需的任何低级查询或查找以找到与提供的标准值之一匹配的对象，使用`from_data_dict`处理每个记录并生成对象列表

+   将当前列表过滤为那些与标准的`matches`结果为`True`的对象

+   返回结果列表

+   否则，执行所需的任何低级查询或查找以检索所有可用对象，再次使用`from_data_dict`处理每个记录，生成对象列表并简单地返回它们所有

综合考虑，`oids`和`criteria`值的组合将允许`get`类方法找到并返回执行以下操作的对象：

+   匹配一个或多个`oids`：`get(oid[, oid, …, oid])`

+   匹配一个或多个`oids`和一些`criteria`的集合：`get(oid[, oid, …, oid], key=value[, key=value, …, key=value])`

+   匹配一个或多个`criteria`键/值对，无论找到的项目的`oids`如何：`get(key=value[, key=value, …, key=value])`

+   这只是存在于后端数据存储中的：`get()`

这留下了`matches`和`save`方法，这两个方法是类中唯一的两个具体实现。`matches`的目标是提供一个实例级机制，用于比较实例与标准名称/值，这是`get`方法中使用和依赖的过程，以实际找到匹配项。它的实现比起一开始可能看起来要简单，但依赖于对`set`对象的操作，并且依赖于一个经常被忽视的 Python 内置函数（`all`），因此代码中的过程本身有很多注释：

```py
###################################
# Instance methods                #
###################################

def matches(self, **criteria) -> (bool,):
    """
Compares the supplied criteria with the state-data values of 
the instance, and returns True if all instance properties 
specified in the criteria exist and equal the values supplied.
"""
    # - First, if criteria is empty, we can save some time 
    #   and simply return True - If no criteria are specified, 
    #   then the object is considered to match the criteria.
    if not criteria:
        return True
    # - Next, we need to check to see if all the criteria 
    #   specified even exist in the instance:
    data_dict = self.to_data_dict()
    data_keys = set(check_dict.keys())
    criteria_keys = set(criteria.keys())
    # - If all criteria_keys exist in data_keys, then the 
    #   intersection of the two will equal criteria_keys. 
    #   If that's not the case, at least one key-value won't 
    #   match (because it doesn't exist), so return False
    if criteria_keys.intersection(data_keys) != criteria_keys:
        return False
    # - Next, we need to verify that values match for all 
    #   specified criteria
    return all(
        [
            (data_dict[key] == criteria[key]) 
            for key in criteria_keys
        ]
    )
```

`all`函数是一个很好的便利，如果它被传递的可迭代对象中的所有项都评估为`True`（或至少是真的，因此非空字符串、列表、元组和字典以及非零数字都被认为是`True`），它将返回`True`。如果可迭代对象中的任何成员不是`True`，则返回`False`，如果可迭代对象为空，则返回`True`。如果出现这些条件，`matches`的结果将是`False`：

+   `criteria`中的任何键都不存在于实例的`data_dict`中- 一个无法匹配的标准键，本质上

+   `criteria`中指定的任何值都不完全匹配实例的`data_dict`中的相应值

`save`方法非常简单。它只是根据实例的`is_new`或`is_dirty`标志属性的当前状态调用实例的`_create`或`_update`方法，然后在执行后重置这些标志，使对象变得干净并准备好接下来可能发生的任何事情：

```py
    def save(self):
        """
Saves the instance's state-data to the back-end data-store by 
creating it if the instance is new, or updating it if the 
instance is dirty
"""
        if self.is_new:
            self._create()
            self._set_is_new = False
            self._set_is_dirty = False
```

```py
        elif self.is_dirty:
            self._update()
            self._set_is_dirty = False
            self._set_is_new = False
```

`BaseDataObject`的初始化应该允许为其所有属性指定值，但不需要这些值：

```py
    def __init__(self, 
        oid:(UUID,str,None)=None, 
        created:(datetime,str,float,int,None)=None, 
        modified:(datetime,str,float,int,None)=None,
        is_active:(bool,int,None)=None, 
        is_deleted:(bool,int,None)=None,
        is_dirty:(bool,int,None)=None, 
        is_new:(bool,int,None)=None,
    ):
```

实际的初始化过程遵循了先前为所有参数建立的可选参数模式：对于每个参数，如果参数不是`None`，则调用相应的`_del_`方法，然后调用相应的`_set_`方法。让我们以`oid`参数为例：

```py
        # - Call parent initializers if needed
        # - Set default instance property-values using _del_... methods

        # ...

        self._del_oid()
        # - Set instance property-values from arguments using 
        #   _set_... methods
        if oid != None:
            self._set_oid(oid)

        # ...

        # - Perform any other initialization needed
```

这个初始化方法的签名变得非常长，有七个参数（忽略`self`，因为它总是存在的，并且总是第一个参数）。知道我们最终将定义具体类作为`BaseDataObject`和已定义的业务对象类的组合，这些具体类的`__init__`签名也可能会变得更长。然而，这正是`BaseDataObject`的初始化签名使所有参数都是可选的原因之一。与其中一个业务对象类结合使用时，例如`BaseArtisan`，其`__init__`签名如下：

```py
def __init__(self, 
    contact_name:str, contact_email:str, 
    address:Address, company_name:str=None, 
    website:(str,)=None, 
    *products
    ):
```

从这两者派生的`Artisan`的`__init__`签名，虽然很长...

```py
def __init__(self, 
    contact_name:str, contact_email:str, 
    address:Address, company_name:str=None, 
    website:(str,)=None, 
    oid:(UUID,str,None)=None, 
    created:(datetime,str,float,int,None)=None, 
    modified:(datetime,str,float,int,None)=None,
    is_active:(bool,int,None)=None, 
    is_deleted:(bool,int,None)=None,
    is_dirty:(bool,int,None)=None, 
    is_new:(bool,int,None)=None,
    *products
    ):
```

...只需要`BaseArtisan`需要的`contact_name`、`contact_email`和`address`参数，并允许所有参数都被传递，就像它们是关键字参数一样，像这样：

```py
artisan = Artisan(
    contact_name='John Doe', contact_email='john@doe.com', 
    address=my_address, oid='00000000-0000-0000-0000-000000000000', 
    created='2001-01-01 12:34:56', modified='2001-01-01 12:34:56'
)
```

允许将整个参数集定义为单个字典，并使用传递关键字参数集的相同语法将其整体传递给初始化程序：

```py
artisan_parameters = {
    'contact_name':'John Doe',
    'contact_email':'john@doe.com', 
    'address':my_address,
    'oid':'00000000-0000-0000-0000-000000000000', 
    'created':'2001-01-01 12:34:56', 
    'modified':'2001-01-01 12:34:56'
}
artisan = Artisan(**artisan_parameters)
```

在 Python 中，使用`**dictionary_name`将参数传递给字典的语法是一种常见的参数参数化形式，特别是在参数集合非常长的函数和方法中。这需要在开发过程的设计方面进行一些思考和纪律，并且需要对必需参数非常严格，但从长远来看，它比一开始看起来的更有帮助和更容易使用。

这个最后的结构将对从`BaseDataObject`派生的各种类的`from_data_dict`方法的实现至关重要- 在大多数情况下，它应该允许这些方法的实现不仅仅是这样：

```py
@classmethod
def from_data_dict(cls, data_dict):
    return cls(**data_dict)
```

# 单元测试`BaseDataObject`

就目前而言，对`BaseDataObject`进行单元测试将会是有趣的。测试`matches`方法，这是一个依赖于抽象方法(`to_data_dict`)的具体方法，而抽象方法又依赖于派生类的实际数据结构(`properties`)，在`BaseDataObject`的测试用例类的上下文中，要么是不可能的，要么是没有意义的：

+   为了测试`matches`，我们必须定义一个非抽象类，其中包含`to_data_dict`的具体实现，以及一些实际属性来生成该`dict`。

+   除非该派生类也恰好是系统中需要的实际类，否则它在最终系统代码中没有相关性，因此在那里的测试不能保证其他派生类在`matches`中不会出现问题

+   即使完全放置`matches`方法的测试，测试`save`也同样毫无意义，原因是它是一个依赖于在`BaseDataObject`级别上是抽象和未定义的方法的具体方法

当实现`BaseArtisan`时，我们定义了它的`add_product`和`remove_product`方法为抽象，但仍然在两者中编写了可用的具体实现代码，以便允许派生类简单地调用父类的实现。实际上，我们要求所有派生类都实现这两个方法，但提供了一个可以从派生类方法内部调用的实现。同样的方法应用到`BaseDataObject`中的`matches`和`save`方法，基本上会强制每个派生具体类的测试要求，同时允许在需要覆盖该实现之前或除非需要覆盖该实现之前使用单一实现。这可能感觉有点狡猾，但这种方法似乎没有任何不利之处：

+   以这种方式处理的方法仍然必须在派生类中实现。

+   如果由于某种原因需要覆盖它们，测试策略仍将要求对它们进行测试。

+   如果它们只是作为对父类方法的调用实现，它们将起作用，并且测试策略代码仍将识别它们为派生类的本地方法。我们的测试策略表示这些方法需要一个测试方法，这允许测试方法针对派生类的特定需求和功能执行。

然而，测试`save`不必采用这种方法。最终，就该方法而言，我们真正关心的是能够证明它调用了`_create`和`_update`抽象方法并重置了标志。如果可以在测试`BaseDataObject`的过程中测试和建立这个证明，我们就不必在其他地方进行测试，除非测试策略代码检测到该方法的覆盖。这将使我们能够避免在以后的所有最终具体类的所有测试用例中散布相同的测试代码，这是一件好事。

开始`data_objects`模块的单元测试非常简单：

1.  在项目的`test_hms_core`目录中创建一个`test_data_object.py`文件

1.  执行头部注释中指出的两个名称替换

1.  在同一目录的`__init__.py`中添加对它的引用

1.  运行测试代码并进行正常的迭代测试编写过程

在`__init__.py`中对新测试模块的引用遵循我们的单元测试模块模板中已经存在的结构，复制现有代码中以`# import child_module`开头的两行，然后取消注释并将`child_module`更改为新的测试模块：

```py
#######################################
# Child-module test-cases to execute  #
#######################################

import test_data_objects
LocalSuite.addTests(test_data_objects.LocalSuite._tests)

# import child_module
# LocalSuite.addTests(child_module.LocalSuite._tests)
```

这个添加将新的`test_data_objects`模块中的所有测试添加到顶层`__init__.py`测试模块中已经存在的测试中，从而使顶层测试套件能够执行子模块的测试：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/f9359000-284f-4821-a55a-54158255a251.png)

`test_data_objects.py`中的测试也可以独立执行，产生相同的失败，但不执行所有其他现有的测试：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/51ea1863-b0cd-436c-8809-be5d1e9e7e1e.png)

为`data_objects.py`编写单元测试的迭代过程与在上一次迭代中为基本业务对象编写测试的过程没有区别：运行测试模块，找到失败的测试，编写或修改该测试，并重复运行直到所有测试通过。由于`BaseDataObject`是一个抽象类，需要一个一次性的派生具体类来执行一些测试。除了针对`BaseDataObject`的`oid`，`created`和`modified`属性的面向值的测试之外，我们已经建立了覆盖其他所有内容的模式：

+   迭代好和坏值列表，这些值对于正在测试的成员是有意义的：

+   （尚不适用）标准可选文本行值

+   （尚不适用）标准必需文本行值

+   布尔（和数值等效）值

+   （尚不适用）非负数值

+   验证属性方法的关联——到目前为止在每种情况下都是获取方法，以及预期的设置方法和删除方法

+   验证获取方法检索其底层存储属性值

+   验证删除方法按预期重置其底层存储属性值

+   验证设置方法是否按预期执行类型检查和值检查

+   验证初始化方法（`__init__`）按预期调用所有删除和设置方法

这三个属性（`oid`，`created`和`modified`）除了没有已定义的测试模式之外，还共享另一个共同特征：如果请求属性并且属性尚未存在值（即，底层存储属性的值为`None`），则这三个属性都将创建一个值。这种行为需要一些额外的测试，超出了测试方法开始时确认获取方法读取存储属性的正常确认（使用`test_get_created`来说明）：

```py
def test_get_created(self):
    # Tests the _get_created method of the BaseDataObject class
    test_object = BaseDataObjectDerived()
    expected = 'expected value'
    test_object._created = expected
    actual = test_object.created
    self.assertEquals(actual, expected, 
        '_get_created was expected to return "%s" (%s), but '
        'returned "%s" (%s) instead' % 
        (
            expected, type(expected).__name__,
            actual, type(actual).__name__
        )
    )
```

到目前为止，测试方法与获取方法的测试非常典型，它设置一个任意值（因为正在测试的是获取方法是否检索到值，而不仅仅是这个），并验证结果是否与设置的值相同。然后，我们将存储属性的值强制设置为 None，并验证获取方法的结果是否是适当类型的对象——在这种情况下是`datetime`：

```py
    test_object._created = None
    self.assertEqual(type(test_object._get_created()), datetime, 
        'BaseDataObject._get_created should return a '
        'datetime value if it\'s retrieved from an instance '
        'with an underlying None value'
    )
```

属性设置方法（在这种情况下为`_set_created`）的测试方法必须考虑属性的所有不同类型变化，这些类型对于`_set_created`来说都是合法的——`datetime`，`int`，`float`和`str`值，然后根据输入类型设置预期值，然后调用被测试的方法并检查结果：

```py
def test_set_created(self):
    # Tests the _set_created method of the BaseDataObject class
    test_object = BaseDataObjectDerived()
    # - Test all "good" values
    for created in GoodDateTimes:
        if type(created) == datetime:
            expected = created
        elif type(created) in (int, float):
            expected = datetime.fromtimestamp(created)
        elif type(created) == str:
            expected = datetime.strptime(
                created, BaseDataObject._data_time_string
            )
        test_object._set_created(created)
        actual = test_object.created
        self.assertEqual(
            actual, expected, 
            'Setting created to "%s" (%s) should return '
            '"%s" (%s) through the property, but "%s" (%s) '
            'was returned instead' % 
            (
                created, type(created).__name__,
                expected, type(expected).__name__, 
                actual, type(actual).__name__, 
            )
        )
    # - Test all "bad" values
    for created in BadDateTimes:
        try:
            test_object._set_created(created)
            self.fail(
                'BaseDataObject objects should not accept "%s" '
                '(%s) as created values, but it was allowed to '
                'be set' % 
                (created, type(created).__name__)
            )
        except (TypeError, ValueError):
            pass
        except Exception as error:
            self.fail(
                'BaseDataObject objects should raise TypeError '
                'or ValueError if passed a created value of '
                '"%s" (%s), but %s was raised instead:\n'
                '    %s' % 
                (
                    created, type(created).__name__, 
                    error.__class__.__name__, error
                )
            )
```

删除方法的测试结构上与之前实施的测试过程相同，尽管：

```py
def test_del_created(self):
    # Tests the _del_created method of the BaseDataObject class
    test_object = BaseDataObjectDerived()
    test_object._created = 'unexpected value'
    test_object._del_created()
    self.assertEquals(
        test_object._created, None,
        'BaseDataObject._del_created should leave None in the '
        'underlying storage attribute, but "%s" (%s) was '
        'found instead' % 
        (
            test_object._created, 
            type(test_object._created).__name__
        )
    )
```

具有相同结构的`created`更改为`modified`，测试`modified`属性的基础方法。具有非常相似结构的`created`更改为`oid`和预期类型更改为`UUID`，作为`oid`属性的属性方法测试的起点。

然后，测试`_get_oid`看起来像这样：

```py
def test_get_oid(self):
    # Tests the _get_oid method of the BaseDataObject class
    test_object = BaseDataObjectDerived()
    expected = 'expected value'
    test_object._oid = expected
    actual = test_object.oid
    self.assertEquals(actual, expected, 
        '_get_oid was expected to return "%s" (%s), but '
        'returned "%s" (%s) instead' % 
        (
            expected, type(expected).__name__,
            actual, type(actual).__name__
        )
    )
    test_object._oid = None
    self.assertEqual(type(test_object.oid), UUID, 
        'BaseDataObject._get_oid should return a UUID value '
        'if it\'s retrieved from an instance with an '
        'underlying None value'
    )
```

测试`_set_oid`看起来像这样（请注意，类型更改还必须考虑不同的预期类型和值）：

```py
    def test_set_oid(self):
        # Tests the _set_oid method of the BaseDataObject class
        test_object = BaseDataObjectDerived()
        # - Test all "good" values
        for oid in GoodOIDs:
            if type(oid) == UUID:
                expected = oid
            elif type(oid) == str:
                expected = UUID(oid)
            test_object._set_oid(oid)
            actual = test_object.oid
            self.assertEqual(
                actual, expected, 
                'Setting oid to "%s" (%s) should return '
                '"%s" (%s) through the property, but "%s" '
                '(%s) was returned instead.' % 
                (
                    oid, type(oid).__name__, 
                    expected, type(expected).__name__, 
                    actual, type(actual).__name__, 
                )
            )
        # - Test all "bad" values
        for oid in BadOIDs:
            try:
                test_object._set_oid(oid)
                self.fail(
                    'BaseDatObject objects should not accept '
                    '"%s" (%s) as a valid oid, but it was '
                    'allowed to be set' % 
                    (oid, type(oid).__name__)
                )
            except (TypeError, ValueError):
                pass
            except Exception as error:
                self.fail(
                    'BaseDataObject objects should raise TypeError '
                    'or ValueError if passed a value of "%s" (%s) '
                    'as an oid, but %s was raised instead:\n'
                    '    %s' % 
                    (
                        oid, type(oid).__name__, 
                        error.__class__.__name__, error
                    )
                )
```

随着所有数据对象测试的完成（目前为止），现在是时候将生活在包头文件（`hms_core/__init__.py`）中的类定义移动到一个专门为它们的模块文件中：`business_objects.py`。虽然这纯粹是一个命名空间组织上的问题（因为类本身都没有被改变，只是它们在包中的位置发生了变化），但从长远来看，这是非常有意义的。移动完成后，包中的类有了逻辑分组：

![](https://github.com/OpenDocCN/freelearn-python-pt2-zh/raw/master/docs/hsn-swe-py/img/bfca67f7-3fc4-4445-be41-603b18e47305.png)

业务对象定义以及直接与这些类型相关的项目都将存在于`hms_core.business_objects`命名空间中，并且可以从那里导入，例如：

```py
from hms_core.business_objects import BaseArtisan
```

如果需要，`hms_core.business_objects`的所有成员都可以被导入：

```py
import hms_core.business_objects
```

同样，与仍在开发中的数据对象结构相关的功能都将存在于`hms_core.data_objects`命名空间中：

```py
from hms_core.data_objects import BaseDataObject
```

或者，模块的所有成员都可以通过以下方式导入：

```py
import hms_core.data_objects
```

基本数据对象结构准备就绪并经过测试，现在是时候开始实现一些具体的、数据持久化的业务对象，首先是 Artisan 应用程序中的业务对象。

# 摘要

`BaseDataObject`的实现提供了我们之前确定的所有常见数据访问需求的机制（所有 CRUD 操作）：

+   它允许派生数据对象一旦被实例化，就可以创建和更新它们的状态数据。

+   它提供了一个单一的机制，允许从数据存储中读取一个或多个数据对象，并且作为一个额外的奖励，还允许根据除了数据对象的`oid`之外的标准来检索对象。

+   它提供了一个用于删除对象数据的单一机制。

这些方法的实际实现是数据对象本身的责任，它们将直接与每种对象类型使用的存储机制相关联。

Artisan 应用程序的数据存储，读取和写入用户机器上的本地文件，在许多方面来说，是两种数据存储选项中较为简单的，因此我们将从这里开始。
