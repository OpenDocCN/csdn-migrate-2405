# Python 物联网入门指南（四）

> 原文：[`zh.annas-archive.org/md5/4fe4273add75ed738e70f3d05e428b06`](https://zh.annas-archive.org/md5/4fe4273add75ed738e70f3d05e428b06)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：构建光学字符识别的神经网络模块

本章介绍以下主题：

+   使用**光学字符识别**（**OCR**）系统

+   使用软件可视化光学字符

+   使用神经网络构建光学字符识别器

+   应用 OCR 系统

# 介绍

OCR 系统用于将文本图像转换为字母、单词和句子。它被广泛应用于各个领域，用于从图像中提取信息。它还用于签名识别、自动数据评估和安全系统。它在商业上用于验证数据记录、护照文件、发票、银行对账单、电脑收据、名片、静态数据的打印输出等。OCR 是模式识别、人工智能和计算机视觉的研究领域。

# 可视化光学字符

光学字符可视化是一种常见的数字化印刷文本的方法，使得这些文本可以进行电子编辑、搜索、紧凑存储和在线显示。目前，它们广泛应用于认知计算、机器翻译、文本转语音转换、文本挖掘等领域。

# 如何做…

1.  导入以下软件包：

```py
import os 
import sys 
import cv2 
import numpy as np 
```

1.  加载输入数据：

```py
in_file = 'words.data'  
```

1.  定义可视化参数：

```py
scale_factor = 10 
s_index = 6 
e_index = -1 
h, w = 16, 8 
```

1.  循环直到遇到*Esc*键：

```py
with open(in_file, 'r') as f: 
  for line in f.readlines(): 
    information = np.array([255*float(x) for x in line.split('t')[s_index:e_index]]) 
    image = np.reshape(information, (h,w)) 
    image_scaled = cv2.resize(image, None, fx=scale_factor, fy=scale_factor) 
    cv2.imshow('Image', image_scaled) 
    a = cv2.waitKey() 
    if a == 10: 
      break 
```

1.  键入`python visualize_character.py`来执行代码：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ca2ad22d-0452-4ddb-923a-04c264e6bf16.png)

1.  执行`visualize_character.py`时得到的结果如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/55eb558d-22dc-4190-9199-38d47ff974c6.png)

# 使用神经网络构建光学字符识别器

本节描述基于神经网络的光学字符识别方案。

# 如何做…

1.  导入以下软件包：

```py
import numpy as np 
import neurolab as nl 
```

1.  读取输入文件：

```py
in_file = 'words.data'
```

1.  考虑 20 个数据点来构建基于神经网络的系统：

```py
# Number of datapoints to load from the input file 
num_of_datapoints = 20
```

1.  表示不同的字符：

```py
original_labels = 'omandig' 
# Number of distinct characters 
num_of_charect = len(original_labels) 
```

1.  使用 90%的数据来训练神经网络，剩下的 10%用于测试：

```py
train_param = int(0.9 * num_of_datapoints) 
test_param = num_of_datapoints - train_param 
```

1.  定义数据集提取参数：

```py
s_index = 6 
e_index = -1 
```

1.  构建数据集：

```py
information = [] 
labels = [] 
with open(in_file, 'r') as f: 
  for line in f.readlines(): 
    # Split the line tabwise 
    list_of_values = line.split('t') 
```

1.  实施错误检查以确认字符：

```py
    if list_of_values[1] not in original_labels: 
      continue 
```

1.  提取标签并将其附加到主列表：

```py
    label = np.zeros((num_of_charect , 1)) 
    label[original_labels.index(list_of_values[1])] = 1 
    labels.append(label)
```

1.  提取字符并将其添加到主列表：

```py
    extract_char = np.array([float(x) for x in     list_of_values[s_index:e_index]]) 
    information.append(extract_char)
```

1.  一旦加载所需数据集，退出循环：

```py
    if len(information) >= num_of_datapoints: 
      break 
```

1.  将信息和标签转换为 NumPy 数组：

```py
information = np.array(information) 
labels = np.array(labels).reshape(num_of_datapoints, num_of_charect) 
```

1.  提取维度的数量：

```py
num_dimension = len(information[0]) 
```

1.  创建和训练神经网络：

```py
neural_net = nl.net.newff([[0, 1] for _ in range(len(information[0]))], [128, 16, num_of_charect]) 
neural_net.trainf = nl.train.train_gd 
error = neural_net.train(information[:train_param,:], labels[:train_param,:], epochs=10000, show=100, goal=0.01) 
```

1.  预测测试输入的输出：

```py
p_output = neural_net.sim(information[train_param:, :]) 
print "nTesting on unknown data:" 
  for i in range(test_param): 
    print "nOriginal:", original_labels[np.argmax(labels[i])] 
    print "Predicted:", original_labels[np.argmax(p_output[i])]
```

1.  执行`optical_character_recognition.py`时得到的结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/9c777c60-2961-4856-b0b3-6966565f610f.png)

# 工作原理…

构建了一个神经网络支持的光学字符识别系统，用于从图像中提取文本。该过程涉及训练神经网络系统，测试和验证使用字符数据集。

读者可以参考文章*基于神经网络的光学字符识别系统*，了解 OCR 背后的基本原理：[`ieeexplore.ieee.org/document/6419976/`](http://ieeexplore.ieee.org/document/6419976/)

# 另请参阅

请参考以下内容：

+   [`searchcontentmanagement.techtarget.com/definition/OCR-optical-character-recognition`](https://searchcontentmanagement.techtarget.com/definition/OCR-optical-character-recognition)

+   [`thecodpast.org/2015/09/top-5-ocr-apps/`](https://thecodpast.org/2015/09/top-5-ocr-apps/)

+   [`convertio.co/ocr/`](https://convertio.co/ocr/)

# OCR 系统的应用

OCR 系统广泛用于从图像中提取/转换文本（字母和数字）。OCR 系统被广泛用于验证商业文件、自动车牌识别以及从文件中提取关键字符。它还用于使打印文件的电子图像可搜索，并为盲人和视障用户构建辅助技术。


# 第十章：算术运算、循环和闪烁灯

现在让我们来看看这一章，我们将回顾 Python 中的算术运算和变量。我们还将讨论 Python 中的字符串和接受用户输入。您将了解树莓派的 GPIO 及其特性，并使用 Python 编写代码，使 LED 使用树莓派 Zero 的 GPIO 闪烁。我们还将讨论控制树莓派的 GPIO 的实际应用。

在本章中，我们将涵盖以下主题：

+   Python 中的算术运算

+   Python 中的位运算符

+   Python 中的逻辑运算符

+   Python 中的数据类型和变量

+   Python 中的循环

+   树莓派 Zero 的 GPIO 接口。

# 本章所需的硬件

在本章中，我们将讨论一些例子，我们将控制树莓派的 GPIO。我们需要一个面包板，跳线，LED 和一些电阻（330 或 470 欧姆）来讨论这些例子。

我们还需要一些可选的硬件，我们将在本章的最后一节中讨论。

# 算术运算

Python 可以执行所有标准的算术运算。让我们启动 Python 解释器，了解更多：

+   **加法**：可以使用`+`操作符对两个数字进行相加。结果将打印在屏幕上。使用 Python 解释器尝试以下示例：

```py
       >>>123+456 
       579
```

+   **减法**：可以使用`-`操作符对两个数字进行相加：

```py
       >>>456-123 
       333 
       >>>123-456 
       -333
```

+   **乘法**：可以将两个数字相乘如下：

```py
       >>>123*456 
       56088
```

+   **除法**：可以将两个数字相除如下：

```py
       >>>456/22 
 20.727272727272727 
       >>>456/2.0 
       228.0 
       >>>int(456/228) 
       2
```

+   **模运算符**：在 Python 中，模运算符（`%`）返回除法运算的余数：

```py
       >>>4%2 
       0 
       >>>3%2 
       1
```

+   **floor 运算符**（`//`）是模运算符的相反。此运算符返回商的地板，即整数结果，并丢弃小数部分：

```py
       >>>9//7 
       1 
       >>>7//3 
       2 
       >>>79//25 
       3
```

# Python 中的位运算符

在 Python 中，可以对数字执行位级操作。这在从某些传感器解析信息时特别有帮助。例如，一些传感器以一定频率共享它们的输出。当新的数据点可用时，设置某个特定的位，表示数据可用。可以使用位运算符来检查在从传感器检索数据点之前是否设置了特定的位。

如果您对位运算符有兴趣，我们建议从[`en.wikipedia.org/wiki/Bitwise_operation`](https://en.wikipedia.org/wiki/Bitwise_operation)开始。

考虑数字`3`和`2`，它们的二进制等价物分别是`011`和`010`。让我们看看执行每个数字位操作的不同运算符：

+   **AND 运算符**：AND 运算符用于对两个数字执行 AND 操作。使用 Python 解释器尝试一下：

```py
       >>>3&2 
       2
```

这相当于以下 AND 操作：

```py
   0 1 1 &
   0 1 0
   --------
   0 1 0 (the binary representation of the number 2)
```

+   **OR 运算符**：OR 运算符用于对两个数字执行 OR 操作，如下所示：

```py
       >>>3|2 
       3
```

这相当于以下 OR 操作：

```py
   0 1 1 OR
   0 1 0
   --------
   0 1 1 (the binary representation of the number 3)
```

+   **NOT 运算符**：NOT 运算符翻转数字的位。看下面的例子：

```py
       >>>~1 
       -2
```

在前面的例子中，位被翻转，即`1`变为`0`，`0`变为`1`。因此，`1`的二进制表示是`0001`，当执行按位 NOT 操作时，结果是`1110`。解释器返回结果为`-2`，因为负数存储为它们的*二进制补码*。`1`的二进制补码是`-2`。

为了更好地理解二进制补码等内容，我们建议阅读以下文章，[`wiki.python.org/moin/BitwiseOperators`](https://wiki.python.org/moin/BitwiseOperators)和[`en.wikipedia.org/wiki/Two's_complement`](https://en.wikipedia.org/wiki/Two's_complement)。

+   **XOR 运算符**：可以执行异或操作如下：

```py
       >>>3² 
       1
```

+   **左移运算符**：左移运算符可以将给定值的位向左移动所需的位数。例如，将数字`3`向左移动一位会得到数字`6`。数字`3`的二进制表示是`0011`。将位左移一位将得到`0110`，即数字`6`：

```py
       >>>3<<1 
       6
```

+   **右移运算符**：右移运算符可以将给定值的位向右移动所需的位数。启动命令行解释器并自己尝试一下。当你将数字`6`向右移动一个位置时会发生什么？

# 逻辑运算符

**逻辑运算符**用于检查不同的条件并相应地执行代码。例如，检测与树莓派 GPIO 接口连接的按钮是否被按下，并执行特定任务作为结果。让我们讨论基本的逻辑运算符：

+   **等于**：等于（`==`）运算符用于比较两个值是否相等：

```py
       >>>3==3 
       True 
       >>>3==2 
       False
```

+   **不等于**：不等于（`!=`）运算符比较两个值，如果它们不相等，则返回`True`：

```py
       >>>3!=2 
       True 
       >>>2!=2 
       False
```

+   **大于**：此运算符（`>`）如果一个值大于另一个值，则返回`True`：

```py
       >>>3>2 
       True 
       >>>2>3 
       False
```

+   **小于**：此运算符比较两个值，如果一个值小于另一个值，则返回`True`：

```py
       >>>2<3 
       True 
       >>>3<2 
       False
```

+   **大于或等于（>=）**：此运算符比较两个值，如果一个值大于或等于另一个值，则返回`True`：

```py
       >>>4>=3 
       True 
       >>>3>=3 
       True 
       >>>2>=3 
       False
```

+   **小于或等于（<=）**：此运算符比较两个值，如果一个值小于或等于另一个值，则返回`True`：

```py
       >>>2<=2 
       True 
       >>>2<=3 
       True 
       >>>3<=2 
       False
```

# Python 中的数据类型和变量

在 Python 中，**变量**用于在程序执行期间存储结果或值在计算机的内存中。变量使得可以轻松访问计算机内存中的特定位置，并且使得编写用户可读的代码成为可能。

例如，让我们考虑这样一个情景，一个人想要从办公室或大学获得一张新的身份证。这个人将被要求填写一个包括他们的姓名、部门和紧急联系信息在内的相关信息的申请表。表格将有必需的字段。这将使办公室经理在创建新的身份证时参考表格。

同样，变量通过提供存储信息在计算机内存中的方式来简化代码开发。如果必须考虑存储器映射，编写代码将会非常困难。例如，使用名为 name 的变量比使用特定的内存地址如`0x3745092`更容易。

Python 中有不同种类的数据类型。让我们来回顾一下不同的数据类型：

+   一般来说，姓名、街道地址等都是由字母数字字符组成。在 Python 中，它们被存储为*字符串*。Python 中的字符串表示和存储在变量中如下：

```py
       >>>name = 'John Smith' 
       >>>address = '123 Main Street'
```

+   在 Python 中，*数字*可以存储如下：

```py
       >>>age = 29 
       >>>employee_id = 123456 
       >>>height = 179.5 
       >>>zip_code = 94560
```

+   Python 还可以存储*布尔*变量。例如，一个人的器官捐赠者状态可以是`True`或`False`：

```py
       >>>organ_donor = True
```

+   可以同时*赋值*多个变量的值：

```py
       >>>a = c= 1 
       >>>b = a
```

+   可以*删除*变量如下：

```py
       >>>del(a)
```

Python 中还有其他数据类型，包括列表、元组和字典。我们将在下一章中详细讨论这一点。

# 从用户读取输入

现在，我们将讨论一个简单的程序，要求用户输入两个数字，程序返回两个数字的和。现在，我们假设用户总是提供有效的输入。

在 Python 中，用户可以使用`input()`函数（[`docs.python.org/3/library/functions.html#input`](https://docs.python.org/3/library/functions.html#input)）提供输入给 Python 程序：

```py
    var = input("Enter the first number: ")
```

在前面的例子中，我们使用`input()`函数来获取用户输入的数字。`input()`函数将提示`("Enter the first number: ")`作为参数，并返回用户输入。在这个例子中，用户输入存储在变量`var`中。为了添加两个数字，我们使用`input()`函数请求用户提供两个数字作为输入：

```py
    var1 = input("Enter the first number: ") 
    var2 = input("Enter the second number: ") 
    total = int(var1) + int(var2) 
    print("The sum is %d" % total)
```

我们正在使用`input()`函数来获取两个数字的用户输入。在这种情况下，用户数字分别存储在`var1`和`var2`中。

用户输入是一个字符串。我们需要在将它们相加之前将它们转换为整数。我们可以使用`int()`函数将字符串转换为整数（[`docs.python.org/3/library/functions.html#int`](https://docs.python.org/3/library/functions.html#int)）。

`int()`函数将字符串作为参数，并返回转换后的整数。转换后的整数相加并存储在变量`total`中。前面的例子可与本章一起下载，名称为`input_function.py`。

如果用户输入无效，`int()`函数将抛出异常，表示发生了错误。因此，在本例中，我们假设用户输入是有效的。在后面的章节中，我们将讨论由无效输入引起的异常捕获。

以下快照显示了程序输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/257520f6-52ab-41e9-9660-8f6d16cec262.png)input_function.py 的输出

# 格式化的字符串输出

让我们重新讨论前一节中讨论的例子。我们打印了结果如下：

```py
    print("The sum is %d" % total)
```

在 Python 中，可以格式化字符串以显示结果。在前面的例子中，我们使用`%d`来指示它是整数变量的占位符。这使得可以打印带有整数的字符串。除了作为`print()`函数的参数传递的字符串外，还传递需要打印的变量作为参数。在前面的例子中，变量是使用`%`运算符传递的。还可以传递多个变量：

```py
    print("The sum of %d and %d is %d" % (var1, var2, total))
```

也可以按以下方式格式化字符串：

```py
    print("The sum of 3 and 2 is {total}".format(total=5))
```

# str.format()方法

`format()`方法使用大括号（`{}`）作为占位符来格式化字符串。在前面的例子中，我们使用`total`作为占位符，并使用字符串类的格式化方法填充每个占位符。

# 读者的另一个练习

使用`format()`方法格式化一个带有多个变量的字符串。

让我们构建一个从用户那里获取输入并在屏幕上打印的控制台/命令行应用程序。让我们创建一个名为`input_test.py`的新文件（可与本章的下载一起使用），获取一些用户输入并在屏幕上打印它们：

```py
    name = input("What is your name? ") 
    address = input("What is your address? ") 
    age = input("How old are you? ") 

    print("My name is " + name) 
    print("I am " + age + " years old") 
    print("My address is " + address)
```

执行程序并查看发生了什么：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/7adf2c27-707e-4c25-9fba-77779ac12dc4.png)input_test.py 的输出

前面的例子可与本章一起下载，名称为`input_test.py`。

# 读者的另一个练习

使用字符串格式化技术重复前面的例子。

# 连接字符串

在前面的例子中，我们将用户输入与另一个字符串组合打印出来。例如，我们获取用户输入`name`并打印句子`My name is Sai`。将一个字符串附加到另一个字符串的过程称为**连接**。

在 Python 中，可以通过在两个字符串之间添加`+`来连接字符串：

```py
    name = input("What is your name? ") 
    print("My name is " + name)
```

可以连接两个字符串，但不能连接整数。让我们考虑以下例子：

```py
    id = 5 
    print("My id is " + id)
```

它将抛出一个错误，暗示整数和字符串不能结合使用：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/77a4564b-3376-4e22-aa7d-3ec13fb3ae7d.png)一个异常

可以将整数转换为字符串并将其连接到另一个字符串：

```py
    print("My id is " + str(id))
```

这将产生以下结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/58856394-d5d4-4de2-bf76-2ecba2e749d5.png)

# Python 中的循环

有时，特定任务必须重复多次。在这种情况下，我们可以使用**循环**。在 Python 中，有两种类型的循环，即`for`循环和`while`循环。让我们通过具体的例子来回顾它们。

# 一个 for 循环

在 Python 中，`for`循环用于执行*n*次任务。`for`循环会迭代序列的每个元素。这个序列可以是字典、列表或任何其他迭代器。例如，让我们讨论一个执行循环的例子：

```py
    for i in range(0, 10): 
       print("Loop execution no: ", i)
```

在前面的例子中，`print`语句被执行了 10 次：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/41fa73db-9be7-4df4-9435-1c1f94d118e8.png)

为了执行`print`任务 10 次，使用了`range()`函数（[`docs.python.org/2/library/functions.html#range`](https://docs.python.org/2/library/functions.html#range)）。`range`函数会为传递给函数的起始和停止值生成一个数字列表。在这种情况下，`0`和`10`被作为参数传递给`range()`函数。这将返回一个包含从`0`到`9`的数字的列表。`for`循环会按照步长为 1 的步骤迭代每个元素的代码块。`range`函数也可以按照步长为 2 生成一个数字列表。这是通过将起始值、停止值和步长值作为参数传递给`range()`函数来实现的：

```py
    for i in range(0, 20, 2): 
       print("Loop execution no: ", i)
```

在这个例子中，`0`是起始值，`20`是停止值，`2`是步长值。这会生成一个 10 个数字的列表，步长为 2：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/78b7d6da-e498-4a0c-a913-847895e24fef.png)

`range`函数可以用来从给定的数字倒数。比如，我们想要从`10`倒数到`1`：

```py
    for i in range(10, 0, -1): 
       print("Count down no: ", i)
```

输出将会是这样的：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/1f72610e-b6f2-4180-b0d6-ffab6e2316e9.png)

`range`函数的一般语法是`range(start, stop, step_count)`。它会生成一个从`start`到`n-1`的数字序列，其中`n`是停止值。

# 缩进

注意`for`循环块中的*缩进*：

```py
    for i in range(10, 1, -1): 
       print("Count down no: ", i)
```

Python 执行`for`循环语句下的代码块。这是 Python 编程语言的一个特性。只要缩进级别相同，它就会执行`for`循环下的任何代码块：

```py
    for i in range(0,10): 
       #start of block 
       print("Hello") 
       #end of block
```

缩进有以下两个用途：

+   它使代码可读性更强

+   它帮助我们识别要在循环中执行的代码块

在 Python 中，要注意缩进，因为它直接影响代码的执行方式。

# 嵌套循环

在 Python 中，可以实现*循环内的循环*。例如，假设我们需要打印地图的`x`和`y`坐标。我们可以使用嵌套循环来实现这个：

```py
for x in range(0,3): 
   for y in range(0,3): 
         print(x,y)
```

预期输出是：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/19048a40-2d7b-4ed3-886b-87572e8d01bc.png)

在嵌套循环中要小心代码缩进，因为它可能会引发错误。考虑以下例子：

```py
for x in range(0,10): 
   for y in range(0,10): 
   print(x,y)
```

Python 解释器会抛出以下错误：

```py
    SyntaxError: expected an indented block
```

这在以下截图中可见：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/da5977ea-4fc5-4952-b462-2b596dc2ba32.png)

因此，在 Python 中要注意缩进是很重要的（特别是嵌套循环），以成功执行代码。IDLE 的文本编辑器会在你编写代码时自动缩进。这应该有助于理解 Python 中的缩进。

# 一个 while 循环

当特定任务需要执行直到满足特定条件时，会使用`while`循环。`while`循环通常用于执行无限循环中的代码。让我们看一个具体的例子，我们想要打印`i`的值从`0`到`9`：

```py
i=0 
while i<10: 
  print("The value of i is ",i) 
  i+=1
```

在`while`循环内，我们每次迭代都会将`i`增加`1`。`i`的值增加如下：

```py
i += 1
```

这等同于`i = i+1`。

这个例子会执行代码，直到`i`的值小于 10。也可以执行无限循环中的某些操作：

```py
i=0 
while True: 
  print("The value of i is ",i) 
  i+=1
```

可以通过在键盘上按下*Ctrl* + *C*来停止这个无限循环的执行。

也可以有嵌套的`while`循环：

```py
i=0 
j=0 
while i<10: 
  while j<10: 
    print("The value of i,j is ",i,",",j) 
    i+=1 
    j+=1
```

与`for`循环类似，`while`循环也依赖于缩进的代码块来执行一段代码。

Python 可以打印字符串和整数的组合，只要它们作为`print`函数的参数呈现，并用逗号分隔。在前面提到的示例中，`i，j 的值是`，`i`是`print`函数的参数。您将在下一章中了解更多关于函数和参数的内容。此功能使得格式化输出字符串以满足我们的需求成为可能。

# 树莓派的 GPIO

树莓派 Zero 配备了一个 40 针的 GPIO 引脚标头。在这 40 个引脚中，我们可以使用 26 个引脚来读取输入（来自传感器）或控制输出。其他引脚是电源引脚（**5V**，**3.3V**和**Ground**引脚）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/5412df99-2745-4e1b-8af8-6508c1d944b1.png)树莓派 Zero GPIO 映射（来源：https://www.raspberrypi.org/documentation/usage/gpio-plus-and-raspi2/README.md）

我们可以使用树莓派的 GPIO 最多 26 个引脚来接口设备并控制它们。但是，有一些引脚具有替代功能。

较早的图像显示了树莓派的 GPIO 引脚的映射。圆圈中的数字对应于树莓派处理器上的引脚编号。例如，GPIO 引脚**2**（底部行左侧的第二个引脚）对应于树莓派处理器上的 GPIO 引脚**2**，而不是 GPIO 引脚标头上的物理引脚位置。

一开始，尝试理解引脚映射可能会令人困惑。保留 GPIO 引脚手册（可与本章一起下载）以供参考。需要一些时间来适应树莓派 Zero 的 GPIO 引脚映射。

树莓派 Zero 的 GPIO 引脚是 3.3V 兼容的，也就是说，如果将大于 3.3V 的电压应用到引脚上，可能会永久损坏引脚。当设置为*高*时，引脚被设置为 3.3V，当引脚被设置为低时，电压为 0V。

# 闪烁灯

让我们讨论一个例子，我们将使用树莓派 Zero 的 GPIO。我们将把 LED 接口到树莓派 Zero，并使其以 1 秒的间隔闪烁*开*和*关*。

让我们接线树莓派 Zero 开始：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/40d426e0-5599-48c5-afe6-4b4d4ee64ff6.png)使用 Fritzing 生成的 Blinky 原理图

在前面的原理图中，GPIO 引脚 2 连接到 LED 的阳极（最长的腿）。LED 的阴极连接到树莓派 Zero 的地引脚。还使用了 330 欧姆的限流电阻来限制电流的流动。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/)）。**Raspbian Jessie**操作系统映像带有预安装的库。这是一个非常简单易用的库，对于初学者来说是最好的选择。它支持一套标准设备，帮助我们轻松入门。

例如，为了接口 LED，我们需要从`gpiozero`库中导入`LED`类：

```py
from gpiozero import LED
```

我们将在 1 秒的间隔内打开和关闭 LED。为了做到这一点，我们将*导入*`time`库。在 Python 中，我们需要导入一个库来使用它。由于我们将 LED 接口到 GPIO 引脚 2，让我们在我们的代码中提到这一点：

```py
import time 

led = LED(2)
```

我们刚刚创建了一个名为`led`的变量，并定义我们将在`LED`类中使用 GPIO 引脚 2。让我们使用`while`循环来打开和关闭 LED，间隔为 1 秒。

`gpiozero`库的 LED 类带有名为`on()`和`off()`的函数，分别将 GPIO 引脚 2 设置为高电平和低电平：

```py
while True: 
    led.on() 
    time.sleep(1) 
    led.off() 
    time.sleep(1)
```

在 Python 的时间库中，有一个`sleep`函数，可以在打开/关闭 LED 之间引入 1 秒的延迟。这在一个无限循环中执行！我们刚刚使用树莓派 Zero 构建了一个实际的例子。

将所有代码放在名为`blinky.py`的文件中（可与本书一起下载），从命令行终端运行代码（或者，您也可以使用 IDLE3）：

```py
    python3 blinky.py
```

# GPIO 控制的应用

现在我们已经实施了我们的第一个示例，让我们讨论一些能够控制 GPIO 的可能应用。我们可以使用树莓派的 GPIO 来控制家中的灯光。我们将使用相同的示例来控制台灯！

有一个名为**PowerSwitch Tail II**的产品（[`www.powerswitchtail.com/Pages/default.aspx`](http://www.powerswitchtail.com/Pages/default.aspx)），可以将交流家电（如台灯）与树莓派连接起来。PowerSwitch Tail 配有控制引脚（可以接收 3.3V 高电平信号），可用于打开/关闭灯。开关配有必要的电路/保护，可直接与树莓派 Zero 接口：

树莓派 Zero 与 PowerSwitch Tail II 接口

让我们从上一节中使用相同的示例，将 GPIO 引脚 2 连接到 PowerSwitch Tail 的**+in**引脚。让我们将树莓派 Zero 的 GPIO 引脚的地线连接到 PowerSwitch Tail 的**-in**引脚。PowerSwitch Tail 应连接到交流电源。灯应连接到开关的交流输出。如果我们使用相同的代码并将灯连接到 PowerSwitch Tail，我们应该能够以 1 秒的间隔打开/关闭。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/d0909ca2-bc35-4e48-b8a4-70ac53ca9b2f.png)连接到树莓派 Zero 的 PowerSwitch Tail II 使用 LED 闪烁代码进行家电控制只是一个例子。不建议在如此短的时间间隔内打开/关闭台灯。

# 总结

在本章中，我们回顾了 Python 中的整数、布尔和字符串数据类型，以及算术运算和逻辑运算符。我们还讨论了接受用户输入和循环。我们介绍了树莓派 Zero 的 GPIO，并讨论了 LED 闪烁示例。我们使用相同的示例来控制台灯！

您听说过名为*Slack*的聊天应用程序吗？您是否尝试过在工作时从笔记本电脑控制家里的台灯？如果这引起了您的兴趣，请在接下来的几章中与我们一起工作。


# 第十一章：条件语句、函数和列表

在本章中，我们将在前一章学到的基础上进行扩展。您将学习有关条件语句以及如何使用逻辑运算符来检查条件的使用。接下来，您将学习如何在 Python 中编写简单的函数，并讨论如何使用触摸开关（瞬时按键）将输入接口到树莓派的 GPIO 引脚。我们还将讨论使用树莓派 Zero 进行电机控制（这是最终项目的预演），并使用开关输入来控制电机。让我们开始吧！

在本章中，我们将讨论以下主题：

+   Python 中的条件语句

+   使用条件输入根据 GPIO 引脚状态采取行动

+   使用条件语句跳出循环

+   Python 中的函数

+   GPIO 回调函数

+   Python 中的电机控制

# 条件语句

在 Python 中，条件语句用于确定特定条件是否满足，通过测试条件是`true`还是`false`。条件语句用于确定程序的执行方式。例如，条件语句可以用于确定是否是开灯的时间。语法如下：

```py
if condition_is_true:

  do_something()
```

通常使用逻辑运算符来测试条件，并执行缩进块下的任务集。让我们考虑一个例子，`check_address_if_statement.py`（可在本章下载）中，程序需要使用`yes`或`no`问题来验证用户输入：

```py
check_address = input("Is your address correct(yes/no)? ") 
if check_address == "yes": 
  print("Thanks. Your address has been saved") 
if check_address == "no": 
  del(address) 
  print("Your address has been deleted. Try again")
```

在这个例子中，程序期望输入`yes`或`no`。如果用户提供了输入`yes`，条件`if check_address == "yes"`为`true`，则在屏幕上打印消息`Your address has been saved`。

同样，如果用户输入是`no`，程序将执行在逻辑测试条件`if check_address == "no"`下的缩进代码块，并删除变量`address`。

# if-else 语句

在前面的例子中，我们使用`if`语句测试每个条件。在 Python 中，还有一种名为`if-else`语句的替代选项。`if-else`语句使得在主条件不为`true`时测试替代条件成为可能：

```py
check_address = input("Is your address correct(yes/no)? ") 
if check_address == "yes": 
  print("Thanks. Your address has been saved") 
else: 
  del(address) 
  print("Your address has been deleted. Try again")
```

在这个例子中，如果用户输入是`yes`，则在`if`下的缩进代码块将被执行。否则，将执行`else`下的代码块。

# if-elif-else 语句

在前面的例子中，对于除`yes`之外的任何用户输入，程序执行`else`块下的任何代码。也就是说，如果用户按下回车键而没有提供任何输入，或者提供了`no`而不是`no`，则`if-elif-else`语句的工作如下：

```py
check_address = input("Is your address correct(yes/no)? ") 
if check_address == "yes": 
  print("Thanks. Your address has been saved") 
elif check_address == "no": 
  del(address) 
  print("Your address has been deleted. Try again") 
else: 
  print("Invalid input. Try again")
```

如果用户输入是`yes`，则在`if`语句下的缩进代码块将被执行。如果用户输入是`no`，则在`elif`（*else-if*）下的缩进代码块将被执行。如果用户输入是其他内容，则程序打印消息：`Invalid input. Try again`。

重要的是要注意，代码块的缩进决定了在满足特定条件时需要执行的代码块。我们建议修改条件语句块的缩进，并找出程序执行的结果。这将有助于理解 Python 中缩进的重要性。

到目前为止，我们讨论的三个例子中，可以注意到`if`语句不需要由`else`语句补充。`else`和`elif`语句需要有一个前置的`if`语句，否则程序执行将导致错误。

# 跳出循环

条件语句可以用于跳出循环执行（`for`循环和`while`循环）。当满足特定条件时，可以使用`if`语句来跳出循环：

```py
i = 0 
while True: 
  print("The value of i is ", i) 
  i += 1 
  if i > 100: 
    break
```

在前面的例子中，`while`循环在一个无限循环中执行。`i`的值递增并打印在屏幕上。当`i`的值大于`100`时，程序会跳出`while`循环，并且`i`的值从 1 打印到 100。

# 条件语句的应用：使用 GPIO 执行任务

在上一章中，我们讨论了将输出接口到树莓派的 GPIO。让我们讨论一个简单的按键按下的例子。通过读取 GPIO 引脚状态来检测按钮按下。我们将使用条件语句来根据 GPIO 引脚状态执行任务。

让我们将一个按钮连接到树莓派的 GPIO。你需要准备一个按钮、上拉电阻和几根跳线。稍后给出的图示展示了如何将按键连接到树莓派 Zero。按键的一个端子连接到树莓派 Zero 的 GPIO 引脚的地线。

按键接口的原理图如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/9ce1761f-6261-40b0-b7c4-bb387a5e106a.png)树莓派 GPIO 原理图

按键的另一个端子通过 10K 电阻上拉到 3.3V。按键端子和 10K 电阻的交点连接到 GPIO 引脚 2（参考前一章中分享的 BCM GPIO 引脚图）。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ab6a4c5d-c0e8-4956-a703-5ade988dbee4.png)将按键接口到树莓派 Zero 的 GPIO - 使用 Fritzing 生成的图像

让我们回顾一下需要查看按钮状态的代码。我们利用循环和条件语句来使用树莓派 Zero 读取按钮输入。

我们将使用在上一章介绍的`gpiozero`库。本节的代码示例是`GPIO_button_test.py`，可与本章一起下载。

在后面的章节中，我们将讨论**面向对象编程**（**OOP**）。现在，让我们简要讨论类的概念。在 Python 中，**类**是一个包含定义对象的所有属性的蓝图。例如，`gpiozero`库的`Button`类包含了将按钮接口到树莓派 Zero 的 GPIO 接口所需的所有属性。这些属性包括按钮状态和检查按钮状态所需的函数等。为了接口一个按钮并读取其状态，我们需要使用这个蓝图。创建这个蓝图的副本的过程称为实例化。

让我们开始导入`gpiozero`库，并实例化`gpiozero`库的`Button`类（我们将在后面的章节中讨论 Python 的类、对象及其属性）。按钮接口到 GPIO 引脚 2。我们需要在实例化时传递引脚号作为参数：

```py
from gpiozero import Button 

#button is interfaced to GPIO 2 
button = Button(2)
```

`gpiozero`库的文档可在[`gpiozero.readthedocs.io/en/v1.2.0/api_input.html`](http://gpiozero.readthedocs.io/en/v1.2.0/api_input.html)找到。根据文档，`Button`类中有一个名为`is_pressed`的变量，可以使用条件语句进行测试，以确定按钮是否被按下：

```py
if button.is_pressed: 
    print("Button pressed")
```

每当按下按钮时，屏幕上会打印出消息`Button pressed`。让我们将这段代码片段放在一个无限循环中：

```py
from gpiozero import Button 

#button is interfaced to GPIO 2 
button = Button(2)

while True: 
  if button.is_pressed: 
    print("Button pressed")
```

在无限的`while`循环中，程序不断检查按钮是否被按下，并在按钮被按下时打印消息。一旦按钮被释放，它就会回到检查按钮是否被按下的状态。

# 通过计算按钮按下次数来中断循环

让我们再看一个例子，我们想要计算按钮按下的次数，并在按钮接收到预定数量的按下时中断无限循环：

```py
i = 0 
while True: 
  if button.is_pressed: 
    button.wait_for_release() 
    i += 1 
    print("Button pressed") 

  if i >= 10: 
    break
```

前面的例子可与本章一起下载，文件名为`GPIO_button_loop_break.py`。

在这个例子中，程序检查`is_pressed`变量的状态。在接收到按钮按下时，程序可以使用`wait_for_release`方法暂停，直到按钮被释放。当按钮被释放时，用于存储按下次数的变量会增加一次。

当按钮接收到 10 次按下时，程序会跳出无限循环。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/add8b086-b74e-44a0-909a-a8a30662357b.png)连接到树莓派 Zero GPIO 引脚 2 的红色瞬时按钮

# Python 中的函数

我们简要讨论了 Python 中的函数。函数执行一组预定义的任务。`print`是 Python 中函数的一个例子。它可以将一些东西打印到屏幕上。让我们讨论在 Python 中编写我们自己的函数。

可以使用`def`关键字在 Python 中声明函数。函数可以定义如下：

```py
def my_func(): 
   print("This is a simple function")
```

在这个函数`my_func`中，`print`语句是在一个缩进的代码块下编写的。在函数定义下缩进的任何代码块在代码执行期间调用函数时执行。函数可以被执行为`my_func()`。

# 向函数传递参数：

函数总是用括号定义的。括号用于向函数传递任何必要的参数。参数是执行函数所需的参数。在前面的例子中，没有向函数传递参数。

让我们回顾一个例子，我们向函数传递一个参数：

```py
def add_function(a, b): 
  c = a + b 
  print("The sum of a and b is ", c)
```

在这个例子中，`a`和`b`是函数的参数。函数将`a`和`b`相加，并在屏幕上打印总和。当通过传递参数`3`和`2`调用函数`add_function`时，`add_function(3,2)`，其中`a`为`3`，`b`为`2`。

因此，执行函数需要参数`a`和`b`，或者在没有参数的情况下调用函数会导致错误。可以通过为参数设置默认值来避免与缺少参数相关的错误：

```py
def add_function(a=0, b=0): 
  c = a + b 
  print("The sum of a and b is ", c)
```

前面的函数需要两个参数。如果我们只向这个函数传递一个参数，另一个参数默认为零。例如，`add_function(a=3)`，`b`默认为`0`，或者`add_function(b=2)`，`a`默认为`0`。当在调用函数时未提供参数时，它默认为零（在函数中声明）。

同样，`print`函数打印传递的任何变量。如果调用`print`函数时没有传递任何参数，则会打印一个空行。

# 从函数返回值

函数可以执行一组定义的操作，并最终在结束时返回一个值。让我们考虑以下例子：

```py
def square(a): 
   return a**2
```

在这个例子中，函数返回参数的平方。在 Python 中，`return`关键字用于在执行完成后返回请求的值。

# 函数中变量的作用域

Python 程序中有两种类型的变量：局部变量和全局变量。**局部变量**是函数内部的变量，即在函数内部声明的变量只能在该函数内部访问。例子如下：

```py
def add_function(): 
  a = 3 
  b = 2 
  c = a + b 
  print("The sum of a and b is ", c)
```

在这个例子中，变量`a`和`b`是函数`add_function`的局部变量。让我们考虑一个**全局变量**的例子：

```py
a = 3 
b = 2 
def add_function(): 
  c = a + b 
  print("The sum of a and b is ", c) 

add_function()
```

在这种情况下，变量`a`和`b`在 Python 脚本的主体中声明。它们可以在整个程序中访问。现在，让我们考虑这个例子：

```py
a = 3 
def my_function(): 
  a = 5 
  print("The value of a is ", a)

my_function() 
print("The value of a is ", a)
```

程序输出为：

```py
      The value of a is

      5

      The value of a is

      3
```

在这种情况下，当调用`my_function`时，`a`的值为`5`，在脚本主体的`print`语句中`a`的值为`3`。在 Python 中，不可能在函数内部显式修改全局变量的值。为了修改全局变量的值，我们需要使用`global`关键字：

```py
a = 3 
def my_function(): 
  global a 
  a = 5 
  print("The value of a is ", a)

my_function() 
print("The value of a is ", a)
```

一般来说，不建议在函数内修改变量，因为这不是一个很安全的修改变量的做法。最佳做法是将变量作为参数传递并返回修改后的值。考虑以下例子：

```py
a = 3 
def my_function(a): 
  a = 5 
  print("The value of a is ", a) 
  return a 

a = my_function(a) 
print("The value of a is ", a)
```

在上述程序中，`a`的值为`3`。它作为参数传递给`my_function`。函数返回`5`，保存到`a`中。我们能够安全地修改`a`的值。

# GPIO 回调函数

让我们回顾一下在 GPIO 示例中使用函数的一些用途。函数可以用来处理与树莓派的 GPIO 引脚相关的特定事件。例如，`gpiozero`库提供了在按钮按下或释放时调用函数的能力：

```py
from gpiozero import Button 

def button_pressed(): 
  print("button pressed")

def button_released(): 
  print("button released")

#button is interfaced to GPIO 2 
button = Button(2) 
button.when_pressed = button_pressed 
button.when_released = button_released

while True: 
  pass
```

在这个例子中，我们使用库的 GPIO 类的`when_pressed`和`when_released`属性。当按钮被按下时，执行函数`button_pressed`。同样，当按钮被释放时，执行函数`button_released`。我们使用`while`循环来避免退出程序并继续监听按钮事件。使用`pass`关键字来避免错误，当执行`pass`关键字时什么也不会发生。

能够为不同事件执行不同函数的能力在*家庭自动化*等应用中非常有用。例如，可以用来在天黑时打开灯，反之亦然。

# Python 中的直流电机控制

在本节中，我们将讨论使用树莓派 Zero 进行电机控制。为什么要讨论电机控制？随着我们在本书中不同主题的进展，我们将最终构建一个移动机器人。因此，我们需要讨论使用 Python 编写代码来控制树莓派上的电机。

为了控制电机，我们需要一个**H 桥电机驱动器**（讨论 H 桥超出了我们的范围。有几种资源可供 H 桥电机驱动器使用：[`www.mcmanis.com/chuck/robotics/tutorial/h-bridge/`](http://www.mcmanis.com/chuck/robotics/tutorial/h-bridge/)）。有几种专为树莓派设计的电机驱动器套件。在本节中，我们将使用以下套件：[`www.pololu.com/product/2753`](https://www.pololu.com/product/2753)。

**Pololu**产品页面还提供了如何连接电机的说明。让我们开始编写一些 Python 代码来操作电机：

```py
from gpiozero import Motor 
from gpiozero import OutputDevice 
import time

motor_1_direction = OutputDevice(13) 
motor_2_direction = OutputDevice(12)

motor = Motor(5, 6)

motor_1_direction.on() 
motor_2_direction.on()

motor.forward()

time.sleep(10)

motor.stop()

motor_1_direction.off() 
motor_2_direction.off()
```

树莓派基于电机控制

为了控制电机，让我们声明引脚、电机的速度引脚和方向引脚。根据电机驱动器的文档，电机分别由 GPIO 引脚 12、13 和 5、6 控制。

```py
from gpiozero import Motor 
from gpiozero import OutputDevice 
import time 

motor_1_direction = OutputDevice(13) 
motor_2_direction = OutputDevice(12) 

motor = Motor(5, 6)
```

控制电机就像使用`on()`方法打开电机，使用`forward()`方法向前移动电机一样简单：

```py
motor.forward()
```

同样，通过调用`reverse()`方法可以改变电机方向。通过以下方式可以停止电机：

```py
motor.stop()
```

# 读者的一些迷你项目挑战

以下是一些迷你项目挑战给我们的读者：

+   在本章中，我们讨论了树莓派的输入接口和电机控制。想象一个项目，我们可以驱动一个移动机器人，该机器人从触须开关读取输入并操作移动机器人。结合限位开关和电机，是否可能构建一个沿墙行驶的机器人？

+   在本章中，我们讨论了如何控制直流电机。我们如何使用树莓派控制步进电机？

+   如何使用树莓派 Zero 接口运动传感器来控制家里的灯？

# 总结

在本章中，我们讨论了条件语句以及条件语句在 Python 中的应用。我们还讨论了 Python 中的函数，将参数传递给函数，从函数返回值以及 Python 程序中变量的作用域。我们讨论了回调函数和 Python 中的电机控制。


# 第十二章：通信接口

到目前为止，我们已经讨论了 Python 中的循环、条件语句和函数。我们还讨论了与树莓派接口的输出设备和简单的数字输入设备。

在本章中，我们将讨论以下通信接口：

+   UART - 串行端口

+   串行外围接口

+   I²C 接口

我们将使用不同的传感器/电子元件来演示在 Python 中编写这些接口的代码。我们留给您选择一个您喜欢的组件来探索这些通信接口。

# UART - 串行端口

**通用异步收发器**（**UART**），即串行端口，是一种通信接口，数据以位的形式从传感器串行传输到主机计算机。使用串行端口是最古老的通信协议之一。它用于数据记录，微控制器从传感器收集数据并通过串行端口传输数据。还有一些传感器以串行通信的形式响应传入的命令传输数据。

我们不会深入讨论串行端口通信的理论（网络上有大量理论可供参考，网址为[`en.wikipedia.org/wiki/Universal_asynchronous_receiver/transmitter`](https://en.wikipedia.org/wiki/Universal_asynchronous_receiver/transmitter)）。我们将讨论使用串行端口与树莓派接口不同的传感器。

# 树莓派 Zero 的 UART 端口

通常，UART 端口由接收器（*Rx*）和发送器（*Tx*）引脚组成，用于接收和发送数据。树莓派的 GPIO 引脚带有 UART 端口。 GPIO 引脚 14（*Tx*引脚）和 15（*Rx*引脚）用作树莓派的 UART 端口：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ba8f2fb4-fd2d-4800-89a9-acf61b5b8833.png)GPIO 引脚 14 和 15 是 UART 引脚（图片来源：https://www.rs-online.com/designspark/introducing-the-raspberry-pi-b-plus）

# 设置树莓派 Zero 串行端口

为了使用串行端口与传感器通信，串行端口登录/控制台需要被禁用。在**Raspbian**操作系统镜像中，默认情况下启用此功能，因为它可以方便调试。

串行端口登录可以通过`raspi-config`禁用：

1.  启动终端并运行此命令：

```py
       sudo raspi-config
```

1.  从`raspi-config`的主菜单中选择高级选项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/2c7415ed-c2c3-40b8-83c0-bcc3548d9e69.png)从 raspi-config 菜单中选择高级选项

1.  从下拉菜单中选择 A8 串行选项：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/58a94cc8-560d-4c23-ad84-5bb5329bcaaf.png)从下拉菜单中选择 A8 串行

1.  禁用串行登录：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/ba8f0b5b-4633-4cd2-9b9f-5a41ec3995d1.png)禁用串行登录

1.  完成配置并在最后重新启动：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/631505a6-d950-47b8-8f9c-24bc22f50fff.png)保存配置并重新启动

# 示例 1 - 将二氧化碳传感器与树莓派连接

我们将使用 K30 二氧化碳传感器（其文档可在此处找到，[`co2meters.com/Documentation/Datasheets/DS30-01%20-%20K30.pdf`](http://co2meters.com/Documentation/Datasheets/DS30-01%20-%20K30.pdf)）。它的范围是 0-10,000 ppm，传感器通过串行端口以响应来自树莓派的特定命令提供二氧化碳浓度读数。

以下图显示了树莓派和 K30 二氧化碳传感器之间的连接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/b9774d1e-a0bd-4f58-9a42-3bba84a0f6e4.png)与树莓派连接的 K30 二氧化碳传感器

传感器的接收器（*Rx*）引脚连接到树莓派 Zero 的发送器（*Tx*-**GPIO 14（UART_TXD）**）引脚（前图中的黄色线）。传感器的发送器（*Tx*）引脚连接到树莓派 Zero 的接收器（*Rx*-**GPIO 15（UART_RXD）**）引脚（前图中的绿色线）。

为了给传感器供电，传感器的 G+引脚（前图中的红线）连接到树莓派 Zero 的**5V**引脚。传感器的 G0 引脚连接到树莓派 Zero 的**GND**引脚（前图中的黑线）。

通常，串行端口通信是通过指定波特率、帧中的位数、停止位和流控来初始化的。

# 用于串行端口通信的 Python 代码

我们将使用**pySerial**库（[`pyserial.readthedocs.io/en/latest/shortintro.html#opening-serial-ports`](https://pyserial.readthedocs.io/en/latest/shortintro.html#opening-serial-ports)）来接口二氧化碳传感器：

1.  根据传感器的文档，可以通过以波特率 9600、无奇偶校验、8 位和 1 个停止位初始化串行端口来读取传感器输出。 GPIO 串行端口为`ttyAMA0`。与传感器进行接口的第一步是初始化串行端口通信：

```py
       import serial 
       ser = serial.Serial("/dev/ttyAMA0")
```

1.  根据传感器文档（[`co2meters.com/Documentation/Other/SenseAirCommGuide.zip`](http://co2meters.com/Documentation/Other/SenseAirCommGuide.zip)），传感器对二氧化碳浓度的以下命令做出响应：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/f94c1fbd-f4b0-4ad7-965b-058f4cd1d3a1.png)从传感器数据表中借用的读取二氧化碳浓度的命令

1.  命令可以如下传输到传感器：

```py
       ser.write(bytearray([0xFE, 0x44, 0x00, 0x08, 0x02, 0x9F, 0x25]))
```

1.  传感器以 7 个字节的响应做出响应，可以如下读取：

```py
       resp = ser.read(7)
```

1.  传感器的响应格式如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/e4c08dba-07ab-4ea3-8865-db3c17c1b9dd.png)二氧化碳传感器响应

1.  根据数据表，传感器数据大小为 2 个字节。每个字节可用于存储 0 和 255 的值。两个字节可用于存储高达 65,535 的值（255 * 255）。二氧化碳浓度可以根据消息计算如下：

```py
       high = resp[3] 
       low = resp[4] 
       co2 = (high*256) + low
```

1.  把它全部放在一起：

```py
       import serial 
       import time 
       import array 
       ser = serial.Serial("/dev/ttyAMA0") 
       print("Serial Connected!") 
       ser.flushInput() 
       time.sleep(1) 

       while True: 
           ser.write(bytearray([0xFE, 0x44, 0x00, 0x08,
           0x02, 0x9F, 0x25])) 
           # wait for sensor to respond 
           time.sleep(.01) 
           resp = ser.read(7) 
           high = resp[3] 
           low = resp[4] 
           co2 = (high*256) + low 
           print() 
           print() 
           print("Co2 = " + str(co2)) 
           time.sleep(1)
```

1.  将代码保存到文件并尝试执行它。

# I2C 通信

**I²C**（Inter-Integrated Circuit）通信是一种串行通信类型，允许将多个传感器接口到计算机。 I²C 通信由时钟和数据线两根线组成。树莓派 Zero 的 I²C 通信的时钟和数据引脚分别为**GPIO 3**（**SCL**）和**GPIO 2**（**SDA**）。为了在同一总线上与多个传感器通信，通常通过 I²C 协议通信的传感器/执行器通常通过它们的 7 位地址进行寻址。可以有两个或更多树莓派板与同一 I²C 总线上的同一传感器进行通信。这使得可以在树莓派周围构建传感器网络。

I²C 通信线是开漏线路；因此，它们使用电阻上拉，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/9a174b4f-84ae-4b04-8bae-8310ea6cdaa3.png)I²C 设置

让我们通过一个示例来回顾一下 I²C 通信。

# 示例 2 - PiGlow

**PiGlow**是树莓派的一个附加硬件，由 18 个 LED 与**SN3218**芯片接口。该芯片允许通过 I²C 接口控制 LED。芯片的 7 位地址为`0x54`。

为了接口附加硬件，**SCL**引脚连接到**GPIO 3**，**SDA**引脚连接到**GPIO 2**；地线引脚和电源引脚分别连接到附加硬件的对应引脚。

PiGlow 附带了一个抽象 I²C 通信的库：[`github.com/pimoroni/piglow`](https://github.com/pimoroni/piglow)。

尽管该库是对 I²C 接口的封装，但我们建议阅读代码以了解操作 LED 的内部机制：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/681f2d8e-b110-4ae4-b62b-f326cdef6450.jpg)PiGlow 叠放在 Raspberry Pi 上

# 安装库

PiGlow 库可以通过从命令行终端运行以下命令来安装：

```py
    curl get.pimoroni.com/piglow | bash
```

# 示例

安装完成后，切换到示例文件夹（`/home/pi/Pimoroni/piglow`）并运行其中一个示例：

```py
    python3 bar.py
```

它应该运行*闪烁*灯效果，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/2ac65de6-24b3-4945-ae7d-406e5946ed31.jpg)PiGlow 上的闪烁灯

同样，还有库可以使用 I²C 通信与实时时钟、LCD 显示器等进行通信。如果你有兴趣编写自己的接口，提供 I²C 通信与传感器/输出设备的细节，请查看本书附带网站上的一些示例。

# 示例 3 - 用于树莓派的 Sensorian 附加硬件

**Sensorian**是为树莓派设计的附加硬件。这个附加硬件配备了不同类型的传感器，包括光传感器、气压计、加速度计、LCD 显示器接口、闪存存储器、电容触摸传感器和实时时钟。

这个附加硬件上的传感器足以学习本章讨论的所有通信接口的使用方法：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/23b57438-e4a5-4997-bc46-e485b31a001a.jpg)堆叠在树莓派 Zero 上的 Sensorian 硬件

在本节中，我们将讨论一个示例，我们将使用 I²C 接口通过树莓派 Zero 测量环境光水平。附加硬件板上的传感器是**APDS-9300**传感器（[www.avagotech.com/docs/AV02-1077EN](http://www.avagotech.com/docs/AV02-1077EN)）。

# 用于光传感器的 I2C 驱动程序

传感器硬件的驱动程序可从 GitHub 存储库中获取（[`github.com/sensorian/sensorian-firmware.git`](https://github.com/sensorian/sensorian-firmware.git)）。让我们从命令行终端克隆存储库：

```py
    git clone https://github.com/sensorian/sensorian-firmware.git 
```

让我们使用驱动程序（位于` ~/sensorian-firmware/Drivers_Python/APDS-9300`文件夹中）从传感器的两个 ADC 通道读取值：

```py
import time 
import APDS9300 as LuxSens 
import sys 

AmbientLight = LuxSens.APDS9300() 
while True: 
   time.sleep(1) 
   channel1 = AmbientLight.readChannel(1)                       
   channel2 = AmbientLight.readChannel(0) 
   Lux = AmbientLight.getLuxLevel(channel1,channel2) 
   print("Lux output: %d." % Lux)
```

有了两个通道的 ADC 值，驱动程序可以使用以下公式（从传感器数据表中检索）计算环境光值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/3af23ebe-b270-47a2-93a3-e379b7a6bea7.png)使用 ADC 值计算的环境光水平

这个计算是由属性`getLuxLevel`执行的。在正常照明条件下，环境光水平（以勒克斯为单位）约为`2`。当我们用手掌遮住光传感器时，测得的输出为`0`。这个传感器可以用来测量环境光，并相应地调整房间照明。

# 挑战

我们讨论了使用光传感器测量环境光水平。我们如何利用光输出（环境光水平）来控制房间照明？

# SPI 接口

还有一种名为**串行外围接口**（**SPI**）的串行通信接口。必须通过`raspi-config`启用此接口（这类似于在本章前面启用串行端口接口）。使用 SPI 接口类似于 I²C 接口和串行端口。

通常，SPI 接口由时钟线、数据输入、数据输出和**从机选择**（**SS**）线组成。与 I²C 通信不同（在那里我们可以连接多个主机），在同一总线上可以有一个主机（树莓派 Zero），但可以有多个从机。**SS**引脚用于选择树莓派 Zero 正在读取/写入数据的特定传感器，当同一总线上连接了多个传感器时。

# 示例 4 - 写入外部存储器芯片

让我们查看一个示例，我们将通过 SPI 接口向 Sensorian 附加硬件上的闪存存储器写入数据。SPI 接口和存储器芯片的驱动程序可从同一 GitHub 存储库中获取。

由于我们已经下载了驱动程序，让我们查看一下驱动程序中提供的示例：

```py
import sys 
import time   
import S25FL204K as Memory
```

让我们初始化并将消息`hello`写入存储器：

```py
Flash_memory = Memory.S25FL204K() 
Flash_memory.writeStatusRegister(0x00) 
message = "hello" 
flash_memory.writeArray(0x000000,list(message), message.len())
```

现在，让我们尝试读取刚刚写入外部存储器的数据：

```py
data = flash_memory.readArray(0x000000, message.len()) 
print("Data Read from memory: ") 
print(''.join(data))
```

本章提供了代码示例，可通过下载获得（`memory_test.py`）。

我们成功地演示了使用 SPI 读/写外部存储器芯片。

# 向读者提出挑战

在这里的图中，有一个 LED 灯带（[`www.adafruit.com/product/306`](https://www.adafruit.com/product/306)）与树莓派附加硬件的 SPI 接口相连，使用了 Adafruit Cobbler（[`www.adafruit.com/product/914`](https://www.adafruit.com/product/914)）。我们提供了一个线索，说明如何将 LED 灯带与树莓派 Zero 相连。我们希望看到您能否自己找到将 LED 灯带与树莓派 Zero 相连的解决方案。请参考本书网站获取答案。

LED 灯带与树莓派 Zero 的 Adafruit Cobbler 接口

# 总结

在本章中，我们讨论了树莓派 Zero 上可用的不同通信接口。这些接口包括 I²C、SPI 和 UART。我们将在我们的最终项目中使用这些接口。我们使用了二氧化碳传感器、LED 驱动器和传感器平台来讨论这些接口。在下一章中，我们将讨论面向对象编程及其独特的优势。我们将通过一个例子讨论面向对象编程的必要性。面向对象编程在您需要编写自己的驱动程序来控制机器人的组件或编写传感器的接口库的情况下尤其有帮助。


# 第十三章：Python 中的数据类型和面向对象编程

在本章中，我们将讨论 Python 中的数据类型和**面向对象编程**（**OOP**）。我们将讨论 Python 中的列表、字典、元组和集合等数据类型。我们还将讨论 OOP，它的必要性以及如何在树莓派基于项目中编写面向对象的代码（例如，使用 OOP 来控制家用电器）。我们将讨论在树莓派 Zero 项目中使用 OOP。

# 列表

在 Python 中，列表是一种数据类型（其文档在此处可用，[`docs.python.org/3.4/tutorial/datastructures.html#`](https://docs.python.org/3.4/tutorial/datastructures.html#)），可用于按顺序存储元素。

本章讨论的主题如果不在实践中使用很难理解。任何使用此符号表示的示例：`>>>`都可以使用 Python 解释器进行测试。

列表可以包含字符串、对象（在本章中详细讨论）或数字等。例如，以下是列表的示例：

```py
    >>> sequence = [1, 2, 3, 4, 5, 6]
 >>> example_list = ['apple', 'orange', 1.0, 2.0, 3]
```

在前面的一系列示例中，`sequence`列表包含介于`1`和`6`之间的数字，而`example_list`列表包含字符串、整数和浮点数的组合。列表用方括号（`[]`）表示。项目可以用逗号分隔添加到列表中：

```py
    >>> type(sequence)
 <class 'list'>
```

由于列表是有序元素的序列，可以通过使用`for`循环遍历列表元素来获取列表的元素，如下所示：

```py
for item in sequence: 
    print("The number is ", item)
```

输出如下：

```py
 The number is  1
 The number is  2
 The number is  3
 The number is  4
 The number is  5
 The number is  6
```

由于 Python 的循环可以遍历一系列元素，它会获取每个元素并将其赋值给`item`。然后将该项打印到控制台上。

# 可以在列表上执行的操作

在 Python 中，可以使用`dir()`方法检索数据类型的属性。例如，可以检索`sequence`列表的可用属性如下：

```py
    >>> dir(sequence)
 ['__add__', '__class__', '__contains__', '__delattr__',
    '__delitem__', '__dir__', '__doc__', '__eq__',
    '__format__', '__ge__', '__getattribute__', '__getitem__',
    '__gt__', '__hash__', '__iadd__', '__imul__', '__init__', 
    '__iter__', '__le__', '__len__', '__lt__', '__mul__',
    '__ne__', '__new__', '__reduce__', '__reduce_ex__',
    '__repr__', '__reversed__', '__rmul__', '__setattr__', 
    '__setitem__', '__sizeof__', '__str__', '__subclasshook__', 
    'append', 'clear', 'copy', 'count', 'extend', 'index',
    'insert', 'pop', 'remove', 'reverse', 'sort']
```

这些属性使得可以在列表上执行不同的操作。让我们详细讨论每个属性。

# 向列表添加元素：

可以使用`append()`方法添加元素：

```py
    >>> sequence.append(7)
 >>> sequence
 [1, 2, 3, 4, 5, 6, 7]
```

# 从列表中删除元素：

`remove()`方法找到元素的第一个实例（传递一个参数）并将其从列表中删除。让我们考虑以下示例：

+   **示例 1**：

```py
       >>> sequence = [1, 1, 2, 3, 4, 7, 5, 6, 7]
 >>> sequence.remove(7)
 >>> sequence
 [1, 1, 2, 3, 4, 5, 6, 7]
```

+   **示例 2**：

```py
       >>> sequence.remove(1)
 >>> sequence
 [1, 2, 3, 4, 5, 6, 7]
```

+   **示例 3**：

```py
       >>> sequence.remove(1)
 >>> sequence
 [2, 3, 4, 5, 6, 7]
```

# 检索元素的索引

`index()`方法返回列表中元素的位置：

```py
    >>> index_list = [1, 2, 3, 4, 5, 6, 7]
 >>> index_list.index(5)
 4
```

在这个例子中，该方法返回元素`5`的索引。由于 Python 使用从 0 开始的索引，因此元素`5`的索引为`4`：

```py
    random_list = [2, 2, 4, 5, 5, 5, 6, 7, 7, 8]
 >>> random_list.index(5)
 3
```

在这个例子中，该方法返回元素的第一个实例的位置。元素`5`位于第三个位置。

# 从列表中弹出一个元素

`pop()`方法允许从指定位置删除一个元素并返回它：

```py
    >>> index_list = [1, 2, 3, 4, 5, 6, 7]
 >>> index_list.pop(3)
 4
 >>> index_list
 [1, 2, 3, 5, 6, 7]
```

在这个例子中，`index_list`列表包含介于`1`和`7`之间的数字。通过传递索引位置`(3)`作为参数弹出第三个元素时，数字`4`从列表中移除并返回。

如果没有为索引位置提供参数，则弹出并返回最后一个元素：

```py
    >>> index_list.pop()
 7
 >>> index_list
 [1, 2, 3, 5, 6]
```

在这个例子中，最后一个元素`(7)`被弹出并返回。

# 计算元素的实例数量：

`count()`方法返回元素在列表中出现的次数。例如，该元素在列表`random_list`中出现两次。

```py
 >>> random_list = [2, 9, 8, 4, 3, 2, 1, 7] >>> random_list.count(2) 2
```

# 在特定位置插入元素：

`insert()`方法允许在列表中的特定位置添加一个元素。例如，让我们考虑以下示例：

```py
    >>> day_of_week = ['Monday', 'Tuesday', 'Thursday',
    'Friday', 'Saturday']
```

在列表中，`Wednesday`缺失。它需要被放置在`Tuesday`和`Thursday`之间的位置 2（Python 使用**零基索引**，即元素的位置/索引从 0、1、2 等开始计数）。可以使用 insert 添加如下：

```py
    >>> day_of_week.insert(2, 'Wednesday')
 >>> day_of_week
 ['Monday', 'Tuesday', 'Wednesday', 'Thursday',
    'Friday', 'Saturday']
```

# 读者的挑战

在前面的列表中，缺少 `Sunday`。使用列表的 `insert` 属性将其插入到正确的位置。

# 扩展列表

可以使用 `extend()` 方法将两个列表合并。`day_of_week` 和 `sequence` 列表可以合并如下：

```py
    >>> day_of_week.extend(sequence)
 >>> day_of_week
 ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday',
    'Saturday', 1, 2, 3, 4, 5, 6]
```

列表也可以组合如下：

```py
    >>> [1, 2, 3] + [4, 5, 6]
 [1, 2, 3, 4, 5, 6]
```

还可以将一个列表作为另一个列表的元素添加：

```py
    sequence.insert(6, [1, 2, 3])
 >>> sequence
 [1, 2, 3, 4, 5, 6, [1, 2, 3]]
```

# 清除列表的元素

可以使用 `clear()` 方法删除列表的所有元素：

```py
    >>> sequence.clear()
 >>> sequence
 []
```

# 对列表的元素进行排序

列表的元素可以使用 `sort()` 方法进行排序：

```py
    random_list = [8, 7, 5, 2, 2, 5, 7, 5, 6, 4]
 >>> random_list.sort()
 >>> random_list
 [2, 2, 4, 5, 5, 5, 6, 7, 7, 8]
```

当列表由一组字符串组成时，它们按照字母顺序排序：

```py
    >>> day_of_week = ['Monday', 'Tuesday', 'Thursday',
    'Friday', 'Saturday']
 >>> day_of_week.sort()
 >>> day_of_week
 ['Friday', 'Monday', 'Saturday', 'Thursday', 'Tuesday']
```

# 颠倒列表中的元素顺序

`reverse()` 方法使列表元素的顺序颠倒：

```py
    >>> random_list = [8, 7, 5, 2, 2, 5, 7, 5, 6, 4]
 >>> random_list.reverse()
 >>> random_list
 [4, 6, 5, 7, 5, 2, 2, 5, 7, 8]
```

# 创建列表的副本

`copy()` 方法可以创建列表的副本：

```py
    >>> copy_list = random_list.copy()
 >>> copy_list
 [4, 6, 5, 7, 5, 2, 2, 5, 7, 8]
```

# 访问列表元素

可以通过指定 `list_name[i]` 的索引位置来访问列表的元素。例如，可以按照以下方式访问 `random_list` 列表的第零个元素：

```py
 >>> random_list = [4, 6, 5, 7, 5, 2, 2, 5, 7, 8] 
 >>> random_list[0]4>>> random_list[3]7
```

# 访问列表中的一组元素

可以访问指定索引之间的元素。例如，可以检索索引为 2 和 4 之间的所有元素：

```py
    >>> random_list[2:5]
 [5, 7, 5]
```

可以按照以下方式访问列表的前六个元素：

```py
    >>> random_list[:6]
 [4, 6, 5, 7, 5, 2]
```

可以按照以下方式以相反的顺序打印列表的元素：

```py
    >>> random_list[::-1]
 [8, 7, 5, 2, 2, 5, 7, 5, 6, 4]
```

可以按照以下方式获取列表中的每个第二个元素：

```py
    >>> random_list[::2]
 [4, 5, 5, 2, 7]
```

还可以跳过前两个元素后获取第二个元素之后的每个第二个元素：

```py
    >>> random_list[2::2]
 [5, 5, 2, 7]
```

# 列表成员

可以使用 `in` 关键字检查一个值是否是列表的成员。例如：

```py
 >>> random_list = [2, 1, 0, 8, 3, 1, 10, 9, 5, 4]
```

在这个列表中，我们可以检查数字 `6` 是否是成员：

```py
    >>> 6 in random_list
 False
 >>> 4 in random_list
 True
```

# 让我们构建一个简单的游戏！

这个练习由两部分组成。在第一部分中，我们将回顾构建一个包含在 `0` 和 `10` 之间的十个随机数的列表。第二部分是给读者的一个挑战。执行以下步骤：

1.  第一步是创建一个空列表。让我们创建一个名为 `random_list` 的空列表。可以按照以下方式创建一个空列表：

```py
       random_list = []
```

1.  我们将使用 Python 的 `random` 模块 ([`docs.python.org/3/library/random.html`](https://docs.python.org/3/library/random.html)) 生成随机数。为了生成在 `0` 和 `10` 之间的随机数，我们将使用 `random` 模块的 `randint()` 方法。

```py
       random_number = random.randint(0,10)
```

1.  让我们将生成的数字附加到列表中。使用 `for` 循环重复此操作 `10` 次：

```py
       for index in range(0,10):
             random_number = random.randint(0, 10)
             random_list.append(random_number)
       print("The items in random_list are ")
       print(random_list)
```

1.  生成的列表看起来像这样：

```py
       The items in random_list are
 [2, 1, 0, 8, 3, 1, 10, 9, 5, 4]
```

我们讨论了生成一个随机数列表。下一步是接受用户输入，我们要求用户猜一个在 `0` 和 `10` 之间的数字。如果数字是列表的成员，则打印消息 `你的猜测是正确的`，否则打印消息 `对不起！你的猜测是错误的`。我们将第二部分留给读者作为挑战。使用本章提供的 `list_generator.py` 代码示例开始。

# 字典

字典 ([`docs.python.org/3.4/tutorial/datastructures.html#dictionaries`](https://docs.python.org/3.4/tutorial/datastructures.html#dictionaries)) 是一个无序的键值对集合的数据类型。字典中的每个键都有一个相关的值。字典的一个示例是：

```py
 >>> my_dict = {1: "Hello", 2: "World"} >>> my_dict   
 {1: 'Hello', 2: 'World'}
```

通过使用大括号 `{}` 创建字典。在创建时，新成员以以下格式添加到字典中：`key: value`（如前面的示例所示）。在前面的示例中，`1` 和 `2` 是键，而 `'Hello'` 和 `'World'` 是相关的值。添加到字典的每个值都需要有一个相关的键。

字典的元素没有顺序，即不能按照添加的顺序检索元素。可以通过遍历键来检索字典的值。让我们考虑以下示例：

```py
 >>> my_dict = {1: "Hello", 2: "World", 3: "I", 4: "am",
    5: "excited", 6: "to", 7: "learn", 8: "Python" }
```

有几种方法可以打印字典的键或值：

```py
 >>> for key in my_dict: ... 
 print(my_dict[value]) 
 ... Hello World I 
 am excited to learn Python
```

在前面的示例中，我们遍历字典的键并使用键`my_dict[key]`检索值。还可以使用字典中可用的`values()`方法检索值：

```py
 >>> for value in my_dict.values(): ... 

print(value) ... Hello World I am excited to learn Python
```

字典的键可以是整数、字符串或元组。字典的键需要是唯一的且不可变的，即创建后无法修改。无法创建键的重复项。如果向现有键添加新值，则字典中将存储最新值。让我们考虑以下示例：

+   可以按以下方式向字典添加新的键/值对：

```py
 >>> my_dict[9] = 'test' >>> my_dict {1: 'Hello', 2: 'World', 3: 'I', 4: 'am', 5: 'excited',
       6: 'to', 7: 'learn', 8: 'Python', 9: 'test'}
```

+   让我们尝试创建键`9`的重复项：

```py
 >>> my_dict[9] = 'programming' >>> my_dict {1: 'Hello', 2: 'World', 3: 'I', 4: 'am', 5: 'excited',
       6: 'to', 7: 'learn', 8: 'Python', 9: 'programming'}
```

+   如前面的示例所示，当我们尝试创建重复项时，现有键的值会被修改。

+   可以将多个值与一个键关联。例如，作为列表或字典：

```py
 >>> my_dict = {1: "Hello", 2: "World", 3: "I", 4: "am",
      "values": [1, 2, 3,4, 5], "test": {"1": 1, "2": 2} } 
```

字典在解析 CSV 文件并将每一行与唯一键关联的场景中非常有用。字典也用于编码和解码 JSON 数据

# 元组

元组（发音为*two-ple*或*tuh-ple*）是一种不可变的数据类型，按顺序排列并用逗号分隔。可以按以下方式创建元组：

```py
 >>> my_tuple = 1, 2, 3, 4, 5
 >>> my_tuple (1, 2, 3, 4, 5)
```

由于元组是不可变的，因此无法修改给定索引处的值：

```py
    >>> my_tuple[1] = 3
 Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
 TypeError: 'tuple' object does not support item assignment
```

元组可以由数字、字符串或列表组成。由于列表是可变的，如果列表是元组的成员，则可以修改。例如：

```py
    >>> my_tuple = 1, 2, 3, 4, [1, 2, 4, 5]
 >>> my_tuple[4][2] = 3
 >>> my_tuple
 (1, 2, 3, 4, [1, 2, 3, 5])
```

元组在值无法修改的情况下特别有用。元组还用于从函数返回值。让我们考虑以下示例：

```py
 >>> for value in my_dict.items(): ... 

 print(value) 
 ...
 (1, 'Hello') (2, 'World') (3, 'I') (4, 'am') ('test', {'1': 1, '2': 2}) ('values', [1, 2, 3, 4, 5])
```

在前面的示例中，`items()`方法返回一个元组列表。

# 集合

集合（[`docs.python.org/3/tutorial/datastructures.html#sets`](https://docs.python.org/3/tutorial/datastructures.html#sets)）是一个无序的不可变元素的集合，不包含重复条目。可以按以下方式创建集合：

```py
 >>> my_set = set([1, 2, 3, 4, 5]) >>> my_set {1, 2, 3, 4, 5}
```

现在，让我们向这个集合添加一个重复的列表：

```py
 >>> my_set.update([1, 2, 3, 4, 5]) >>> my_set {1, 2, 3, 4, 5}
```

集合可以避免重复条目并保存唯一条目。可以将单个元素添加到集合中，如下所示：

```py
 >>> my_set = set([1, 2, 3, 4, 5]) >>> my_set.add(6)
 >>> my_set
 {1, 2, 3, 4, 5, 6}
```

集合用于测试元素在不同集合中的成员资格。有与成员资格测试相关的不同方法。我们建议使用集合的文档来了解每种方法（运行`help(my_set)`以查找成员资格测试的不同方法）。

# Python 中的面向对象编程

面向对象编程有助于简化代码并简化应用程序开发。在重用代码方面尤其有用。面向对象的代码使您能够重用使用通信接口的传感器的代码。例如，所有配有 UART 端口的传感器可以使用面向对象的代码进行分组。

面向对象编程的一个例子是**GPIO Zero 库**（[`www.raspberrypi.org/blog/gpio-zero-a-friendly-python-api-for-physical-computing/`](https://www.raspberrypi.org/blog/gpio-zero-a-friendly-python-api-for-physical-computing/)），在之前的章节中使用过。实际上，在 Python 中一切都是对象。

面向对象的代码在与其他人合作项目时特别有帮助。例如，您可以使用 Python 中的面向对象的代码实现传感器驱动程序并记录其用法。这使其他开发人员能够开发应用程序，而无需关注传感器接口背后的细节。面向对象编程为应用程序提供了模块化，简化了应用程序开发。我们将在本章中回顾一个示例，演示面向对象编程的优势。在本章中，我们将利用面向对象编程为我们的项目带来模块化。

让我们开始吧！

# 重新审视学生 ID 卡示例

让我们重新访问第十章中的身份证示例，*算术运算、循环和闪烁灯*（`input_test.py`）。我们讨论了编写一个简单的程序，用于捕获和打印属于一个学生的信息。学生的联系信息可以按以下方式检索和存储：

```py
name = input("What is your name? ") 
address = input("What is your address? ") 
age = input("How old are you? ")
```

现在，考虑一个情景，需要保存和在程序执行期间的任何时刻检索 10 个学生的信息。我们需要为用于保存学生信息的变量想出一个命名规范。如果我们使用 30 个不同的变量来存储每个学生的信息，那将会是一团糟。这就是面向对象编程可以真正帮助的地方。

让我们使用面向对象编程来重新编写这个例子，以简化问题。面向对象编程的第一步是声明对象的结构。这是通过定义一个类来完成的。类确定了对象的功能。让我们编写一个 Python 类，定义学生对象的结构。

# 类

由于我们将保存学生信息，所以类将被称为`Student`。类是使用`class`关键字定义的，如下所示：

```py
class Student(object):
```

因此，定义了一个名为`Student`的类。每当创建一个新对象时，Python 会在内部调用`__init__()`方法。

这个方法是在类内定义的：

```py
class Student(object): 
    """A Python class to store student information""" 

    def __init__(self, name, address, age): 
        self.name = name 
        self.address = address 
        self.age = age
```

在这个例子中，`__init__`方法的参数包括`name`、`age`和`address`。这些参数被称为**属性**。这些属性使得可以创建一个属于`Student`类的唯一对象。因此，在这个例子中，在创建`Student`类的实例时，需要`name`、`age`和`address`这些属性作为参数。

让我们创建一个属于`Student`类的对象（也称为实例）：

```py
student1 = Student("John Doe", "123 Main Street, Newark, CA", "29")
```

在这个例子中，我们创建了一个属于`Student`类的对象，称为`student1`，其中`John Doe`（姓名）、`29`（年龄）和`123 Main Street, Newark, CA`（地址）是创建对象所需的属性。当我们创建一个属于`Student`类的对象时，通过传递必要的参数（在`Student`类的`__init__()`方法中声明的），`__init__()`方法会自动调用以初始化对象。初始化后，与`student1`相关的信息将存储在对象`student1`下。

现在，属于`student1`的信息可以按以下方式检索：

```py
print(student1.name) 
print(student1.age) 
print(student1.address)
```

现在，让我们创建另一个名为`student2`的对象：

```py
student2 = Student("Jane Doe", "123 Main Street, San Jose, CA", "27")
```

我们创建了两个对象，分别称为`student1`和`student2`。每个对象的属性都可以通过`student1.name`、`student2.name`等方式访问。在没有面向对象编程的情况下，我们将不得不创建变量，如`student1_name`、`student1_age`、`student1_address`、`student2_name`、`student2_age`和`student2_address`等。因此，面向对象编程使得代码模块化。

# 向类添加方法

让我们为我们的`Student`类添加一些方法，以帮助检索学生的信息：

```py
class Student(object): 
    """A Python class to store student information""" 

    def __init__(self, name, age, address): 
        self.name = name 
        self.address = address 
        self.age = age 

    def return_name(self): 
        """return student name""" 
        return self.name 

    def return_age(self): 
        """return student age""" 
        return self.age 

    def return_address(self): 
        """return student address""" 
        return self.address
```

在这个例子中，我们添加了三个方法，分别是`return_name()`、`return_age()`和`return_address()`，它们分别返回属性`name`、`age`和`address`。类的这些方法被称为**可调用属性**。让我们回顾一个快速的例子，我们在其中使用这些可调用属性来打印对象的信息。

```py
student1 = Student("John Doe", "29", "123 Main Street, Newark, CA") 
print(student1.return_name()) 
print(student1.return_age()) 
print(student1.return_address())
```

到目前为止，我们讨论了检索有关学生的信息的方法。让我们在我们的类中包含一个方法，使得学生的信息可以更新。现在，让我们在类中添加另一个方法，使学生可以更新地址：

```py
def update_address(self, address): 
    """update student address""" 
    self.address = address 
    return self.address
```

让我们比较更新地址之前和之后的`student1`对象的地址：

```py
print(student1.address()) 
print(student1.update_address("234 Main Street, Newark, CA"))
```

这将在屏幕上打印以下输出：

```py
    123 Main Street, Newark, CA
 234 Main Street, Newark, CA
```

因此，我们已经编写了我们的第一个面向对象的代码，演示了模块化代码的能力。前面的代码示例可与本章一起下载，名称为`student_info.py`。

# Python 中的文档字符串

在面向对象的示例中，您可能已经注意到了一个用三个双引号括起来的句子：

```py
    """A Python class to store student information"""
```

这被称为**文档字符串**。文档字符串用于记录有关类或方法的信息。文档字符串在尝试存储与方法或类的使用相关的信息时特别有帮助（稍后将在本章中演示）。文档字符串还用于在文件开头存储与应用程序或代码示例相关的多行注释。Python 解释器会忽略文档字符串，它们旨在为其他程序员提供有关类的文档。

同样，Python 解释器会忽略以`#`符号开头的任何单行注释。单行注释通常用于对一块代码做特定的注释。包括结构良好的注释可以使您的代码易读。

例如，以下代码片段通知读者，生成并存储在变量`rand_num`中的随机数在`0`和`9`之间：

```py
# generate a random number between 0 and 9 
rand_num = random.randrange(0,10)
```

相反，提供没有上下文的注释将会让审阅您的代码的人感到困惑：

```py
# Todo: Fix this later
```

当您以后重新访问代码时，很可能您可能无法回忆起需要修复什么。

# self

在我们的面向对象的示例中，每个方法的第一个参数都有一个名为`self`的参数。`self`指的是正在使用的类的实例，`self`关键字用作与类的实例交互的方法中的第一个参数。在前面的示例中，`self`指的是对象`student1`。它相当于初始化对象并访问它如下：

```py
Student(student1, "John Doe", "29", "123 Main Street, Newark, CA") 
Student.return_address(student1)
```

在这种情况下，`self`关键字简化了我们访问对象属性的方式。现在，让我们回顾一些涉及树莓派的 OOP 的例子。

# 扬声器控制器

让我们编写一个 Python 类（下载的`tone_player.py`），它会播放一个音乐音调，指示您的树莓派已完成启动。对于本节，您将需要一个 USB 声卡和一个连接到树莓派的 USB 集线器的扬声器。

让我们称我们的类为`TonePlayer`。这个类应该能够控制扬声器音量，并在创建对象时播放任何传递的文件：

```py
class TonePlayer(object): 
    """A Python class to play boot-up complete tone""" 

    def __init__(self, file_name): 
        self.file_name = file_name
```

在这种情况下，必须传递给`TonePlayer`类要播放的文件的参数。例如：

```py
       tone_player = TonePlayer("/home/pi/tone.wav")
```

我们还需要能够设置要播放音调的音量级别。让我们添加一个执行相同操作的方法：

```py
def set_volume(self, value): 
    """set tone sound volume""" 
    subprocess.Popen(["amixer", "set", "'PCM'", str(value)], 
    shell=False)
```

在`set_volume`方法中，我们使用 Python 的`subprocess`模块来运行调整声音驱动器音量的 Linux 系统命令。

这个类最重要的方法是`play`命令。当调用`play`方法时，我们需要使用 Linux 的`play`命令播放音调声音：

```py
def play(self):
    """play the wav file"""
    subprocess.Popen(["aplay", self.file_name], shell=False)
```

把它全部放在一起：

```py
import subprocess 

class TonePlayer(object): 
    """A Python class to play boot-up complete tone""" 

    def __init__(self, file_name): 
        self.file_name = file_name 

    def set_volume(self, value): 
        """set tone sound volume""" 
        subprocess.Popen(["amixer", "set", "'PCM'", str(value)],
        shell=False) 

    def play(self): 
        """play the wav file""" 
        subprocess.Popen(["aplay", self.file_name], shell=False) 

if __name__ == "__main__": 
    tone_player = TonePlayer("/home/pi/tone.wav") 
    tone_player.set_volume(75) 
    tone_player.play()
```

将`TonePlayer`类保存到您的树莓派（保存为名为`tone_player.py`的文件），并使用来自*freesound*（[`www.freesound.org/people/zippi1/sounds/18872/`](https://www.freesound.org/people/zippi1/sounds/18872/)）等来源的音调声音文件。将其保存到您选择的位置并尝试运行代码。它应该以所需的音量播放音调声音！

现在，编辑`/etc/rc.local`并在文件末尾添加以下行（在`exit 0`行之前）：

```py
python3 /home/pi/toneplayer.py
```

这应该在 Pi 启动时播放一个音调！

# 灯光控制守护程序

让我们回顾另一个例子，在这个例子中，我们使用 OOP 实现了一个简单的守护程序，它在一天中的指定时间打开/关闭灯光。为了能够在预定时间执行任务，我们将使用`schedule`库（[`github.com/dbader/schedule`](https://github.com/dbader/schedule)）。可以按照以下方式安装它：

```py
    sudo pip3 install schedule
```

让我们称我们的类为`LightScheduler`。它应该能够接受开启和关闭灯光的开始和结束时间。它还应该提供覆盖功能，让用户根据需要开启/关闭灯光。假设灯光是使用**PowerSwitch Tail II**（[`www.powerswitchtail.com/Pages/default.aspx`](http://www.powerswitchtail.com/Pages/default.aspx)）来控制的。它的接口如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/gtst-py-iot/img/4616788e-12ba-409b-8fcc-499916c7a9bb.png)树莓派 Zero 与 PowerSwitch Tail II 的接口

以下是创建的`LightSchedular`类：

```py
class LightScheduler(object): 
    """A Python class to turn on/off lights""" 

    def __init__(self, start_time, stop_time): 
        self.start_time = start_time 
        self.stop_time = stop_time 
        # lamp is connected to GPIO pin2.
        self.lights = OutputDevice(2)
```

每当创建`LightScheduler`的实例时，GPIO 引脚被初始化以控制 PowerSwitch Tail II。现在，让我们添加开启/关闭灯光的方法：

```py
def init_schedule(self): 
        # set the schedule 
        schedule.every().day.at(self.start_time).do(self.on) 
        schedule.every().day.at(self.stop_time).do(self.off) 

    def on(self): 
        """turn on lights""" 
        self.lights.on() 

    def off(self): 
        """turn off lights""" 
        self.lights.off()
```

在`init_schedule()`方法中，传递的开始和结束时间被用来初始化`schedule`，以便在指定的时间开启/关闭灯光。

把它放在一起，我们有：

```py
import schedule 
import time 
from gpiozero import OutputDevice 

class LightScheduler(object): 
    """A Python class to turn on/off lights""" 

    def __init__(self, start_time, stop_time): 
        self.start_time = start_time 
        self.stop_time = stop_time 
        # lamp is connected to GPIO pin2.
        self.lights = OutputDevice(2) 

    def init_schedule(self): 
        # set the schedule 
        schedule.every().day.at(self.start_time).do(self.on) 
        schedule.every().day.at(self.stop_time).do(self.off) 

    def on(self): 
        """turn on lights""" 
        self.lights.on() 

    def off(self): 
        """turn off lights""" 
        self.lights.off() 

if __name__ == "__main__": 
    lamp = LightScheduler("18:30", "9:30") 
    lamp.on() 
    time.sleep(50) 
    lamp.off() 
    lamp.init_schedule() 
    while True:
        schedule.run_pending() 
        time.sleep(1)
```

在上面的例子中，灯光被安排在下午 6:30 开启，并在上午 9:30 关闭。一旦工作被安排，程序就会进入一个无限循环，等待任务执行。这个例子可以作为守护进程运行，通过在启动时执行文件（在`/etc/rc.local`中添加一行`light_scheduler.py`）。安排完工作后，它将继续作为后台守护进程运行。

这只是面向初学者的 OOP 及其应用的基本介绍。请参考本书网站以获取更多关于 OOP 的例子。

# 总结

在本章中，我们讨论了列表和 OOP 的优势。我们使用树莓派作为例子的中心，讨论了 OOP 的例子。由于本书主要面向初学者，我们决定在讨论例子时坚持 OOP 的基础知识。书中还有一些超出范围的高级方面。我们让读者通过本书网站上提供的其他例子来学习高级概念。
