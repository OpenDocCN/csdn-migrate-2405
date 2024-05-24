# 精通 Python 系统管理脚本编程（三）

> 原文：[`zh.annas-archive.org/md5/c33d6613eafa4d86b92059a00f7aa16f`](https://zh.annas-archive.org/md5/c33d6613eafa4d86b92059a00f7aa16f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：文档和报告

在本章中，您将学习如何使用 Python 记录和报告信息。您还将学习如何使用 Python 脚本获取输入以及如何打印输出。在 Python 中编写接收电子邮件的脚本更容易。您将学习如何格式化信息。

在本章中，您将学习以下内容：

+   标准输入和输出

+   信息格式化

+   发送电子邮件

# 标准输入和输出

在本节中，我们将学习 Python 中的输入和输出。我们将学习`stdin`和`stdout`，以及`input()`函数。

`stdin`和`stdout`是类似文件的对象。这些对象由操作系统提供。每当用户在交互会话中运行程序时，`stdin`充当输入，`stdout`将是用户的终端。由于`stdin`是类似文件的对象，我们必须从`stdin`读取数据而不是在运行时读取数据。`stdout`用于输出。它用作表达式和`print()`函数的输出，以及`input()`函数的提示。

现在，我们将看一个`stdin`和`stdout`的例子。为此，请创建一个名为`stdin_stdout_example.py`的脚本，并在其中写入以下内容：

```py
import sys print("Enter number1: ") a = int(sys.stdin.readline()) print("Enter number2: ") b = int(sys.stdin.readline()) c = a + b sys.stdout.write("Result: %d " % c)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 stdin_stdout_example.py Enter number1: 10 Enter number2: 20 Result: 30
```

在上面的例子中，我们使用了`stdin`和`stdout`来获取输入和显示输出。`sys.stdin.readline()`将从`stdin`读取数据。将写入数据。

现在，我们将学习`input()`和`print()`函数。`input()`函数用于从用户那里获取输入。该函数有一个可选参数：提示字符串。

语法：

```py
 input(prompt)
```

`input()`函数返回一个字符串值。如果您想要一个数字值，只需在`input()`之前写入`int`关键字。您可以这样做：

```py
 int(input(prompt))
```

同样，您可以为浮点值写入`float`。现在，我们将看一个例子。创建一个`input_example.py`脚本，并在其中写入以下代码：

```py
str1 = input("Enter a string: ") print("Entered string is: ", str1) print() a = int(input("Enter the value of a: ")) b = int(input("Enter the value of b: ")) c = a + b print("Value of c is: ", c) print() num1 = float(input("Enter num 1: ")) num2 = float(input("Enter num 2: ")) num3 = num1/num2 print("Value of num 3 is: ", num3)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 input_example.py Output: Enter a string: Hello Entered string is:  Hello Enter the value of a: 10 Enter the value of b: 20 Value of c is:  30Enter num 1: 10.50 Enter num 2: 2.0 Value of num 3 is:  5.25
```

在上面的例子中，我们使用`input()`函数获取了三个不同的值。首先是字符串，第二个是整数值，第三个是`float`值。要将`input()`用于整数和浮点数，我们必须使用`int()`和`float()`类型转换函数将接收到的字符串转换为整数和浮点数。

现在，`print()`函数用于输出数据。我们必须输入一个以逗号分隔的参数列表。在`input_example.py`中，我们使用了`print()`函数来获取输出。使用`print()`函数，您可以通过将数据括在`""`或`''`中简单地将数据写入屏幕上。要仅访问值，只需在`print()`函数中写入变量名。如果您想在同一个`print()`函数中写一些文本并访问一个值，那么请用逗号将这两者分开。

我们将看一个`print()`函数的简单例子。创建一个`print_example.py`脚本，并在其中写入以下内容：

```py
# printing a simple string on the screen. print("Hello Python") # Accessing only a value. a = 80 print(a)  # printing a string on screen as well as accessing a value. a = 50 b = 30 c = a/b print("The value of c is: ", c)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 print_example.py Hello Python 80 The value of c is:  1.6666666666666667
```

在上面的例子中，首先我们简单地在屏幕上打印了一个字符串。接下来，我们只是访问了`a`的值并将其打印在屏幕上。最后，我们输入了`a`和`b`的值，然后将它们相加并将结果存储在变量`c`中，然后我们打印了一个语句并从同一个`print()`函数中访问了一个值。

# 信息格式化

在本节中，我们将学习字符串格式化。我们将学习两种格式化信息的方法：一种是使用字符串`format()`方法，另一种是使用`%`运算符。

首先，我们将学习使用字符串`format()`方法进行字符串格式化。`string`类的这种方法允许我们进行值格式化。它还允许我们进行变量替换。这将通过位置参数连接元素。

现在，我们将学习如何使用格式化程序进行格式化。调用此方法的字符串可以包含文字或由大括号`{}`分隔的替换字段。在格式化字符串时可以使用多对`{}`。此替换字段包含参数的索引或参数的名称。结果，您将获得一个字符串副本，其中每个替换字段都替换为参数的字符串值。

现在，我们将看一个字符串格式化的例子。

创建一个`format_example.py`脚本，并在其中写入以下内容：

```py
# Using single formatter print("{}, My name is John".format("Hi")) str1 = "This is John. I am learning {} scripting language." print(str1.format("Python")) print("Hi, My name is Sara and I am {} years old !!".format(26)) # Using multiple formatters str2 = "This is Mary {}. I work at {} Resource department. I am {} years old !!" print(str2.format("Jacobs", "Human", 30)) print("Hello {}, Nice to meet you. I am {}.".format("Emily", "Jennifer"))
```

按以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 format_example.py Output: Hi, My name is John This is John. I am learning Python scripting language. Hi, My name is Sara and I am 26 years old !! This is Mary Jacobs. I work at Human Resource department. I am 30 years old !! Hello Emily, Nice to meet you. I am Jennifer.
```

在前面的例子中，我们使用`string`类的`format()`方法进行了字符串格式化，使用了单个和多个格式化程序。

现在，我们将学习如何使用`％`运算符进行字符串格式化。`％`运算符与格式符一起使用。以下是一些常用的符号：

+   `％d`：十进制整数

+   `%s`：字符串

+   `％f`：浮点数

+   `％c`：字符

现在，我们将看一个例子。创建一个`string_formatting.py`脚本，并在其中写入以下内容：

```py
# Basic formatting a = 10 b = 30 print("The values of a and b are %d %d" % (a, b)) c = a + b print("The value of c is %d" % c) str1 = 'John' print("My name is %s" % str1)  x = 10.5 y = 33.5 z = x * y print("The value of z is %f" % z) print() # aligning name = 'Mary' print("Normal: Hello, I am %s !!" % name) print("Right aligned: Hello, I am %10s !!" % name) print("Left aligned: Hello, I am %-10s !!" % name) print() # truncating print("The truncated string is %.4s" % ('Examination')) print() # formatting placeholders students = {'Name' : 'John', 'Address' : 'New York'} print("Student details: Name:%(Name)s Address:%(Address)s" % students) 
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 string_formatting.py The values of a and b are 10 30 The value of c is 40 My name is John The value of z is 351.750000Normal: Hello, I am Mary !! Right aligned: Hello, I am       Mary !! Left aligned: Hello, I am Mary       !!
The truncated string is Exam
Student details: Name:John Address:New York
```

在前面的例子中，我们使用`％`运算符来格式化字符串：`％d`表示数字，`％s`表示字符串，`％f`表示浮点数。然后，我们将字符串左对齐和右对齐。我们还学会了如何使用`％`运算符截断字符串。`％.4s`将仅显示前四个字符。接下来，我们创建了一个名为`students`的字典，并输入了`Name`和`Address`键值对。然后，我们在`％`运算符后放置了我们的键名以获取字符串。

# 发送电子邮件

在本节中，我们将学习如何通过 Python 脚本从 Gmail 发送电子邮件。为此，Python 有一个名为`smtplib`的模块。Python 中的`smtplib`模块提供了用于向具有 SMTP 侦听器的任何互联网机器发送电子邮件的 SMTP 客户端会话对象。

我们将看一个例子。在这个例子中，我们将从 Gmail 向接收者发送包含简单文本的电子邮件。

创建一个`send_email.py`脚本，并在其中写入以下内容：

```py
import smtplib from email.mime.text import MIMEText import getpass host_name = 'smtp.gmail.com' port = 465 u_name = 'username/emailid' password = getpass.getpass() sender = 'sender_name' receivers = ['receiver1_email_address', 'receiver2_email_address'] text = MIMEText('Test mail') text['Subject'] = 'Test' text['From'] = sender text['To'] = ', '.join(receivers) s_obj = smtplib.SMTP_SSL(host_name, port) s_obj.login(u_name, password) s_obj.sendmail(sender, receivers, text.as_string()) s_obj.quit() print("Mail sent successfully")
```

按以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 send_text.py
```

输出：

```py
Password: Mail sent successfully
```

在前面的例子中，我们从我们的 Gmail ID 向接收者发送了一封电子邮件。用户名变量将存储您的电子邮件 ID。在密码变量中，您可以输入密码，或者您可以使用`getpass`模块提示密码。在这里，我们提示输入密码。接下来，发件人变量将有您的名字。现在，我们将向多个接收者发送此电子邮件。然后，我们为该电子邮件包括了主题，发件人和收件人。然后在`login()`中，我们提到了我们的用户名和密码变量。接下来，在`sendmail()`中，我们提到了发件人，接收者和文本变量。因此，使用此过程，我们成功发送了电子邮件。

现在，我们将看一个发送带附件的电子邮件的例子。在这个例子中，我们将向收件人发送一张图片。我们将通过 Gmail 发送此邮件。创建一个`send_email_attachment.py`脚本，并在其中写入以下内容：

```py
import os import smtplib from email.mime.text import MIMEText from email.mime.image import MIMEImage from email.mime.multipart import MIMEMultipart import getpass host_name = 'smtp.gmail.com' port = 465  u_name = 'username/emailid' password = getpass.getpass() sender = 'sender_name' receivers = ['receiver1_email_address', 'receiver2_email_address'] text = MIMEMultipart() text['Subject'] = 'Test Attachment' text['From'] = sender text['To'] = ', '.join(receivers) txt = MIMEText('Sending a sample image.') text.attach(txt) f_path = '/home/student/Desktop/mountain.jpg' with open(f_path, 'rb') as f:
 img = MIMEImage(f.read()) img.add_header('Content-Disposition',
 'attachment', filename=os.path.basename(f_path)) text.attach(img) server = smtplib.SMTP_SSL(host_name, port) server.login(u_name, password) server.sendmail(sender, receivers, text.as_string()) print("Email with attachment sent successfully !!")server.quit()
```

按以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 send_email_attachment.py
```

输出：

```py
Password: Email with attachment sent successfully!!
```

在前面的例子中，我们将图像作为附件发送给接收者。我们提到了发件人和收件人的电子邮件 ID。接下来，在`f_path`中，我们提到了我们发送为附件的图像的路径。接下来，我们将该图像作为附件发送给接收者。

在前面的两个例子——`send_text.py`和`send_email_attachment.py`——我们通过 Gmail 发送了电子邮件。您可以通过任何其他电子邮件提供商发送。要使用任何其他电子邮件提供商，只需在`host_name`中写入该提供商名称。不要忘记在其前面添加`smtp`。在这些示例中，我们使用了`smtp.gmail.com`；对于 Yahoo！您可以使用`smtp.mail.yahoo.com`。因此，您可以根据您的电子邮件提供商更改主机名以及端口。

# 摘要

在本章中，我们学习了标准输入和输出。我们了解了`stdin`和`stdout`分别作为键盘输入和用户终端。我们还学习了`input()`和`print()`函数。除此之外，我们还学习了如何从 Gmail 发送电子邮件给接收者。我们发送了一封包含简单文本的电子邮件，还发送了附件。此外，我们还学习了使用`format()`方法和`%`运算符进行字符串格式化。

在下一章中，您将学习如何处理不同类型的文件，如 PDF、Excel 和“csv”。

# 问题

1.  `stdin`和输入之间有什么区别？

1.  SMTP 是什么？

1.  以下内容的输出将是什么？

```py
>>> name = "Eric"
>>> profession = "comedian"
>>> affiliation = "Monty Python"
>>> age = 25
>>> message = (
...     f"Hi {name}. "
...     f"You are a {profession}. "
...     f"You were in {affiliation}."
... )
>>> message
```

1.  以下内容的输出将是什么？

```py
str1 = 'Hello'
str2 ='World!'
print('str1 + str2 = ', str1 + str2)
print('str1 * 3 =', str1 * 3)
```

# 进一步阅读

1.  `string`文档：[`docs.python.org/3.1/library/string.html`](https://docs.python.org/3.1/library/string.html)

1.  `smptplib`文档：[`docs.python.org/3/library/smtplib.html`](https://docs.python.org/3/library/smtplib.html)


# 第九章：处理各种文件

在这一章中，您将学习如何处理各种类型的文件，如 PDF 文件、Excel 文件、CSV 文件和`txt`文件。Python 有用于在这些文件上执行操作的模块。您将学习如何使用 Python 打开、编辑和获取这些文件中的数据。

在本章中，将涵盖以下主题：

+   处理 PDF 文件

+   处理 Excel 文件

+   处理 CSV 文件

+   处理`txt`文件

# 处理 PDF 文件

在本节中，我们将学习如何使用 Python 模块处理 PDF 文件。PDF 是一种广泛使用的文档格式，PDF 文件的扩展名为`.pdf`。Python 有一个名为`PyPDF2`的模块，对`pdf`文件进行各种操作非常有用。它是一个第三方模块，是作为 PDF 工具包构建的 Python 库。

我们必须首先安装这个模块。要安装`PyPDF2`，请在终端中运行以下命令：

```py
pip3 install PyPDF2
```

现在，我们将看一些操作来处理 PDF 文件，比如读取 PDF、获取页面数、提取文本和旋转 PDF 页面。

# 阅读 PDF 文档并获取页面数

在本节中，我们将使用`PyPDF2`模块读取 PDF 文件。此外，我们将获取该 PDF 的页面数。该模块有一个名为`PdfFileReader()`的函数，可以帮助读取 PDF 文件。确保您的系统中有一个 PDF 文件。现在，我在我的系统中有`test.pdf`文件，所以我将在本节中使用这个文件。在`test.pdf`的位置输入您的 PDF 文件名。创建一个名为`read_pdf.py`的脚本，并在其中编写以下内容：

```py
import PyPDF2 with open('test.pdf', 'rb') as pdf:
 read_pdf= PyPDF2.PdfFileReader(pdf)
    print("Number of pages in pdf : ", read_pdf.numPages)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 read_pdf.py
```

以下是输出：

```py
Number of pages in pdf :  20
```

在前面的示例中，我们使用了`PyPDF2`模块。接下来，我们创建了一个`pdf`文件对象。`PdfFileReader()`将读取创建的对象。读取 PDF 文件后，我们将使用`numPages`属性获取该`pdf`文件的页面数。在这种情况下，有`20`页。

# 提取文本

要提取`pdf`文件的页面，`PyPDF2`模块有`extractText()`方法。创建一个名为`extract_text.py`的脚本，并在其中编写以下内容：

```py
import PyPDF2 with open('test.pdf', 'rb') as pdf:
 read_pdf = PyPDF2.PdfFileReader(pdf) pdf_page = read_pdf.getPage(1) pdf_content = pdf_page.extractText() print(pdf_content) 
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 extract_text.py
```

以下是输出：

```py
3Pythoncommands 9 3.1Comments........................................ .9 3.2Numbersandotherdatatypes........................ ......9 3.2.1The type function................................9 3.2.2Strings....................................... 10 3.2.3Listsandtuples................................ ..10 3.2.4The range function................................11 3.2.5Booleanvalues................................. .11 3.3Expressions..................................... ...11 3.4Operators.......................................
```

在前面的示例中，我们创建了一个文件阅读器对象。`pdf`阅读器对象有一个名为`getPage()`的函数，它以页面编号（从第 0 页开始）作为参数，并返回页面对象。接下来，我们使用`extractText()`方法，它将从我们在`getPage()`中提到的页面编号中提取文本。页面索引从`0`开始。

# 旋转 PDF 页面

在本节中，我们将看到如何旋转 PDF 页面。为此，我们将使用`PDF`对象的`rotate.Clockwise()`方法。创建一个名为`rotate_pdf.py`的脚本，并在其中编写以下内容：

```py
import PyPDF2

with open('test.pdf', 'rb') as pdf:
 rd_pdf = PyPDF2.PdfFileReader(pdf)
 wr_pdf = PyPDF2.PdfFileWriter()
 for pg_num in range(rd_pdf.numPages):
 pdf_page = rd_pdf.getPage(pg_num)
 pdf_page.rotateClockwise(90)
 wr_pdf.addPage(pdf_page)

 with open('rotated.pdf', 'wb') as pdf_out:
 wr_pdf.write(pdf_out)

print("pdf successfully rotated")
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 rotate_pdf.py
```

以下是输出：

```py
pdf successfully rotated
```

在前面的示例中，为了旋转`pdf`，我们首先创建了原始`pdf`文件的`pdf`文件阅读器对象。然后旋转的页面将被写入一个新的`pdf`文件。因此，为了写入新的`pdf`，我们使用`PyPDF2`模块的`PdfFileWriter()`函数。新的`pdf`文件将以名称`rotated.pdf`保存。现在，我们将使用`rotateClockwise()`方法旋转`pdf`文件的页面。然后，使用`addPage()`方法将页面添加到旋转后的`pdf`中。现在，我们必须将这些`pdf`页面写入新的`pdf`文件。因此，首先我们必须打开新的文件对象（`pdf_out`），并使用`pdf`写入对象的`write()`方法将`pdf`页面写入其中。在所有这些之后，我们将关闭原始（`test.pdf`）文件对象和新的（`pdf_out`）文件对象。

# 处理 Excel 文件

在本节中，我们将处理具有`.xlsx`扩展名的 Excel 文件。这个文件扩展名是用于 Microsoft Excel 使用的一种开放的 XML 电子表格文件格式。

Python 有不同的模块：`xlrd`，pandas 和`openpyxl`用于处理 Excel 文件。在本节中，我们将学习如何使用这三个模块处理 Excel 文件。

首先，我们将看一个使用`xlrd`模块的例子。`xlrd`模块用于读取、写入和修改 Excel 电子表格以及执行大量工作。

# 使用 xlrd 模块

首先，我们必须安装`xlrd`模块。在终端中运行以下命令以安装`xlrd`模块：

```py
   pip3 install xlrd
```

注意：确保您的系统中有一个 Excel 文件。我在我的系统中有`sample.xlsx`。所以我将在本节中始终使用该文件。

我们将学习如何读取 Excel 文件以及如何从 Excel 文件中提取行和列。

# 读取 Excel 文件

在本节中，我们将学习如何读取 Excel 文件。我们将使用`xlrd`模块。创建一个名为`read_excel.py`的脚本，并在其中写入以下内容：

```py
import xlrd excel_file = (r"/home/student/sample.xlsx") book_obj = xlrd.open_workbook(excel_file) excel_sheet = book_obj.sheet_by_index(0) result = excel_sheet.cell_value(0, 1)
print(result)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 read_excel.py
```

以下是输出：

```py
First Name
```

在前面的例子中，我们导入了`xlrd`模块来读取 Excel 文件。我们还提到了 Excel 文件的位置。然后，我们创建了一个文件对象，然后我们提到了索引值，以便从该索引开始阅读。最后，我们打印了结果。

# 提取列名

在本节中，我们正在从 Excel 表中提取列名。创建一个名为`extract_column_names.py`的脚本，并在其中写入以下内容：

```py
import xlrd excel_file = ("/home/student/work/sample.xlsx") book_obj = xlrd.open_workbook(excel_file) excel_sheet = book_obj.sheet_by_index(0) excel_sheet.cell_value(0, 0) for i in range(excel_sheet.ncols):
 print(excel_sheet.cell_value(0, i))
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 extract_column_names.py
```

以下是输出：

```py
Id First Name Last Name Gender Age Country
```

在前面的例子中，我们正在从 Excel 表中提取列名。我们使用`ncols`属性获取了列名。

# 使用 pandas

在使用 Pandas 读取 Excel 文件之前，我们首先必须安装`pandas`模块。我们可以使用以下命令安装`pandas`：

```py
 pip3 install pandas
```

注意：确保您的系统中有一个 Excel 文件。我在我的系统中有`sample.xlsx`。所以我将在本节中始终使用该文件。

现在，我们将看一些使用`pandas`的例子。

# 读取 Excel 文件

在本节中，我们将使用`pandas`模块读取 Excel 文件。现在，让我们看一个读取 Excel 文件的例子。

创建一个名为`rd_excel_pandas.py`的脚本，并在其中写入以下内容：

```py
import pandas as pd 
excel_file = 'sample.xlsx'
df = pd.read_excel(excel_file)
print(df.head())
```

运行上述脚本，您将获得以下输出：

```py
student@ubuntu:~/test$ python3 rd_excel_pandas.py
```

以下是输出：

```py
 OrderDate     Region  ...   Unit Cost     Total
0  2014-01-09   Central  ...    125.00      250.00
1   6/17/15     Central    ...  125.00      625.00
2  2015-10-09   Central    ...    1.29        9.03
3  11/17/15     Central   ...     4.99       54.89
4  10/31/15     Central   ...     1.29       18.06
```

在前面的例子中，我们正在使用`pandas`模块读取 Excel 文件。首先，我们导入了`pandas`模块。然后，我们创建了一个名为`excel_file`的字符串，用于保存要打开的文件的名称，我们希望使用 pandas 进行操作。随后，我们创建了一个`df 数据框`对象。在这个例子中，我们使用了 pandas 的`read_excel`方法来从 Excel 文件中读取数据。读取从索引零开始。最后，我们打印了`pandas`数据框。

# 在 Excel 文件中读取特定列

当我们使用 pandas 模块使用`read_excel`方法读取 Excel 文件时，我们还可以读取该文件中的特定列。要读取特定列，我们需要在`read_excel`方法中使用`usecols`参数。

现在，让我们看一个示例，读取 Excel 文件中的特定列。创建一个名为`rd_excel_pandas1.py`的脚本，并在其中写入以下内容：

```py
import pandas as pd

excel_file = 'sample.xlsx'
cols = [1, 2, 3]
df = pd.read_excel(excel_file , sheet_names='sheet1', usecols=cols)

print(df.head())
```

运行上述脚本，您将获得以下输出：

```py
student@ubuntu:~/test$ python3 rd_excel_pandas1.py
```

以下是输出：

```py
 Region      Rep    Item
0  Central    Smith    Desk
1  Central   Kivell    Desk
2  Central     Gill  Pencil
3  Central  Jardine  Binder
4  Central  Andrews  Pencil
```

在前面的例子中，首先我们导入了 pandas 模块。然后，我们创建了一个名为`excel_file`的字符串来保存文件名。然后我们定义了`cols`变量，并将列的索引值放在其中。因此，当我们使用`read_excel`方法时，在该方法内部，我们还提供了`usecols`参数，通过该参数可以通过之前在`cols`变量中定义的索引获取特定列。因此，在运行脚本后，我们只从 Excel 文件中获取特定列。

我们还可以使用 pandas 模块对 Excel 文件执行各种操作，例如读取具有缺失数据的 Excel 文件，跳过特定行以及读取多个 Excel 工作表。

# 使用 openpyxl

`openpyxl`是一个用于读写`xlsx`，`xlsm`，`xltx`和`xltm`文件的 Python 库。首先，我们必须安装`openpyxl`。运行以下命令：

```py
 pip3 install openpyxl
```

现在，我们将看一些使用`openpyxl`的示例。

# 创建新的 Excel 文件

在本节中，我们将学习使用`openpyxl`创建新的 Excel 文件。创建一个名为`create_excel.py`的脚本，并在其中写入以下内容：

```py
from openpyxl import Workbook book_obj = Workbook() excel_sheet = book_obj.active excel_sheet['A1'] = 'Name' excel_sheet['A2'] = 'student' excel_sheet['B1'] = 'age' excel_sheet['B2'] = '24' book_obj.save("test.xlsx") print("Excel created successfully")
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 create_excel.py
```

以下是输出：

```py
Excel created successfully
```

现在，检查您当前的工作目录，您会发现`test.xlsx`已成功创建。在前面的示例中，我们将数据写入了四个单元格。然后，从`openpyxl`模块中导入`Workbook`类。工作簿是文档的所有其他部分的容器。接下来，我们将引用对象设置为活动工作表，并在单元格`A1`，`A2`和`B1`，`B2`中写入数值。最后，我们使用`save()`方法将内容写入`test.xlsx`文件。

# 追加数值

在本节中，我们将在 Excel 中追加数值。为此，我们将使用`append()`方法。我们可以在当前工作表的底部添加一组数值。创建一个名为`append_values.py`的脚本，并在其中写入以下内容：

```py
from openpyxl import Workbookbook_obj = Workbook() excel_sheet = book_obj.active rows = (
 (11, 12, 13), (21, 22, 23), (31, 32, 33), (41, 42, 43) ) for values in rows: excel_sheet.append(values) print() print("values are successfully appended") book_obj.save('test.xlsx')wb.save('append_values.xlsx')
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 append_values.py
```

以下是输出：

```py
values are successfully appended
```

在前面的示例中，我们在`append_values.xlsx`文件的工作表中追加了三列数据。我们存储的数据是元组的元组，并且为了追加这些数据，我们逐行通过容器并使用`append()`方法插入它。

# 读取多个单元格

在本节中，我们将读取多个单元格。我们将使用`openpyxl`模块。创建一个名为`read_multiple.py`的脚本，并在其中写入以下内容：

```py
import openpyxl book_obj = openpyxl.load_workbook('sample.xlsx') excel_sheet = book_obj.active cells = excel_sheet['A1': 'C6'] for c1, c2, c3 in cells:
 print("{0:6} {1:6} {2:6}".format(c1.value, c2.value, c3.value))
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 read_multiple.py
```

以下是输出：

```py
Id     First Name Last Name
 101 John   Smith 102 Mary   Williams 103 Rakesh Sharma 104 Amit   Roy105 Sandra Ace 
```

在前面的示例中，我们使用`range`操作读取了三列数据。然后，我们从单元格`A1 – C6`中读取数据。

同样地，我们可以使用`openpyxl`模块在 Excel 文件上执行许多操作，比如合并和拆分单元格。

# 处理 CSV 文件

**CSV**格式代表**逗号分隔值**。逗号用于分隔记录中的字段。这些通常用于导入和导出电子表格和数据库的格式。

CSV 文件是使用特定类型的结构来排列表格数据的纯文本文件。Python 具有内置的`csv`模块，允许 Python 解析这些类型的文件。`csv`模块主要用于处理从电子表格以及数据库以文本文件格式导出的数据，包括字段和记录。

`csv`模块具有所有必需的内置函数，如下所示：

+   `csv.reader`：此函数用于返回一个`reader`对象，该对象迭代 CSV 文件的行

+   `csv.writer`：此函数用于返回一个`writer`对象，该对象将数据写入 CSV 文件

+   `csv.register_dialect`：此函数用于注册 CSV 方言

+   `csv.unregister_dialect`：此函数用于取消注册 CSV 方言

+   `csv.get_dialect`：此函数用于返回具有给定名称的方言

+   `csv.list_dialects`：此函数用于返回所有已注册的方言

+   `csv.field_size_limit`：此函数用于返回解析器允许的当前最大字段大小

在本节中，我们将只看`csv.reader`和`csv.writer`。

# 读取 CSV 文件

Python 具有内置模块`csv`，我们将在此处使用它来处理 CSV 文件。我们将使用`csv.reader`模块来读取 CSV 文件。创建一个名为`csv_read.py`的脚本，并在其中写入以下内容：

```py
import csv csv_file = open('test.csv', 'r') with csv_file:
 read_csv = csv.reader(csv_file) for row in read_csv: print(row)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 csv_read.py
```

以下是输出：

```py
['Region', 'Country', 'Item Type', 'Sales Channel', 'Order Priority', 'Order Date', 'Order ID', 'Ship Date', 'Units Sold'] ['Sub-Saharan Africa', 'Senegal', 'Cereal', 'Online', 'H', '4/18/2014', '616607081', '5/30/2014', '6593'] ['Asia', 'Kyrgyzstan', 'Vegetables', 'Online', 'H', '6/24/2011', '814711606', '7/12/2011', '124'] ['Sub-Saharan Africa', 'Cape Verde', 'Clothes', 'Offline', 'H', '8/2/2014', '939825713', '8/19/2014', '4168'] ['Asia', 'Bangladesh', 'Clothes', 'Online', 'L', '1/13/2017', '187310731', '3/1/2017', '8263'] ['Central America and the Caribbean', 'Honduras', 'Household', 'Offline', 'H', '2/8/2017', '522840487', '2/13/2017', '8974'] ['Asia', 'Mongolia', 'Personal Care', 'Offline', 'C', '2/19/2014', '832401311', '2/23/2014', '4901'] ['Europe', 'Bulgaria', 'Clothes', 'Online', 'M', '4/23/2012', '972292029', '6/3/2012', '1673'] ['Asia', 'Sri Lanka', 'Cosmetics', 'Offline', 'M', '11/19/2016', '419123971', '12/18/2016', '6952'] ['Sub-Saharan Africa', 'Cameroon', 'Beverages', 'Offline', 'C', '4/1/2015', '519820964', '4/18/2015', '5430'] ['Asia', 'Turkmenistan', 'Household', 'Offline', 'L', '12/30/2010', '441619336', '1/20/2011', '3830']
```

在上述程序中，我们将`test.csv`文件作为`csv_file`打开。然后，我们使用`csv.reader()`函数将数据提取到`reader`对象中，我们可以迭代以获取数据的每一行。现在，我们将看一下第二个函数`csv.Writer()`

# 写入 CSV 文件

要在`csv`文件中写入数据，我们使用`csv.writer`模块。在本节中，我们将一些数据存储到 Python 列表中，然后将该数据放入`csv`文件中。创建一个名为`csv_write.py`的脚本，并在其中写入以下内容：

```py
import csv write_csv = [['Name', 'Sport'], ['Andres Iniesta', 'Football'], ['AB de Villiers', 'Cricket'], ['Virat Kohli', 'Cricket'], ['Lionel Messi', 'Football']] with open('csv_write.csv', 'w') as csvFile:
 writer = csv.writer(csvFile) writer.writerows(write_csv) print(write_csv)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 csv_write.py
```

以下是输出：

```py
[['Name', 'Sport'], ['Andres Iniesta', 'Football'], ['AB de Villiers', 'Cricket'], ['Virat Kohli', 'Cricket'], ['Lionel Messi', 'Football']]
```

在上述程序中，我们创建了一个名为`write_csv`的列表，其中包含`Name`和`Sport`。然后，在创建列表后，我们打开了新创建的`csv_write.csv`文件，并使用`csvWriter()`函数将`write_csv`列表插入其中。

# 处理 txt 文件

纯文本文件用于存储仅表示字符或字符串的数据，并且不考虑任何结构化元数据。在 Python 中，无需导入任何外部库来读写文本文件。Python 提供了一个内置函数来创建、打开、关闭、写入和读取文本文件。为了执行操作，有不同的访问模式来管理在打开文件中可能的操作类型。

Python 中的访问模式如下：

+   **仅读取模式（`'r'`）**：此模式打开文本文件以供读取。如果文件不存在，它会引发 I/O 错误。我们也可以称此模式为文件将打开的默认模式。

+   **读写模式（`'r+'`）**：此模式打开文本文件以供读取和写入，并在文件不存在时引发 I/O 错误。

+   **仅写入模式（`'w'`）**：此模式将打开文本文件以供写入。如果文件不存在，则创建文件，并且对于现有文件，数据将被覆盖。

+   **写入和读取模式（`'w+'`）**：此模式将打开文本文件以供读取和写入。对于现有文件，数据将被覆盖。

+   **仅追加模式（`'a'`）**：此模式将打开文本文件以供写入。如果文件不存在，则创建文件，并且数据将被插入到现有数据的末尾。

+   **追加和读取模式（`'a+'`）**：此模式将打开文本文件以供读取和写入。如果文件不存在，则会创建文件，并且数据将被插入到现有数据的末尾。

# `open()`函数

此函数用于打开文件，不需要导入任何外部模块。

语法如下：

```py
 Name_of_file_object = open("Name of file","Access_Mode")
```

对于前面的语法，文件必须在我们的 Python 程序所在的相同目录中。如果文件不在同一目录中，那么在打开文件时我们还必须定义文件路径。这种情况的语法如下所示：

```py
Name_of_file_object = open("/home/……/Name of file","Access_Mode")
```

# 文件打开

打开文件的`open`函数为`"test.txt"`。

文件与`追加`模式相同的目录中：

```py
text_file = open("test.txt","a")
```

如果文件不在相同的目录中，我们必须在`追加`模式中定义路径：

```py
text_file = open("/home/…../test.txt","a")
```

# close()函数

此函数用于关闭文件，释放文件获取的内存。当文件不再需要或将以不同的文件模式打开时使用此函数。

语法如下：

```py
 Name_of_file_object.close()
```

以下代码语法可用于简单地打开和关闭文件：

```py
#Opening and closing a file test.txt:
text_file = open("test.txt","a") text_file.close()
```

# 写入文本文件

通过使用 Python，您可以创建一个文本文件（`test.txt`）。通过使用代码，写入文本文件很容易。要打开一个文件进行写入，我们将第二个参数设置为访问模式中的`"w"`。要将数据写入`test.txt`文件，我们使用`file handle`对象的`write()`方法。创建一个名为`text_write.py`的脚本，并在其中写入以下内容：

```py
text_file = open("test.txt", "w") text_file.write("Monday\nTuesday\nWednesday\nThursday\nFriday\nSaturday\n") text_file.close()
```

运行上述脚本，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/6620eefb-81eb-459b-b9b1-8c43968a5850.jpg)

现在，检查您的当前工作目录。您会发现一个我们创建的`test.txt`文件。现在，检查文件的内容。您会发现我们在`write()`函数中写入的日期将保存在`test.txt`中。

在上述程序中，我们声明了`text_file`变量来打开名为`test.txt`的文件。`open`函数接受两个参数：第一个是我们要打开的文件，第二个是表示我们要在文件上执行的权限或操作的访问模式。在我们的程序中，我们在第二个参数中使用了`"w"`字母，表示写入。然后，我们使用`text_file.close()`来关闭存储的`test.txt`文件的实例。

# 读取文本文件

读取文件和写入文件一样容易。要打开一个文件进行读取，我们将第二个参数即访问模式设置为`"r"`，而不是`"w"`。要从该文件中读取数据，我们使用`文件句柄`对象的`read()`方法。创建一个名为`text_read.py`的脚本，并在其中写入以下内容：

```py
text_file = open("test.txt", "r") data = text_file.read() print(data) text_file.close()
```

以下是输出：

```py
student@ubuntu:~$ python3 text_read.py Monday Tuesday Wednesday Thursday Friday Saturday
```

在上述程序中，我们声明了`text_file`变量来打开名为`test.txt`的文件。`open`函数接受两个参数：第一个是我们要打开的文件，第二个是表示我们要在文件上执行的权限或操作的访问模式。在我们的程序中，我们在第二个参数中使用了`"r"`字母，表示读取操作。然后，我们使用`text_file.close()`来关闭存储的`test.txt`文件的实例。运行 Python 程序后，我们可以在终端中轻松看到文本文件中的内容。

# 总结

在本章中，我们学习了各种文件。我们学习了 PDF、Excel、CSV 和文本文件。我们使用 Python 模块对这些类型的文件执行了一些操作。

在下一章中，我们将学习 Python 中的基本网络和互联网模块。

# 问题

1.  `readline()`和`readlines()`之间有什么区别？

1.  `open()`和`with open()`之间有什么区别？

1.  `r c:\\Downloads`的意义是什么？

1.  生成器对象是什么？

1.  `pass`的用途是什么？

1.  什么是 lambda 表达式？

# 进一步阅读

+   XLRD：[`xlrd.readthedocs.io/en/latest/api.html`](https://xlrd.readthedocs.io/en/latest/api.html)

+   `openoyxl`：[`www.python-excel.org/`](http://www.python-excel.org/)

+   关于生成器概念：[`wiki.python.org/moin/Generators`](https://wiki.python.org/moin/Generators)


# 第十章：基本网络 - 套接字编程

在本章中，您将学习套接字和三种互联网协议：`http`，`ftplib`和`urllib`。您还将学习 Python 中用于网络的`socket`模块。`http`是一个用于处理**超文本传输协议**（**HTTP**）的包。`ftplib`模块用于执行自动化的与 FTP 相关的工作。`urllib`是一个处理与 URL 相关的工作的包。

在本章中，您将学习以下内容：

+   套接字

+   `http`包

+   `ftplib`模块

+   `urllib`包

# 套接字

在本节中，我们将学习套接字。我们将使用 Python 的 socket 模块。套接字是用于机器之间通信的端点，无论是在本地还是通过互联网。套接字模块有一个套接字类，用于处理数据通道。它还具有用于网络相关任务的函数。要使用套接字模块的功能，我们首先需要导入套接字模块。

让我们看看如何创建套接字。套接字类有一个套接字函数，带有两个参数：`address_family` 和 `socket 类型`。

以下是语法：

```py
 import socket            s = socket.socket(address_family, socket type)
```

`address_family` 控制 OSI 网络层协议。

**`socket 类型`** 控制传输层协议。

Python 支持三种地址族：`AF_INET`，`AF_INET6`和`AF_UNIX`。最常用的是`AF_INET`，用于互联网寻址。`AF_INET6`用于 IPv6 互联网寻址。`AF_UNIX`用于**Unix 域套接字**（**UDS**），这是一种进程间通信协议。

有两种套接字类型：`SOCK_DGRAM` 和 `SOCK_STREAM`。`SOCK_DGRAM` 套接字类型用于面向消息的数据报传输；这些与 UDP 相关联。数据报套接字传递单个消息。`SOCK_STREAM` 用于面向流的传输；这些与 TCP 相关联。流套接字在客户端和服务器之间提供字节流。

套接字可以配置为服务器套接字和客户端套接字。当 TCP/IP 套接字都连接时，通信将是双向的。现在我们将探讨一个客户端-服务器通信的示例。我们将创建两个脚本：`server.py`和`client.py`。

`server.py`脚本如下：

```py
import socket host_name = socket.gethostname() port = 5000 s_socket = socket.socket() s_socket.bind((host_name, port)) s_socket.listen(2) conn, address = s_socket.accept() print("Connection from: " + str(address)) while True:
 recv_data = conn.recv(1024).decode() if not recv_data: break print("from connected user: " + str(recv_data)) recv_data = input(' -> ') conn.send(recv_data.encode()) conn.close()
```

现在我们将为客户端编写一个脚本。

`client.py`脚本如下：

```py
import socket host_name = socket.gethostname() port = 5000 c_socket = socket.socket() c_socket.connect((host_name, port)) msg = input(" -> ")  while msg.lower().strip() != 'bye': c_socket.send(msg.encode()) recv_data = c_socket.recv(1024).decode() print('Received from server: ' + recv_data) msg = input(" -> ") c_socket.close()
```

现在我们将在两个不同的终端中运行这两个程序。在第一个终端中，我们将运行`server.py`，在第二个终端中，运行`client.py`。

输出将如下所示：

| **终端 1：** `python3 server.py` | **终端 2：** `python3 client.py` |
| --- | --- |
| `student@ubuntu:~/work$ python3 server.py``连接来自：（'127.0.0.1'，35120）``来自连接的用户：来自客户端的问候`` -> 来自服务器的问候！` | `student@ubuntu:~/work$ python3 client.py``-> 来自客户端的问候``从服务器接收：来自服务器的问候！`` ->` |

# http 包

在本节中，我们将学习`http`包。`http`包有四个模块：

+   `http.client`：这是一个低级 HTTP 协议客户端

+   `http.server`：这包含基本的 HTTP 服务器类

+   `http.cookies`：这用于使用 cookie 实现状态管理

+   `http.cookiejar`：此模块提供 cookie 持久性

在本节中，我们将学习`http.client`和`http.server`模块。

# http.client 模块

我们将看到两个`http`请求：`GET` 和 `POST`。我们还将建立一个`http`连接。

首先，我们将探讨一个创建`http`连接的示例。为此，创建一个`make_connection.py`脚本，并在其中编写以下内容：

```py
import http.client con_obj = http.client.HTTPConnection('Enter_URL_name', 80, timeout=20) print(con_obj)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~/work$ python3 make_connection.py <http.client.HTTPConnection object at 0x7f2c365dd898>
```

在上面的示例中，我们使用了指定超时的端口 80 上的 URL 建立了连接。

现在我们将看到`http`的`GET`请求方法；使用这个`GET`请求方法，我们将看到一个示例，其中我们获得响应代码以及头列表。创建一个`get_example.py`脚本，并在其中编写以下内容：

```py
import http.client con_obj = http.client.HTTPSConnection("www.imdb.com") con_obj.request("GET", "/") response = con_obj.getresponse()  print("Status: {}".format(response.status))  headers_list = response.getheaders()
print("Headers: {}".format(headers_list))  con_obj.close()
```

按照以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 get_example.py
```

输出应该如下：

```py
Status: 200 Headers: [('Server', 'Server'), ('Date', 'Fri, 23 Nov 2018 09:49:12 GMT'), ('Content-Type', 'text/html;charset=UTF-8'), ('Transfer-Encoding', 'chunked'), ('Connection', 'keep-alive'), ('X-Frame-Options', 'SAMEORIGIN'), ('Content-Security-Policy', "frame-ancestors 'self' imdb.com *.imdb.com *.media-imdb.com withoutabox.com *.withoutabox.com amazon.com *.amazon.com amazon.co.uk *.amazon.co.uk amazon.de *.amazon.de translate.google.com images.google.com www.google.com www.google.co.uk search.aol.com bing.com www.bing.com"), ('Ad-Unit', 'imdb.home.homepage'), ('Entity-Id', ''), ('Section-Id', 'homepage'), ('Page-Id', 'homepage'), ('Content-Language', 'en-US'), ('Set-Cookie', 'uu=BCYsgIz6VTPefAjQB9YlJiZhwogwHmoU3sLx9YK-A61kPgvXEKwHSJKU3XeaxIoL8DBQGhYLuFvR%0D%0AqPV6VVvx70AV6eL_sGzVaRQQAKf-PUz2y0sTx9H4Yvib9iSYRPOzR5qHQkwuoHPKmpu2KsSbPaCb%0D%0AYbc-R6nz9ObkbQf6RAYm5sTAdf5lSqM2ZzCEhfIt_H3tWQqnK5WlihYwfMZS2AJdtGXGRnRvEHlv%0D%0AyA4Dcn9NyeX44-hAnS64zkDfDeGXoCUic_kH6ZnD5vv21HOiVodVKA%0D%0A; Domain=.imdb.com; Expires=Wed, 11-Dec-2086 13:03:18 GMT; Path=/; Secure'), ('Set-Cookie', 'session-id=134-6809939-6044806; Domain=.imdb.com; Expires=Wed, 11-Dec-2086 13:03:18 GMT; Path=/; Secure'), ('Set-Cookie', 'session-id-time=2173686551; Domain=.imdb.com; Expires=Wed, 11-Dec-2086 13:03:18 GMT; Path=/; Secure'), ('Vary', 'Accept-Encoding,X-Amzn-CDN-Cache,User-Agent'), ('x-amz-rid', '7SWEYTYH4TX8YR2CF5JT')]
```

在前面的示例中，我们使用了`HTTPSConnection`，因为该网站是通过`HTTPS`协议提供的。您可以根据您使用的网站使用`HTTPSConnection`或`HTTPConnection`。我们提供了一个 URL，并使用连接对象检查了状态。之后，我们得到了一个标题列表。这个标题列表包含了从服务器返回的数据类型的信息。`getheaders()`方法将获取标题列表。

现在我们将看到一个`POST`请求的示例。我们可以使用`HTTP POST`将数据发布到 URL。为此，创建一个`post_example.py`脚本，并在其中写入以下内容：

```py
import http.client import json con_obj = http.client.HTTPSConnection('www.httpbin.org') headers_list = {'Content-type': 'application/json'} post_text = {'text': 'Hello World !!'} json_data = json.dumps(post_text) con_obj.request('POST', '/post', json_data, headers_list) response = con_obj.getresponse() print(response.read().decode())
```

按照以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 post_example.py
```

您应该得到以下输出：

```py
{
 "args": {}, "data": "{\"text\": \"Hello World !!\"}", "files": {}, "form": {}, "headers": { "Accept-Encoding": "identity", "Connection": "close", "Content-Length": "26", "Content-Type": "application/json", "Host": "www.httpbin.org" }, "json": { "text": "Hello World !!" }, "origin": "1.186.106.115", "url": "https://www.httpbin.org/post" }
```

在前面的示例中，我们首先创建了一个`HTTPSConnection`对象。接下来，我们创建了一个`post_text`对象，它发布了`Hello World`。之后，我们写了一个`POST`请求，得到了一个响应。

# http.server 模块

在本节中，我们将学习`http`包中的一个模块，即`http.server`模块。这个模块定义了用于实现`HTTP`服务器的类。它有两种方法：`GET`和`HEAD`。通过使用这个模块，我们可以在网络上共享文件。您可以在任何端口上运行`http`服务器。确保端口号大于`1024`。默认端口号是`8000`。

您可以按照以下方式使用`http.server`。

首先，导航到您想要的目录，然后运行以下命令：

```py
student@ubuntu:~/Desktop$ python3 -m http.server 9000
```

现在打开您的浏览器，在地址栏中输入`localhost:9000`，然后按*Enter*。您将得到以下输出：

```py
student@ubuntu:~/Desktop$ python3 -m http.server 9000 Serving HTTP on 0.0.0.0 port 9000 (http://0.0.0.0:9000/) ... 127.0.0.1 - - [23/Nov/2018 16:08:14] code 404, message File not found 127.0.0.1 - - [23/Nov/2018 16:08:14] "GET /Downloads/ HTTP/1.1" 404 - 127.0.0.1 - - [23/Nov/2018 16:08:14] code 404, message File not found 127.0.0.1 - - [23/Nov/2018 16:08:14] "GET /favicon.ico HTTP/1.1" 404 - 127.0.0.1 - - [23/Nov/2018 16:08:21] "GET / HTTP/1.1" 200 - 127.0.0.1 - - [23/Nov/2018 16:08:21] code 404, message File not found 127.0.0.1 - - [23/Nov/2018 16:08:21] "GET /favicon.ico HTTP/1.1" 404 - 127.0.0.1 - - [23/Nov/2018 16:08:26] "GET /hello/ HTTP/1.1" 200 - 127.0.0.1 - - [23/Nov/2018 16:08:26] code 404, message File not found 127.0.0.1 - - [23/Nov/2018 16:08:26] "GET /favicon.ico HTTP/1.1" 404 - 127.0.0.1 - - [23/Nov/2018 16:08:27] code 404, message File not found 127.0.0.1 - - [23/Nov/2018 16:08:27] "GET /favicon.ico HTTP/1.1" 404 -
```

# ftplib 模块

`ftplib`是 Python 中的一个模块，它提供了执行 FTP 协议的各种操作所需的所有功能。`ftplib`包含 FTP 客户端类，以及一些辅助函数。使用这个模块，我们可以轻松地连接到 FTP 服务器，检索多个文件并处理它们。通过导入`ftplib`模块，我们可以使用它提供的所有功能。

在本节中，我们将介绍如何使用`ftplib`模块进行 FTP 传输。我们将看到各种 FTP 对象。

# 下载文件

在本节中，我们将学习如何使用`ftplib`模块从另一台机器下载文件。为此，创建一个`get_ftp_files.py`脚本，并在其中写入以下内容：

```py
import os
from ftplib import FTP ftp = FTP('your-ftp-domain-or-ip')
with ftp:
 ftp.login('your-username','your-password') ftp.cwd('/home/student/work/') files = ftp.nlst()
    print(files) # Print the files for file in files:
        if os.path.isfile(file): print("Downloading..." + file) ftp.retrbinary("RETR " + file ,open("/home/student/testing/" + file, 'wb').write) ftp.close()
```

按照以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 get_ftp_files.py
```

您应该得到以下输出：

```py
Downloading...hello Downloading...hello.c Downloading...sample.txt Downloading...strip_hello Downloading...test.py
```

在前面的示例中，我们使用`ftplib`模块从主机检索了多个文件。首先，我们提到了另一台机器的 IP 地址、用户名和密码。为了从主机获取所有文件，我们使用了`ftp.nlst()`函数，为了将这些文件下载到我们的计算机，我们使用了`ftp.retrbinary()`函数。

# 使用 getwelcome()获取欢迎消息：

一旦建立了初始连接，服务器通常会返回一个欢迎消息。这条消息通过`getwelcome()`函数传递，有时包括免责声明或对用户相关的有用信息。

现在我们将看到一个`getwelcome()`的示例。创建一个`get_welcome_msg.py`脚本，并在其中写入以下内容：

```py
from ftplib import FTP ftp = FTP('your-ftp-domain-or-ip') ftp.login('your-username','your-password') welcome_msg = ftp.getwelcome() print(welcome_msg) ftp.close()
```

按照以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 get_welcome_msg.py 220 (vsFTPd 3.0.3)
```

在前面的代码中，我们首先提到了另一台机器的 IP 地址、用户名和密码。我们使用了`getwelcome()`函数在建立初始连接后获取信息。

# 使用 sendcmd()函数向服务器发送命令

在本节中，我们将学习`sendcmd()`函数。我们可以使用`sendcmd()`函数向服务器发送一个简单的`string`命令以获取字符串响应。客户端可以发送 FTP 命令，如`STAT`、`PWD`、`RETR`和`STOR`。`ftplib`模块有多个方法可以包装这些命令。这些命令可以使用`sendcmd()`或`voidcmd()`方法发送。例如，我们将发送一个`STAT`命令来检查服务器的状态。

创建一个`send_command.py`脚本，并在其中写入以下内容：

```py
from ftplib import FTP ftp = FTP('your-ftp-domain-or-ip') ftp.login('your-username','your-password') ftp.cwd('/home/student/') s_cmd_stat = ftp.sendcmd('STAT') print(s_cmd_stat) print() s_cmd_pwd = ftp.sendcmd('PWD') print(s_cmd_pwd) print() ftp.close()
```

运行脚本如下：

```py
student@ubuntu:~/work$ python3 send_command.py
```

您将获得以下输出：

```py
211-FTP server status:
 Connected to ::ffff:192.168.2.109 Logged in as student TYPE: ASCII No session bandwidth limit Session timeout in seconds is 300 Control connection is plain text Data connections will be plain text At session startup, client count was 1 vsFTPd 3.0.3 - secure, fast, stable 211 End of status
257 "/home/student" is the current directory
```

在上面的代码中，我们首先提到了另一台机器的 IP 地址，用户名和密码。接下来，我们使用`sendcmd()`方法发送`STAT`命令到另一台机器。然后，我们使用`sendcmd()`发送`PWD`命令。

# urllib 包

像`http`一样，`urllib`也是一个包，其中包含用于处理 URL 的各种模块。`urllib`模块允许您通过脚本访问多个网站。我们还可以使用该模块下载数据，解析数据，修改标头等。

`urllib`有一些不同的模块，列在这里：

+   `urllib.request`：用于打开和读取 URL。

+   `urllib.error`：包含`urllib.request`引发的异常。

+   `urllib.parse`：用于解析 URL。

+   `urllib.robotparser`：用于解析`robots.txt`文件。

在本节中，我们将学习如何使用`urllib`打开 URL 以及如何从 URL 读取`html`文件。我们将看到一个简单的`urllib`使用示例。我们将导入`urllib.requests`。然后我们将打开 URL 的操作赋给一个变量，然后我们将使用`.read()`命令从 URL 读取数据。

创建一个`url_requests_example.py`脚本，并在其中写入以下内容：

```py
import urllib.request x = urllib.request.urlopen('https://www.imdb.com/') print(x.read())
```

运行脚本如下：

```py
student@ubuntu:~/work$ python3 url_requests_example.py
```

以下是输出：

```py
b'\n\n<!DOCTYPE html>\n<html\n    \n    >\n    <head>\n         \n        <meta charset="utf-8">\n        <meta http-equiv="X-UA-Compatible" content="IE=edge">\n\n    \n    \n    \n\n    \n    \n    \n\n    <meta name="apple-itunes-app" content="app-id=342792525, app-argument=imdb:///?src=mdot">\n\n\n\n        <script type="text/javascript">var IMDbTimer={starttime: new Date().getTime(),pt:\'java\'};</script>\n\n<script>\n    if (typeof uet == \'function\') {\n      uet("bb", "LoadTitle", {wb: 1});\n    }\n</script>\n  <script>(function(t){ (t.events = t.events || {})["csm_head_pre_title"] = new Date().getTime(); })(IMDbTimer);</script>\n        <title>IMDb - Movies, TV and Celebrities - IMDb</title>\n  <script>(function(t){ (t.events = t.events || {})["csm_head_post_title"] = new Date().getTime(); })(IMDbTimer);</script>\n<script>\n    if (typeof uet == \'function\') {\n      uet("be", "LoadTitle", {wb: 1});\n    }\n</script>\n<script>\n    if (typeof uex == \'function\') {\n      uex("ld", "LoadTitle", {wb: 1});\n    }\n</script>\n\n        <link rel="canonical" href="https://www.imdb.com/" />\n        <meta property="og:url" content="http://www.imdb.com/" />\n        <link rel="alternate" media="only screen and (max-width: 640px)" href="https://m.imdb.com/">\n\n<script>\n    if (typeof uet == \'function\') {\n      uet("bb", "LoadIcons", {wb: 1});\n    }\n</script>\n  <script>(function(t){ (t.events = t.events || {})["csm_head_pre_icon"] = new Date().getTime(); })(IMDbTimer);</script>\n        <link href="https://m.media-amazon.com/images/G/01/imdb/images/safari-favicon-517611381._CB483525257_.svg" mask rel="icon" sizes="any">\n        <link rel="icon" type="image/ico" href="https://m.media-amazon.com/images/G/01/imdb/images/favicon-2165806970._CB470047330_.ico" />\n        <meta name="theme-color" content="#000000" />\n        <link rel="shortcut icon" type="image/x-icon" href="https://m.media-amazon.com/images/G/01/imdb/images/desktop-favicon-2165806970._CB484110913_.ico" />\n        <link href="https://m.media-amazon.com/images/G/01/imdb/images/mobile/apple-touch-icon-web-4151659188._CB483525313_.png" rel="apple-touch-icon"> \n
```

在上面的示例中，我们使用了`read()`方法，该方法返回字节数组。这会以非人类可读的格式打印`Imdb`主页返回的 HTML 数据，但我们可以使用 HTML 解析器从中提取一些有用的信息。

# Python urllib 响应标头

我们可以通过在响应对象上调用`info()`函数来获取响应标头。这将返回一个字典，因此我们还可以从响应中提取特定的标头数据。创建一个`url_response_header.py`脚本，并在其中写入以下内容：

```py
import urllib.request x = urllib.request.urlopen('https://www.imdb.com/') print(x.info())
```

运行脚本如下：

```py
student@ubuntu:~/work$ python3 url_response_header.py
```

以下是输出：

```py
Server: Server Date: Fri, 23 Nov 2018 11:22:48 GMT Content-Type: text/html;charset=UTF-8 Transfer-Encoding: chunked Connection: close X-Frame-Options: SAMEORIGIN Content-Security-Policy: frame-ancestors 'self' imdb.com *.imdb.com *.media-imdb.com withoutabox.com *.withoutabox.com amazon.com *.amazon.com amazon.co.uk *.amazon.co.uk amazon.de *.amazon.de translate.google.com images.google.com www.google.com www.google.co.uk search.aol.com bing.com www.bing.com Content-Language: en-US Set-Cookie: uu=BCYsJu-IKhmmXuZWHgogzgofKfB8CXXLkNXdfKrrvsCP-RkcSn29epJviE8uRML4Xl4E7Iw9V09w%0D%0Anl3qKv1bEVJ-hHWVeDFH6BF8j_MMf8pdVA2NWzguWQ2XbKvDXFa_rK1ymzWc-Q35RCk_Z6jTj-Mk%0D%0AlEMrKkFyxbDYxLMe4hSjUo7NGrmV61LY3Aohaq7zE-ZE8a6DhgdlcLfXsILNXTkv7L3hvbxmr4An%0D%0Af73atPNPOgyLTB2S615MnlZ3QpOeNH6E2fElDYXZnsIFEAb9FW2XfQ%0D%0A; Domain=.imdb.com; Expires=Wed, 11-Dec-2086 14:36:55 GMT; Path=/; Secure Set-Cookie: session-id=000-0000000-0000000; Domain=.imdb.com; Expires=Wed, 11-Dec-2086 14:36:55 GMT; Path=/; Secure Set-Cookie: session-id-time=2173692168; Domain=.imdb.com; Expires=Wed, 11-Dec-2086 14:36:55 GMT; Path=/; Secure Vary: Accept-Encoding,X-Amzn-CDN-Cache,User-Agent x-amz-rid: GJDGQQTNA4MH7S3KJJKV
```

# 总结

在本章中，我们学习了套接字，用于双向客户端-服务器通信。我们学习了三个互联网模块：`http`，`ftplib`和`urllib`。`http`包具有客户端和服务器的模块：`http.client`和`http.server`。使用`ftplib`，我们从另一台机器下载文件。我们还查看了欢迎消息和发送`send`命令。

在下一章中，我们将介绍构建和发送电子邮件。我们将学习有关消息格式和添加多媒体内容。此外，我们将学习有关 SMTP，POP 和 IMAP 服务器的知识。

# 问题

1.  什么是套接字编程？

1.  什么是 RPC？

1.  导入用户定义模块或文件的不同方式是什么？

1.  列表和元组之间有什么区别？

1.  字典中是否可以有重复的键？

1.  `urllib`，`urllib2`和`requests`模块之间有什么区别？

# 进一步阅读

+   `ftplib`文档：[`docs.python.org/3/library/ftplib.html`](https://docs.python.org/3/library/ftplib.html)

+   `xmlrpc`文档：[`docs.python.org/3/library/xmlrpc.html`](https://docs.python.org/3/library/xmlrpc.html)


# 第十一章：使用 Python 脚本处理电子邮件

在本章中，您将学习如何使用 Python 脚本处理电子邮件。您将学习电子邮件消息格式。我们将探索`smtplib`模块用于发送和接收电子邮件。我们将使用 Python 电子邮件包发送带有附件和 HTML 内容的电子邮件。您还将学习用于处理电子邮件的不同协议。

在本章中，您将学习以下内容：

+   电子邮件消息格式

+   添加 HTML 和多媒体内容

+   POP3 和 IMAP 服务器

# 电子邮件消息格式

在本节中，我们将学习电子邮件消息格式。电子邮件消息由三个主要组件组成：

+   接收者的电子邮件地址

+   发件人的电子邮件地址

+   消息

消息格式中还包括其他组件，如主题行、电子邮件签名和附件。

现在，我们将看一个简单的例子，从您的 Gmail 地址发送纯文本电子邮件，在其中您将学习如何编写电子邮件消息并发送它。现在，请创建一个名为`write_email_message.py`的脚本，并在其中编写以下内容：

```py
import smtplib import getpass host_name = "smtp.gmail.com" port = 465 sender = 'sender_emil_id'
receiver = 'receiver_email_id' password = getpass.getpass() msg = """\ Subject: Test Mail Hello from Sender !!""" s = smtplib.SMTP_SSL(host_name, port) s.login(sender, password) s.sendmail(sender, receiver, msg) s.quit() print("Mail sent successfully")
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work/Chapter_11$ python3 write_email_message.py Output: Password: Mail sent successfully
```

在上面的例子中，我们使用了`smtplib` Python 模块来发送电子邮件。确保您从 Gmail ID 向接收者发送电子邮件。`sender`变量保存了发件人的电子邮件地址。在`password`变量中，您可以输入密码，或者您可以使用`getpass`模块提示输入密码。在这里，我们提示输入密码。接下来，我们创建了一个名为`msg`的变量，这将是我们实际的电子邮件消息。在其中，我们首先提到了一个主题，然后是我们想要发送的消息。然后，在`login()`中，我们提到了`sender`和`password`变量。接下来，在`sendmail()`中，我们提到了`sender`，`receivers`和`text`变量。因此，通过这个过程，我们成功地发送了电子邮件。

# 添加 HTML 和多媒体内容

在本节中，我们将看到如何将多媒体内容作为附件发送以及如何添加 HTML 内容。为此，我们将使用 Python 的`email`包。

首先，我们将看如何添加 HTML 内容。为此，请创建一个名为`add_html_content.py`的脚本，并在其中编写以下内容：

```py
import os import smtplib from email.mime.text import MIMEText from email.mime.multipart import MIMEMultipart import getpass host_name = 'smtp.gmail.com' port = 465 sender = '*sender_emailid*' password = getpass.getpass() receiver = '*receiver_emailid*' text = MIMEMultipart() text['Subject'] = 'Test HTML Content' text['From'] = sender text['To'] = receiver msg = """\ <html>
 <body> <p>Hello there, <br> Good day !!<br> <a href="http://www.imdb.com">Home</a> </p> </body> </html> """ html_content = MIMEText(msg, "html") text.attach(html_content) s = smtplib.SMTP_SSL(host_name, port) print("Mail sent successfully !!")  s.login(sender, password) s.sendmail(sender, receiver, text.as_string()) s.quit()
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work/Chapter_11$ python3 add_html_content.py Output: Password: Mail sent successfully !!
```

在上面的例子中，我们使用了电子邮件包通过 Python 脚本发送 HTML 内容作为消息。我们创建了一个`msg`变量，其中存储了 HTML 内容。

现在，我们将看如何添加附件并通过 Python 脚本发送它。为此，请创建一个名为`add_attachment.py`的脚本，并在其中编写以下内容：

```py
import os import smtplib from email.mime.text import MIMEText from email.mime.image import MIMEImage from email.mime.multipart import MIMEMultipart import getpass host_name = 'smtp.gmail.com' port = 465 sender = '*sender_emailid*' password = getpass.getpass() receiver = '*receiver_emailid*' text = MIMEMultipart() text['Subject'] = 'Test Attachment' text['From'] = sender text['To'] = receiver txt = MIMEText('Sending a sample image.') text.attach(txt) f_path = 'path_of_file' with open(f_path, 'rb') as f:
 img = MIMEImage(f.read()) img.add_header('Content-Disposition',
 'attachment', filename=os.path.basename(f_path)) text.attach(img) s = smtplib.SMTP_SSL(host_name, port) print("Attachment sent successfully !!") s.login(sender, password) s.sendmail(sender, receiver, text.as_string()) s.quit()
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work/Chapter_11$ python3 add_attachment.py Output: Password: Attachment sent successfully !!
```

在上面的例子中，我们将一张图片作为附件发送给接收者。我们提到了发件人和收件人的电子邮件 ID。接下来，在`f_path`中，我们提到了我们要发送的图片的路径。接下来，我们将该图片作为附件发送给接收者。

# POP3 和 IMAP 服务器

在本节中，您将学习如何通过 POP 和 IMAP 服务器接收电子邮件。Python 提供了`poplib`和`imaplib`库，用于通过 Python 脚本接收电子邮件。

# 使用 poplib 库接收电子邮件

**POP3**代表**邮局协议第 3 版**。这个标准协议帮助您从远程服务器接收电子邮件到我们的本地计算机。POP3 的主要优势在于它允许我们将电子邮件下载到本地计算机上，并离线阅读已下载的电子邮件。

POP3 协议在两个端口上运行：

+   端口`110`：默认的非加密端口

+   端口`995`：加密端口

现在，我们将看一些例子。首先，我们将看一个例子，其中我们收到了一些电子邮件。为此，请创建一个名为`number_of_emails.py`的脚本，并在其中编写以下内容：

```py
import poplib import getpass pop3_server = 'pop.gmail.com' username = 'Emaild_address'
password = getpass.getpass()
email_obj = poplib.POP3_SSL(pop3_server) print(email_obj.getwelcome()) email_obj.user(username) email_obj.pass_(password) email_stat = email_obj.stat() print("New arrived e-Mails are : %s (%s bytes)" % email_stat)
```

运行脚本，如下所示：

```py
student@ubuntu:~$ python3 number_of_emails.py
```

作为输出，您将得到邮箱中存在的电子邮件数量。

在上面的示例中，首先我们导入了`poplib`库，该库用于 Python 的 POP3 协议，以安全地接收电子邮件。然后，我们声明了特定的电子邮件服务器和我们的电子邮件凭据，即我们的用户名和密码。之后，我们打印来自服务器的响应消息，并向 POP3 SSL 服务器提供用户名和密码。登录后，我们获取邮箱统计信息并将其以电子邮件数量的形式打印到终端。

现在，我们将编写一个脚本来获取最新的电子邮件。为此，请创建一个名为`latest_email.py`的脚本，并在其中编写以下内容：

```py
import poplib
import getpass pop3_server = 'pop.gmail.com' username = 'Emaild_address' password = getpass.getpass() email_obj = poplib.POP3_SSL(pop3_server) print(email_obj.getwelcome()) email_obj.user(username) email_obj.pass_(password) print("\nLatest Mail\n") latest_email = email_obj.retr(1) print(latest_email[1])
```

运行脚本，如下所示：

```py
student@ubuntu:~$ python3 latest_email.py
```

作为输出，您将获得您收件箱中收到的最新邮件。

在上面的示例中，我们导入了用于 Python 的`poplib`库，以安全地提供 POP3 协议以接收电子邮件。在声明了特定的电子邮件服务器和用户名和密码之后，我们打印了来自服务器的响应消息，并向 POP3 SSL 服务器提供了用户名和密码。然后，我们从邮箱中获取了最新的电子邮件。

现在，我们将编写一个脚本来获取所有的电子邮件。为此，请创建一个名为`all_emails.py`的脚本，并在其中编写以下内容：

```py
import poplib
import getpass pop3_server = 'pop.gmail.com' username = 'Emaild_address' password = getpass.getpass() email_obj = poplib.POP3_SSL(pop3_server) print(email_obj.getwelcome()) email_obj.user(username) email_obj.pass_(password) email_stat = email_obj.stat() NumofMsgs = email_stat[0] for i in range(NumofMsgs):
 for mail in email_obj.retr(i+1)[1]: print(mail)
```

运行脚本，如下所示：

```py
student@ubuntu:~$ python3 latest_email.py
```

作为输出，您将获得您收件箱中收到的所有电子邮件。

# 使用 imaplib 库接收电子邮件

IMAP 代表 Internet 消息访问协议。它用于通过本地计算机访问远程服务器上的电子邮件。IMAP 允许多个客户端同时访问您的电子邮件。当您通过不同位置访问电子邮件时，IMAP 更适用。

IMAP 协议在两个端口上运行：

+   端口`143`：默认非加密端口

+   端口`993`：加密端口

现在，我们将看到使用`imaplib`库的示例。创建一个名为`imap_email.py`的脚本，并在其中编写以下内容：

```py
import imaplib import pprint
import getpass imap_server = 'imap.gmail.com' username = 'Emaild_address'
password = getpass.getpass()imap_obj = imaplib.IMAP4_SSL(imap_server) imap_obj.login(username, password) imap_obj.select('Inbox') temp, data_obj = imap_obj.search(None, 'ALL') for data in data_obj[0].split():
 temp, data_obj = imap_obj.fetch(data, '(RFC822)') print('Message: {0}\n'.format(data)) pprint.pprint(data_obj[0][1]) break imap_obj.close()
```

运行脚本，如下所示：

```py
student@ubuntu:~$ python3 imap_email.py
```

作为输出，您将获得指定文件夹中的所有电子邮件。

在上面的示例中，首先我们导入了`imaplib`库，该库用于 Python 通过 IMAP 协议安全地接收电子邮件。然后，我们声明了特定的电子邮件服务器和我们的用户凭据，即我们的用户名和密码。之后，我们向 IMAP SSL 服务器提供了用户名和密码。我们使用`'select('Inbox')'`函数在`imap_obj`上显示收件箱中的消息。然后，我们使用`for`循环逐个显示已获取的消息。为了显示消息，我们使用“pretty print”——即`pprint.pprint()`函数——因为它会格式化您的对象，将其写入数据流，并将其作为参数传递。最后，连接被关闭。

# 摘要

在本章中，我们学习了如何在 Python 脚本中编写电子邮件消息。我们还学习了 Python 的`smtplib`模块，该模块用于通过 Python 脚本发送和接收电子邮件。我们还学习了如何通过 POP3 和 IMAP 协议接收电子邮件。Python 提供了`poplib`和`imaplib`库，我们可以使用这些库执行任务。

在下一章中，您将学习有关 Telnet 和 SSH 的知识。

# 问题

1.  POP3 和 IMAP 是什么？

1.  break 和 continue 分别用于什么？给出一个适当的例子。

1.  pprint 是什么？

1.  什么是负索引，为什么要使用它们？

1.  `pyc`和`py`文件扩展名之间有什么区别？

1.  使用循环生成以下模式：

```py
 1010101
 10101 
 101 
 1  
```


# 第十二章：Telnet 和 SSH 上的主机远程监控

在本章中，您将学习如何在配置了 Telnet 和 SSH 的服务器上进行基本配置。我们将首先使用 Telnet 模块，然后使用首选方法实现相同的配置：使用 Python 中的不同模块进行 SSH。您还将了解`telnetlib`、`subprocess`、`fabric`、`Netmiko`和`paramiko`模块的工作原理。在本章中，您必须具备基本的网络知识。

在本章中，我们将涵盖以下主题：

+   `telnetlib()`模块

+   `subprocess.Popen()`模块

+   使用 fabric 模块的 SSH

+   使用 Paramiko 库的 SSH

+   使用 Netmiko 库的 SSH

# telnetlib()模块

在本节中，我们将学习有关 Telnet 协议，然后我们将使用`telnetlib`模块在远程服务器上执行 Telnet 操作。

Telnet 是一种网络协议，允许用户与远程服务器通信。网络管理员通常使用它来远程访问和管理设备。要访问设备，请在终端中使用 Telnet 命令和远程服务器的 IP 地址或主机名。

Telnet 在默认端口号`23`上使用 TCP。要使用 Telnet，请确保它已安装在您的系统上。如果没有，请运行以下命令进行安装：

```py
$ sudo apt-get install telnetd
```

要使用简单的终端运行 Telnet，您只需输入以下命令：

```py
$ telnet ip_address_of_your_remote_server
```

Python 具有`telnetlib`模块，可通过 Python 脚本执行 Telnet 功能。在对远程设备或路由器进行 Telnet 之前，请确保它们已正确配置，如果没有，您可以通过在路由器的终端中使用以下命令进行基本配置：

```py
configure terminal
enable password 'set_Your_password_to_access_router'
username 'set_username' password 'set_password_for_remote_access'
line vty 0 4 
login local 
transport input all 
interface f0/0 
ip add 'set_ip_address_to_the_router' 'put_subnet_mask'
no shut 
end 
show ip interface brief 
```

现在，让我们看一下远程设备的 Telnet 示例。为此，请创建一个`telnet_example.py`脚本，并在其中写入以下内容：

```py
import telnetlib
import getpass
import sys

HOST_IP = "your host ip address"
host_user = input("Enter your telnet username: ")
password = getpass.getpass()

t = telnetlib.Telnet(HOST_IP)
t.read_until(b"Username:")
t.write(host_user.encode("ascii") + b"\n")
if password:
 t.read_until(b"Password:") t.write(password.encode("ascii") + b"\n")

t.write(b"enable\n")
t.write(b"enter_remote_device_password\n") #password of your remote device
t.write(b"conf t\n")
t.write(b"int loop 1\n")
t.write(b"ip add 10.1.1.1 255.255.255.255\n") t.write(b"int loop 2\n") t.write(b"ip add 20.2.2.2 255.255.255.255\n") t.write(b"end\n") t.write(b"exit\n") print(t.read_all().decode("ascii") )
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 telnet_example.py Output: Enter your telnet username: student Password: 

server>enable Password: server#conf t Enter configuration commands, one per line.  End with CNTL/Z. server(config)#int loop 1 server(config-if)#ip add 10.1.1.1 255.255.255.255 server(config-if)#int loop 23 server(config-if)#ip add 20.2.2.2 255.255.255.255 server(config-if)#end server#exit
```

在前面的示例中，我们使用`telnetlib`模块访问并配置了 Cisco 路由器。在此脚本中，首先我们从用户那里获取用户名和密码，以初始化与远程设备的 Telnet 连接。当连接建立时，我们对远程设备进行了进一步的配置。Telnet 之后，我们将能够访问远程服务器或设备。但是 Telnet 协议有一个非常重要的缺点，那就是所有数据，包括用户名和密码都以文本方式通过网络发送，这可能会造成安全风险。因此，现在 Telnet 很少使用，并已被一个名为安全外壳（SSH）的非常安全的协议所取代。

# SSH

SSH 是一种网络协议，用于通过远程访问管理设备或服务器。SSH 使用公钥加密来确保安全。Telnet 和 SSH 之间的重要区别在于 SSH 使用加密，这意味着所有通过网络传输的数据都受到未经授权的实时拦截的保护。

用户访问远程服务器或设备必须安装 SSH 客户端。通过在终端中运行以下命令来安装 SSH：

```py
$ sudo apt install ssh
```

此外，在用户希望通信的远程服务器上，必须安装并运行 SSH 服务器。SSH 使用 TCP 协议，默认情况下在端口号`22`上运行。

您可以通过终端运行`ssh`命令如下：

```py
$ ssh host_name@host_ip_address
```

现在，您将学习如何使用 Python 中的不同模块进行 SSH，例如 subprocess、fabric、Netmiko 和 Paramiko。现在，我们将依次看到这些模块。

# subprocess.Popen()模块

`Popen`类处理进程的创建和管理。使用此模块，开发人员可以处理较少的常见情况。子程序执行将在新进程中完成。要在 Unix/Linux 上执行子程序，该类将使用`os.execvp()`函数。要在 Windows 中执行子程序，该类将使用`CreateProcess()`函数。

现在，让我们看一些`subprocess.Popen()`的有用参数：

```py
class subprocess.Popen(args, bufsize=0, executable=None, stdin=None, stdout=None,
 stderr=None, preexec_fn=None, close_fds=False, shell=False, cwd=None, env=None, universal_newlines=False, startupinfo=None, creationflags=0)
```

让我们看看每个参数：

+   `args`：它可以是程序参数的序列或单个字符串。如果`args`是一个序列，则将执行 args 中的第一项。如果 args 是一个字符串，则建议将 args 作为序列传递。

+   `shell`：shell 参数默认设置为`False`，它指定是否使用 shell 来执行程序。如果 shell 为`True`，则建议将 args 作为字符串传递。在 Linux 中，如果`shell=True`，shell 默认为`/bin/sh`。如果`args`是一个字符串，则该字符串指定要通过 shell 执行的命令。

+   `bufsize`：如果`bufsize`为`0`（默认为`0`），则表示无缓冲，如果`bufsize`为`1`，则表示行缓冲。如果`bufsize`是任何其他正值，则使用给定大小的缓冲区。如果`bufsize`是任何其他负值，则表示完全缓冲。

+   `executable`：它指定要执行的替换程序。

+   `stdin`、`stdout`和`stderr`：这些参数分别定义了标准输入、标准输出和标准错误。

+   `preexec_fn`：这是设置为可调用对象的，将在子进程中执行之前调用。

+   `close_fds`：在 Linux 中，如果`close_fds`为 true，则在执行子进程之前，除了`0`、`1`和`2`之外的所有文件描述符都将被关闭。在 Windows 中，如果`close_fds`为`true`，则子进程将不会继承任何句柄。

+   `env`：如果值不是`None`，则映射将为新进程定义环境变量。

+   `universal_newlines`：如果值为`True`，则`stdout`和`stderr`将以换行模式打开为文本文件。

现在，我们将看一个`subprocess.Popen()`的例子。为此，创建一个`ssh_using_sub.py`脚本，并在其中写入以下内容：

```py
import subprocess
import sys

HOST="your host username@host ip"
COMMAND= "ls"

ssh_obj = subprocess.Popen(["ssh", "%s" % HOST, COMMAND],
 shell=False,
 stdout=subprocess.PIPE,
 stderr=subprocess.PIPE)

result = ssh_obj.stdout.readlines()
if result == []:
 err = ssh_obj.stderr.readlines()
 print(sys.stderr, "ERROR: %s" % err)
else:
 print(result)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~$ python3 ssh_using_sub.py Output : student@192.168.0.106's password: [b'Desktop\n', b'Documents\n', b'Downloads\n', b'examples.desktop\n', b'Music\n', b'Pictures\n', b'Public\n', b'sample.py\n', b'spark\n', b'spark-2.3.1-bin-hadoop2.7\n', b'spark-2.3.1-bin-hadoop2.7.tgz\n', b'ssh\n', b'Templates\n', b'test_folder\n', b'test.txt\n', b'Untitled1.ipynb\n', b'Untitled.ipynb\n', b'Videos\n', b'work\n']
```

在前面的例子中，首先我们导入了 subprocess 模块，然后定义了要建立 SSH 连接的主机地址。之后，我们给出了一个在远程设备上执行的简单命令。在所有这些设置完成后，我们将这些信息放入`subprocess.Popen()`函数中。该函数执行函数内定义的参数，以创建与远程设备的连接。建立 SSH 连接后，执行我们定义的命令并提供结果。然后我们在终端上打印 SSH 的结果，如输出所示。

# 使用 fabric 模块的 SSH

Fabric 是一个 Python 库，也是一个用于 SSH 的命令行工具。它用于系统管理和应用程序在网络上的部署。我们还可以通过 SSH 执行 shell 命令。

要使用 fabric 模块，首先您必须使用以下命令安装它：

```py
$ pip3 install fabric3
```

现在，我们将看一个例子。创建一个`fabfile.py`脚本，并在其中写入以下内容：

```py
from fabric.api import * env.hosts=["host_name@host_ip"] env.password='your password'  def dir(): run('mkdir fabric') print('Directory named fabric has been created on your host network') def diskspace():
 run('df') 
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~$ fab dir Output: [student@192.168.0.106] Executing task 'dir' [student@192.168.0.106] run: mkdir fabric
Done. Disconnecting from 192.168.0.106... done.
```

在前面的例子中，首先我们导入了`fabric.api`模块，然后设置了主机名和密码以连接到主机网络。之后，我们设置了不同的任务以通过 SSH 执行。因此，为了执行我们的程序而不是 Python3 的`fabfile.py`，我们使用了`fab`实用程序（`fab dir`），然后我们声明应该从我们的`fabfile.py`执行所需的任务。在我们的情况下，我们执行了`dir`任务，在您的远程网络上创建了一个名为`'fabric'`的目录。您可以在您的 Python 文件中添加您的特定任务。它可以使用 fabric 模块的`fab`实用程序执行。

# 使用 Paramiko 库的 SSH

Paramiko 是一个实现 SSHv2 协议用于远程设备安全连接的库。Paramiko 是围绕 SSH 的纯 Python 接口。

在使用 Paramiko 之前，请确保您已经在系统上正确安装了它。如果尚未安装，可以通过在终端中运行以下命令来安装它：

```py
$ sudo pip3 install paramiko
```

现在，我们将看一个使用`paramiko`的例子。对于这个`paramiko`连接，我们使用的是 Cisco 设备。Paramiko 支持基于密码和基于密钥对的身份验证，以确保与服务器的安全连接。在我们的脚本中，我们使用基于密码的身份验证，这意味着我们检查密码，如果可用，将尝试使用普通用户名/密码身份验证。在对远程设备或多层路由器进行 SSH 之前，请确保它们已经正确配置，如果没有，您可以使用以下命令在多层路由器终端中进行基本配置：

```py
configure t
ip domain-name cciepython.com
crypto key generate rsa
How many bits in the modulus [512]: 1024
interface range f0/0 - 1
switchport mode access
switchport access vlan 1
no shut
int vlan 1
ip add 'set_ip_address_to_the_router' 'put_subnet_mask'
no shut
exit
enable password 'set_Your_password_to_access_router'
username 'set_username' password 'set_password_for_remote_access'
username 'username' privilege 15
line vty 0 4
login local
transport input all
end
```

现在，创建一个`pmiko.py`脚本，并在其中写入以下内容：

```py
import paramiko
import time

ip_address = "host_ip_address"
usr = "host_username"
pwd = "host_password"

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(hostname=ip_address,username=usr,password=pwd)

print("SSH connection is successfully established with ", ip_address)
rc = c.invoke_shell() for n in range (2,6):
 print("Creating VLAN " + str(n)) rc.send("vlan database\n") rc.send("vlan " + str(n) +  "\n") rc.send("exit\n") time.sleep(0.5) time.sleep(1) output = rc.recv(65535) print(output) c.close
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~$ python3 pmiko.py Output: SSH connection is successfuly established with  192.168.0.70 Creating VLAN 2 Creating VLAN 3 Creating VLAN 4 Creating VLAN 5
```

在上面的例子中，首先我们导入了`paramiko`模块，然后定义了连接到远程设备所需的 SSH 凭据。提供凭据后，我们创建了`paramiko.SSHclient()`的实例`'c'`，这是用于与远程设备建立连接并执行命令或操作的主要客户端。创建`SSHClient`对象允许我们使用`.connect()`函数建立远程连接。然后，我们设置了`paramiko`连接的策略，因为默认情况下，`paramiko.SSHclient`将 SSH 策略设置为拒绝策略状态。这会导致策略拒绝任何未经验证的 SSH 连接。在我们的脚本中，我们使用`AutoAddPolicy()`函数来忽略 SSH 连接中断的可能性，该函数会自动添加服务器的主机密钥而无需提示。我们只能在测试目的中使用此策略，但出于安全目的，这不是生产环境中的好选择。

当建立 SSH 连接时，您可以在设备上进行任何配置或操作。在这里，我们在远程设备上创建了一些虚拟局域网。创建 VLAN 后，我们只是关闭了连接。

# 使用 Netmiko 库进行 SSH

在本节中，我们将学习 Netmiko。Netmiko 库是 Paramiko 的高级版本。它是一个基于 Paramiko 的`multi_vendor`库。Netmiko 简化了与网络设备的 SSH 连接，并对设备进行特定操作。在对远程设备或多层路由器进行 SSH 之前，请确保它们已经正确配置，如果没有，您可以使用 Paramiko 部分中提到的命令进行基本配置。

现在，让我们看一个例子。创建一个`nmiko.py`脚本，并在其中写入以下代码：

```py
from netmiko import ConnectHandler

remote_device={
 'device_type': 'cisco_ios',
 'ip':  'your remote_device ip address',
 'username': 'username',
 'password': 'password',
}

remote_connection = ConnectHandler(**remote_device)
#net_connect.find_prompt()

for n in range (2,6):
 print("Creating VLAN " + str(n))
 commands = ['exit','vlan database','vlan ' + str(n), 'exit']
 output = remote_connection.send_config_set(commands)
 print(output)

command = remote_connection.send_command('show vlan-switch brief')
print(command)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~$ python3 nmiko.py Output: Creating VLAN 2 config term Enter configuration commands, one per line.  End with CNTL/Z. server(config)#exit server #vlan database server (vlan)#vlan 2 VLAN 2 modified: server (vlan)#exit APPLY completed. Exiting.... server # .. .. .. .. switch# Creating VLAN 5 config term Enter configuration commands, one per line.  End with CNTL/Z. server (config)#exit server #vlan database server (vlan)#vlan 5 VLAN 5 modified: server (vlan)#exit APPLY completed. Exiting.... VLAN Name                             Status    Ports ---- -------------------------------- --------- ------------------------------- 1    default                          active    Fa0/0, Fa0/1, Fa0/2, Fa0/3, Fa0/4, Fa0/5, Fa0/6, Fa0/7, Fa0/8, Fa0/9, Fa0/10, Fa0/11, Fa0/12, Fa0/13, Fa0/14, Fa0/15 2    VLAN0002                         active 3    VLAN0003                         active 4    VLAN0004                         active 5    VLAN0005                         active 1002 fddi-default                    active 1003 token-ring-default         active 1004 fddinet-default               active 1005 trnet-default                    active
```

在上面的例子中，我们使用 Netmiko 库来进行 SSH，而不是 Paramiko。在这个脚本中，首先我们从 Netmiko 库中导入`ConnectHandler`，然后通过传递设备字典（在我们的情况下是`remote_device`）来建立与远程网络设备的 SSH 连接。连接建立后，我们执行配置命令，使用`send_config_set()`函数创建了多个虚拟局域网。

当我们使用这种类型（`.send_config_set()`）的函数在远程设备上传递命令时，它会自动将我们的设备设置为配置模式。在发送配置命令后，我们还传递了一个简单的命令来获取有关配置设备的信息。

# 摘要

在本章中，您学习了 Telnet 和 SSH。您还学习了不同的 Python 模块，如 telnetlib、subprocess、fabric、Netmiko 和 Paramiko，使用这些模块可以执行 Telnet 和 SSH。SSH 使用公钥加密以确保安全，并且比 Telnet 更安全。

在下一章中，我们将使用各种 Python 库，您可以使用这些库创建图形用户界面。

# 问题

1.  什么是客户端-服务器架构？

1.  如何在 Python 代码中运行特定于操作系统的命令？

1.  局域网和虚拟局域网之间有什么区别？

1.  以下代码的输出是什么？

```py
 List = [‘a’, ‘b’, ‘c’, ‘d’, ‘e’]
 Print(list [10:])
```

1.  编写一个 Python 程序来显示日历（提示：使用`calendar`模块）。

1.  编写一个 Python 程序来计算文本文件中的行数。

# 进一步阅读

+   Paramiko 文档：[`github.com/paramiko/paramiko`](https://github.com/paramiko/paramiko)

+   Fabric 文档：[`www.fabfile.org/`](http://www.fabfile.org/)


# 第十三章：构建图形用户界面

在本章中，您将学习**图形用户界面**（**GUI**）开发。有各种 Python 库可用于创建 GUI。我们将学习 PyQt5 Python 库用于 GUI 创建。

在本章中，您将学习以下主题：

+   GUI 简介

+   使用库创建基于 GUI 的应用程序

+   安装和使用 Apache Log Viewer 应用程序

# GUI 简介

在本节中，我们将学习 GUI。Python 有各种 GUI 框架。在本节中，我们将看看 PyQt5。PyQt5 具有不同的图形组件，也称为对象小部件，可以显示在屏幕上并与用户交互。以下是这些组件的列表：

+   **PyQt5 窗口**：PyQt5 窗口将创建一个简单的应用程序窗口。

+   **PyQt5 按钮**：PyQt5 按钮是一个在点击时会引发动作的按钮。

+   **PyQt5 文本框**：PyQt5 文本框小部件允许用户输入文本。

+   **PyQt5 标签**：PyQt5 标签小部件显示单行文本或图像。

+   **PyQt5 组合框**：PyQt5 组合框小部件是一个组合按钮和弹出列表。

+   **PyQt5 复选框**：PyQt5 复选框小部件是一个可以选中和取消选中的选项按钮。

+   **PyQt5 单选按钮**：PyQt5 单选按钮小部件是一个可以选中或取消选中的选项按钮。在一组单选按钮中，只能同时选中一个按钮。

+   **PyQt5 消息框**：PyQt5 消息框小部件显示一条消息。

+   **PyQt5 菜单**：PyQt5 菜单小部件提供显示的不同选择。

+   **PyQt5 表格**：PyQt5 表格小部件为应用程序提供标准表格显示功能，可以构建具有多行和列的表格。

+   **PyQt5 信号/槽**：信号将让您对发生的事件做出反应，而槽只是在信号发生时调用的函数。

+   **PyQt5 布局**：PyQt5 布局由多个小部件组成。

有几个 PyQt5 类可用，分为不同的模块。这些模块在这里列出：

+   `QtGui`：`QtGui`包含用于事件处理、图形、字体、文本和基本图像的类。

+   `QtWidgets`：`QtWidgets`包含用于创建桌面样式用户界面的类。

+   `QtCore`：`QtCore`包含核心非 GUI 功能，如时间、目录、文件、流、URL、数据类型、线程和进程。

+   `QtBluetooth`：`QtBluetooth`包含用于连接设备和与其交互的类。

+   `QtPositioning`：`QtPositioning`包含用于确定位置的类。

+   `QtMultimedia`：`QtMultimedia`包含用于 API 和多媒体内容的类。

+   `QtNetwork`：`QtNetwork`包含用于网络编程的类。

+   `QtWebKit`：`QtWebkit`包含用于 Web 浏览器实现的类。

+   `QtXml`：`QtXml`包含用于 XML 文件的类。

+   `QtSql`：`QtSql`包含用于数据库的类。

GUI 由事件驱动。现在，什么是事件？事件是指示程序中发生了某些事情的信号，例如菜单选择、鼠标移动或按钮点击。事件由函数处理，并在用户对对象执行某些操作时触发。监听器将监听事件，然后在事件发生时调用事件处理程序。

# 使用库创建基于 GUI 的应用程序

现在，我们实际上将使用 PyQt5 库创建一个简单的 GUI 应用程序。在本节中，我们将创建一个简单的窗口。在该窗口中，我们将有一个按钮和一个标签。单击该按钮后，标签中将打印一些消息。

首先，我们将看看如何创建按钮小部件。以下行将创建一个按钮小部件：

```py
            b = QPushButton('Click', self)
```

现在，我们将看看如何创建标签。以下行将创建一个标签：

```py
 l = QLabel(self)
```

现在，我们将看到如何创建按钮和标签，以及如何在点击按钮后执行操作。为此，创建一个`print_message.py`脚本，并在其中编写以下代码：

```py
import sys from PyQt5.QtWidgets import QApplication, QLabel, QPushButton, QWidget from PyQt5.QtCore import pyqtSlot from PyQt5.QtGui import QIcon class simple_app(QWidget):
 def __init__(self): super().__init__() self.title = 'Main app window' self.left = 20 self.top = 20 self.height = 300 self.width = 400 self.app_initialize() def app_initialize(self): self.setWindowTitle(self.title) self.setGeometry(self.left, self.top, self.height, self.width) b = QPushButton('Click', self) b.setToolTip('Click on the button !!') b.move(100,70) self.l = QLabel(self) self.l.resize(100,50) self.l.move(100,200) b.clicked.connect(self.on_click) self.show() @pyqtSlot() def on_click(self):self.l.setText("Hello World") if __name__ == '__main__':
 appl = QApplication(sys.argv) ex = simple_app() sys.exit(appl.exec_())
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/gui_example$ python3 print_message.py
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/27a93e6c-9702-455c-870f-af942561b795.jpg)

在上面的例子中，我们导入了必要的 PyQt5 模块。然后，我们创建了应用程序。`QPushButton`创建了小部件，我们输入的第一个参数是将在按钮上打印的文本。接下来，我们有一个`QLabel`小部件，我们在上面打印一条消息，当我们点击按钮时将打印出来。接下来，我们创建了一个`on_click()`函数，它将在点击按钮后执行打印操作。`on_click()`是我们创建的槽。

现在，我们将看到一个框布局的示例。为此，创建一个`box_layout.py`脚本，并在其中编写以下代码：

```py
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout appl = QApplication([]) make_window = QWidget() layout = QVBoxLayout() layout.addWidget(QPushButton('Button 1')) layout.addWidget(QPushButton('Button 2')) make_window.setLayout(l) make_window.show() appl.exec_()
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/gui_example$ python3 box_layout.py
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/f3f5d264-0cf2-42d2-b1fe-16f4e21de4d2.png)

在上面的例子中，我们创建了一个框布局。在其中，我们放置了两个按钮。这个脚本只是为了解释框布局。`l = QVBoxLayout()`将创建一个框布局。

# 安装和使用 Apache 日志查看器应用程序

由于我们已经有了 Apache 日志查看器应用程序，请从以下链接下载 Apache 日志查看器应用程序：[`www.apacheviewer.com/download/`](https://www.apacheviewer.com/download/)

下载后，在您的计算机上安装该应用程序。该应用程序可用于根据其连接状态、IP 地址等分析日志文件。因此，要分析日志文件，我们可以简单地浏览访问日志文件或错误日志文件。获得文件后，我们对日志文件应用不同的操作，例如应用筛选器，例如仅对`access.log`中的未成功连接进行排序，或者按特定 IP 地址进行筛选。

以下截图显示了 Apache 日志查看器与`access.log`文件，没有应用筛选器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/edb4c1c2-51be-400b-96a5-ab38178f7f74.jpg)

以下截图显示了应用筛选器后的 Apache 日志查看器与`access.log`文件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/c88aab5c-c72d-4f49-ba2d-810f6982760b.png)

在第一种情况下，我们取得了访问日志文件，并在 Apache 日志查看器中打开了它。我们可以很容易地看到，在 Apache 日志查看器中打开的访问文件包含各种条目，如授权和未授权的，以及它们的状态、IP 地址、请求等。然而，在第二种情况下，我们对访问日志文件应用了筛选器，以便只能看到未经授权请求的日志条目，如截图所示。

# 摘要

在本节中，我们学习了 GUI。我们学习了 GUI 中使用的组件。我们学习了 Python 中的 PyQt5 模块。使用 PyQt5 模块，我们创建了一个简单的应用程序，在点击按钮后将在标签中打印一条消息。

在下一章中，您将学习如何处理 Apache 日志文件。

# 问题

1.  什么是 GUI？

1.  Python 中的构造函数和析构函数是什么？

1.  `self`的用途是什么？

1.  比较 Tkinter、PyQt 和 wxPython。

1.  创建一个 Python 程序，将一个文件的内容复制到另一个文件中

1.  创建一个 Python 程序，读取文本文件并计算文本文件中某个字母出现的次数。

# 进一步阅读

+   Tkinter GUI 文档：[`docs.python.org/3/library/tk.html`](https://docs.python.org/3/library/tk.html)

+   PyQt GUI 文档：[`wiki.python.org/moin/PyQt`](https://wiki.python.org/moin/PyQt)


# 第十四章：使用 Apache 和其他日志文件

在本章中，您将学习有关日志文件的知识。您将学习如何解析日志文件。您还将了解为什么需要在程序中编写异常。解析不同文件的不同方法也很重要。您还将了解`ErrorLog`和`AccessLog`。最后，您将学习如何解析其他日志文件。

在本章中，您将学习以下内容：

+   解析复杂的日志文件

+   异常的需要

+   解析不同文件的技巧

+   错误日志

+   访问日志

+   解析其他日志文件

# 解析复杂的日志文件

首先，我们将研究解析复杂日志文件的概念。解析日志文件是一项具有挑战性的任务，因为大多数日志文件都是以纯文本格式，而且该格式没有遵循任何规则。这些文件可能会在不显示任何警告的情况下进行修改。用户可以决定他们将在日志文件中存储什么类型的数据以及以何种格式存储，以及谁将开发应用程序。

在进行日志解析示例或更改日志文件中的配置之前，我们首先必须了解典型日志文件中包含什么。根据这一点，我们必须决定我们将学习如何操作或从中获取信息。我们还可以在日志文件中查找常见术语，以便我们可以使用这些常见术语来获取数据。

通常，您会发现日志文件中生成的大部分内容是由应用程序容器生成的，还有系统访问状态的条目（换句话说，注销和登录）或通过网络访问的系统的条目。因此，当您的系统通过网络远程访问时，这种远程连接的条目将保存在日志文件中。让我们以这种情况为例。我们已经有一个名为`access.log`的文件，其中包含一些日志信息。

因此，让我们创建一个名为`read_apache_log.py`的脚本，并在其中写入以下内容：

```py
def read_apache_log(logfile):
 with open(logfile) as f: log_obj = f.read() print(log_obj) if __name__ == '__main__':
 read_apache_log("access.log")
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~$ python3 read_apache_log.py Output: 64.242.88.10 - - [07/Mar/2004:16:05:49 -0800] "GET /twiki/bin/edit/Main/Double_bounce_sender?topicparent=Main.ConfigurationVariables HTTP/1.1" 401 12846 64.242.88.10 - - [07/Mar/2004:16:06:51 -0800] "GET /twiki/bin/rdiff/TWiki/NewUserTemplate?rev1=1.3&rev2=1.2 HTTP/1.1" 200 4523 64.242.88.10 - - [07/Mar/2004:16:10:02 -0800] "GET /mailman/listinfo/hsdivision HTTP/1.1" 200 6291 64.242.88.10 - - [07/Mar/2004:16:11:58 -0800] "GET /twiki/bin/view/TWiki/WikiSyntax HTTP/1.1" 200 7352 64.242.88.10 - - [07/Mar/2004:16:20:55 -0800] "GET /twiki/bin/view/Main/DCCAndPostFix HTTP/1.1" 200 5253 64.242.88.10 - - [07/Mar/2004:16:23:12 -0800] "GET /twiki/bin/oops/TWiki/AppendixFileSystem?template=oopsmore&param1=1.12&param2=1.12 HTTP/1.1" 200 11382 64.242.88.10 - - [07/Mar/2004:16:24:16 -0800] "GET /twiki/bin/view/Main/PeterThoeny HTTP/1.1" 200 4924 64.242.88.10 - - [07/Mar/2004:16:29:16 -0800] "GET /twiki/bin/edit/Main/Header_checks?topicparent=Main.ConfigurationVariables HTTP/1.1" 401 12851 64.242.88.10 - - [07/Mar/2004:16:30:29 -0800] "GET /twiki/bin/attach/Main/OfficeLocations HTTP/1.1" 401 12851 64.242.88.10 - - [07/Mar/2004:16:31:48 -0800] "GET /twiki/bin/view/TWiki/WebTopicEditTemplate HTTP/1.1" 200 3732 64.242.88.10 - - [07/Mar/2004:16:32:50 -0800] "GET /twiki/bin/view/Main/WebChanges HTTP/1.1" 200 40520 64.242.88.10 - - [07/Mar/2004:16:33:53 -0800] "GET /twiki/bin/edit/Main/Smtpd_etrn_restrictions?topicparent=Main.ConfigurationVariables HTTP/1.1" 401 12851 64.242.88.10 - - [07/Mar/2004:16:35:19 -0800] "GET /mailman/listinfo/business HTTP/1.1" 200 6379 …..
```

在前面的示例中，我们创建了一个`read_apache_log`函数来读取 Apache 日志文件。在其中，我们打开了一个日志文件，然后打印了其中的日志条目。在定义了`read_apache_log()`函数之后，我们在主函数中调用了它，并传入了 Apache 日志文件的名称。在我们的案例中，Apache 日志文件的名称是`access.log`。

在`access.log`文件中读取日志条目后，现在我们将从日志文件中解析 IP 地址。为此，请创建一个名为`parse_ip_address.py`的脚本，并在其中写入以下内容：

```py
import re from collections import Counter r_e = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' with open("access.log") as f:
 print("Reading Apache log file") Apache_log = f.read() get_ip = re.findall(r_e,Apache_log) no_of_ip = Counter(get_ip) for k, v in no_of_ip.items(): print("Available IP Address in log file " + "=> " + str(k) + " " + "Count "  + "=> " + str(v))
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work/Chapter_15$ python3 parse_ip_address.py Output: Reading Apache log file Available IP Address in log file => 64.242.88.1 Count => 452 Available IP Address in log file => 213.181.81.4 Count => 1 Available IP Address in log file => 213.54.168.1 Count => 12 Available IP Address in log file => 200.160.249.6 Count => 2 Available IP Address in log file => 128.227.88.7 Count => 14 Available IP Address in log file => 61.9.4.6 Count => 3 Available IP Address in log file => 212.92.37.6 Count => 14 Available IP Address in log file => 219.95.17.5 Count => 1 3Available IP Address in log file => 10.0.0.1 Count => 270 Available IP Address in log file => 66.213.206.2 Count => 1 Available IP Address in log file => 64.246.94.1 Count => 2 Available IP Address in log file => 195.246.13.1 Count => 12 Available IP Address in log file => 195.230.181.1 Count => 1 Available IP Address in log file => 207.195.59.1 Count => 20 Available IP Address in log file => 80.58.35.1 Count => 1 Available IP Address in log file => 200.222.33.3 Count => 1 Available IP Address in log file => 203.147.138.2 Count => 13 Available IP Address in log file => 212.21.228.2 Count => 1 Available IP Address in log file => 80.58.14.2 Count => 4 Available IP Address in log file => 142.27.64.3 Count => 7 ……
```

在前面的示例中，我们创建了 Apache 日志解析器来确定服务器上一些特定 IP 地址及其请求次数。因此，很明显我们不想要 Apache 日志文件中的整个日志条目，我们只想从日志文件中获取 IP 地址。为此，我们必须定义一个模式来搜索 IP 地址，我们可以通过使用正则表达式来实现。因此，我们导入了`re`模块。然后我们导入了`Collection`模块作为 Python 内置数据类型`dict`、`list`、`set`和`tuple`的替代品。该模块具有专门的容器数据类型。在导入所需的模块后，我们使用正则表达式编写了一个模式，以匹配从日志文件中映射 IP 地址的特定条件。

在匹配模式中，`\d`可以是`0`到`9`之间的任何数字，`\r`代表原始字符串。然后，我们打开名为`access.log`的 Apache 日志文件并读取它。之后，我们在 Apache 日志文件上应用了正则表达式条件，然后使用`collection`模块的`counter`函数来获取我们根据`re`条件获取的每个 IP 地址的计数。最后，我们打印了操作的结果，如输出中所示。

# 异常的需要

在这一部分，我们将看看 Python 编程中异常的需要。正常的程序流程包括事件和信号。异常一词表明您的程序出了问题。这些异常可以是任何类型，比如零除错误、导入错误、属性错误或断言错误。这些异常会在指定的函数无法正常执行其任务时发生。一旦异常发生，程序执行就会停止，解释器将继续进行异常处理过程。异常处理过程包括在`try…except`块中编写代码。异常处理的原因是您的程序发生了意外情况。

# 分析异常

在这一部分，我们将了解分析异常。每个发生的异常都必须被处理。您的日志文件也应该包含一些异常。如果您多次遇到类似类型的异常，那么您的程序存在一些问题，您应该尽快进行必要的更改。

考虑以下例子：

```py
f = open('logfile', 'r') print(f.read()) f.close()
```

运行程序后，您将得到以下输出：

```py
Traceback (most recent call last):
 File "sample.py", line 1, in <module> f = open('logfile', 'r') FileNotFoundError: [Errno 2] No such file or directory: 'logfile'
```

在这个例子中，我们试图读取一个在我们目录中不存在的文件，结果显示了一个错误。因此，通过错误我们可以分析我们需要提供什么样的解决方案。为了处理这种情况，我们可以使用异常处理技术。所以，让我们看一个使用异常处理技术处理错误的例子。

考虑以下例子：

```py
try:
    f = open('logfile', 'r')
 print(f.read()) f.close()
except:
    print("file not found. Please check whether the file is present in your directory or not.") 
```

运行程序后，您将得到以下输出：

```py
file not found. Please check whether the file is present in your directory or not.
```

在这个例子中，我们试图读取一个在我们目录中不存在的文件。但是，在这个例子中，我们使用了文件异常技术，将我们的代码放在`try:`和`except:`块中。因此，如果在`try:`块中发生任何错误或异常，它将跳过该错误并执行`except:`块中的代码。在我们的情况下，我们只在`except:`块中放置了一个`print`语句。因此，在运行脚本后，当异常发生在`try:`块中时，它会跳过该异常并执行`except:`块中的代码。因此，在`except`块中的`print`语句会被执行，正如我们在之前的输出中所看到的。

# 解析不同文件的技巧

在这一部分，我们将学习解析不同文件时使用的技巧。在开始实际解析之前，我们必须先读取数据。您需要了解您将从哪里获取所有数据。但是，您也必须记住所有的日志文件大小都不同。为了简化您的任务，这里有一个要遵循的清单：

+   请记住，日志文件可以是纯文本或压缩文件。

+   所有日志文件都有一个`.log`扩展名的纯文本文件和一个`log.bz2`扩展名的`bzip2`文件。

+   您应该根据文件名处理文件集。

+   所有日志文件的解析必须合并成一个报告。

+   您使用的工具必须能够处理所有文件，无论是来自指定目录还是来自不同目录。所有子目录中的日志文件也应包括在内。

# 错误日志

在这一部分，我们将学习错误日志。错误日志的相关指令如下：

+   `ErrorLog`

+   `LogLevel`

服务器日志文件的位置和名称由`ErrorLog`指令设置。这是最重要的日志文件。Apache `httpd`发送的信息和处理过程中产生的记录都在其中。每当服务器出现问题时，这将是第一个需要查看的地方。它包含了出现问题的细节以及修复问题的过程。

错误日志被写入文件中。在 Unix 系统上，服务器可以将错误发送到`syslog`，或者您可以将它们传送到您的程序中。日志条目中的第一件事是消息的日期和时间。第二个条目记录了错误的严重程度。

`LogLevel`指令通过限制严重级别处理发送到错误日志的错误。第三个条目包含生成错误的客户端的信息。该信息将是 IP 地址。接下来是消息本身。它包含了服务器已配置为拒绝客户端访问的信息。服务器将报告所请求文档的文件系统路径。

错误日志文件中可能出现各种类型的消息。错误日志文件还包含来自 CGI 脚本的调试输出。无论信息写入`stderr`，都将直接复制到错误日志中。

错误日志文件是不可定制的。处理请求的错误日志中的条目将在访问日志中有相应的条目。您应该始终监视错误日志以解决测试期间的问题。在 Unix 系统上，您可以运行以下命令来完成这个任务：

```py
$ tail -f error_log
```

# 访问日志

在本节中，您将学习访问日志。服务器访问日志将记录服务器处理的所有请求。`CustomLog`指令控制访问日志的位置和内容。`LogFormat`指令用于选择日志的内容。

将信息存储在访问日志中意味着开始日志管理。下一步将是分析帮助我们获得有用统计信息的信息。Apache `httpd`有各种版本，这些版本使用了一些其他模块和指令来控制访问日志记录。您可以配置访问日志的格式。这个格式是使用格式字符串指定的。

# 通用日志格式

在本节中，我们将学习通用日志格式。以下语法显示了访问日志的配置：

```py
 LogFormat "%h %l %u %t \"%r\" %>s %b" nick_name
 CustomLog logs/access_log nick_name
```

这个字符串将定义一个昵称，然后将该昵称与日志格式字符串关联起来。日志格式字符串由百分比指令组成。每个百分比指令告诉服务器记录特定的信息。这个字符串可能包含文字字符。这些字符将直接复制到日志输出中。

`CustomLog`指令将使用定义的*昵称*设置一个新的日志文件。访问日志的文件名相对于`ServerRoot`，除非以斜杠开头。

我们之前提到的配置将以**通用日志格式**（**CLF**）写入日志条目。这是一种标准格式，可以由许多不同的 Web 服务器生成。许多日志分析程序读取这种日志格式。

现在，我们将看到每个百分比指令的含义：

+   `%h`：这显示了向 Web 服务器发出请求的客户端的 IP 地址。如果`HostnameLookups`打开，那么服务器将确定主机名并将其记录在 IP 地址的位置。

+   `%l`：这个术语用于指示所请求的信息不可用。

+   `%u`：这是请求文档的用户 ID。相同的值将在`REMOTE_USER`环境变量中提供给 CGI 脚本。

+   `%t`：这个术语用于检测服务器处理请求完成的时间。格式如下：

```py
            [day/month/year:hour:minute:second zone]
```

对于`day`参数，需要两位数字。对于`month`，我们必须定义三个字母。对于年份，由于年份有四个字符，我们必须取四位数字。现在，在`day`、`month`和`year`之后，我们必须为`hour`、`minute`和`seconds`各取两位数字。

+   `\"%r\"`：这个术语用作请求行，客户端用双引号给出。这个请求行包含有用的信息。请求客户端使用`GET`方法，使用的协议是 HTTP。

+   `%>s`：这个术语定义了客户端的状态代码。状态代码非常重要和有用，因为它指示了客户端发送的请求是否成功地发送到服务器。

+   `%b`：这个术语定义了对象返回给客户端时的总大小。这个总大小不包括响应头的大小。

# 解析其他日志文件

我们的系统中还有其他不同的日志文件，包括 Apache 日志。在我们的 Linux 发行版中，日志文件位于根文件系统中的`/var/log/`文件夹中，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/42d14bf4-400a-417b-950f-1abb543b30f8.png)

在上面的屏幕截图中，我们可以很容易地看到不同类型的日志文件（例如，认证日志文件`auth.log`，系统日志文件`syslog`和内核日志`kern.log`）可用于不同的操作条目。当我们对 Apache 日志文件执行操作时，如前所示，我们也可以对本地日志文件执行相同类型的操作。让我们看一个以前解析日志文件的例子。在`simple_log.py`脚本中创建并写入以下内容：

```py
f=open('/var/log/kern.log','r') lines = f.readlines() for line in lines:
 kern_log = line.split() print(kern_log) f.close()
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~$ python3 simple_log.py Output:
 ['Dec', '26', '14:39:38', 'ubuntu', 'NetworkManager[795]:', '<info>', '[1545815378.2891]', 'device', '(ens33):', 'state', 'change:', 'prepare', '->', 'config', '(reason', "'none')", '[40', '50', '0]'] ['Dec', '26', '14:39:38', 'ubuntu', 'NetworkManager[795]:', '<info>', '[1545815378.2953]', 'device', '(ens33):', 'state', 'change:', 'config', '->', 'ip-config', '(reason', "'none')", '[50', '70', '0]'] ['Dec', '26', '14:39:38', 'ubuntu', 'NetworkManager[795]:', '<info>', '[1545815378.2997]', 'dhcp4', '(ens33):', 'activation:', 'beginning', 'transaction', '(timeout', 'in', '45', 'seconds)'] ['Dec', '26', '14:39:38', 'ubuntu', 'NetworkManager[795]:', '<info>', '[1545815378.3369]', 'dhcp4', '(ens33):', 'dhclient', 'started', 'with', 'pid', '5221'] ['Dec', '26', '14:39:39', 'ubuntu', 'NetworkManager[795]:', '<info>', '[1545815379.0008]', 'address', '192.168.0.108'] ['Dec', '26', '14:39:39', 'ubuntu', 'NetworkManager[795]:', '<info>', '[1545815379.0020]', 'plen', '24', '(255.255.255.0)'] ['Dec', '26', '14:39:39', 'ubuntu', 'NetworkManager[795]:', '<info>', '[1545815379.0028]', 'gateway', '192.168.0.1']
```

在上面的例子中，首先我们创建了一个简单的文件对象`f`，并以读模式在其中打开了`kern.log`文件。之后，我们在`file`对象上应用了`readlines()`函数，以便在`for`循环中逐行读取文件中的数据。然后我们对内核日志文件的每一行应用了**`split()`**函数，然后使用`print`函数打印整个文件，如输出所示。

像读取内核日志文件一样，我们也可以对其执行各种操作，就像我们现在要执行一些操作一样。现在，我们将通过索引访问内核日志文件中的内容。这是可能的，因为`split`函数将文件中的所有信息拆分为不同的迭代。因此，让我们看一个这样的条件的例子。创建一个`simple_log1.py`脚本，并将以下脚本放入其中：

```py
f=open('/var/log/kern.log','r') lines = f.readlines() for line in lines:
 kern_log = line.split()[1:3] print(kern_log)
```

运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 simple_log1.py Output: ['26', '14:37:20'] ['26', '14:37:20'] ['26', '14:37:32'] ['26', '14:39:38'] ['26', '14:39:38'] ['26', '14:39:38'] ['26', '14:39:38'] ['26', '14:39:38'] ['26', '14:39:38'] ['26', '14:39:38'] ['26', '14:39:38'] ['26', '14:39:38'] 
```

在上面的例子中，我们只是在`split`函数旁边添加了`[1:3]`，换句话说，切片。序列的子序列称为切片，提取子序列的操作称为切片。在我们的例子中，我们使用方括号（`[ ]`）作为切片运算符，并在其中有两个整数值，用冒号（`:`）分隔。操作符`[1:3]`返回序列的第一个元素到第三个元素的部分，包括第一个但不包括最后一个。当我们对任何序列进行切片时，我们得到的子序列始终与从中派生的原始序列具有相同的类型。

然而，列表（或元组）的元素可以是任何类型；无论我们如何对其进行切片，列表的派生切片都是列表。因此，在对日志文件进行切片后，我们得到了先前显示的输出。

# 摘要

在本章中，您学习了如何处理不同类型的日志文件。您还了解了解析复杂日志文件以及在处理这些文件时异常处理的必要性。解析日志文件的技巧将有助于顺利进行解析。您还了解了`ErrorLog`和`AccessLog`。

在下一章中，您将学习有关 SOAP 和 REST 通信的内容。

# 问题

1.  Python 中运行时异常和编译时异常有什么区别？

1.  什么是正则表达式？

1.  探索 Linux 命令`head`，`tail`，`cat`和`awk`。

1.  编写一个 Python 程序，将一个文件的内容追加到另一个文件中。

1.  编写一个 Python 程序，以相反的顺序读取文件的内容。

1.  以下表达式的输出将是什么？

1.  `re.search(r'C\Wke', 'C@ke').group()`

1.  `re.search(r'Co+kie', 'Cooookie').group()`

1.  `re.match(r'<.*?>', '<h1>TITLE</h1>').group()`

# 进一步阅读

+   Python 日志记录：[`docs.python.org/3/library/logging.html`](https://docs.python.org/3/library/logging.html)

+   正则表达式：[`docs.python.org/3/howto/regex.html`](https://docs.python.org/3/howto/regex.html)

+   异常处理：[`www.pythonforbeginners.com/error-handling/python-try-and-except`](https://www.pythonforbeginners.com/error-handling/python-try-and-except)


# 第十五章：SOAP 和 REST API 通信

在本章中，我们将了解 SOAP 和 REST API 的基础知识。我们还将了解 Python 用于 SOAP 和 REST API 的库。我们将学习有关 SOAP 的 Zeep 库和 REST API 的请求。您将学习如何处理 JSON 数据。我们将看到处理 JSON 数据的简单示例，例如将 JSON 字符串转换为 Python 对象和将 Python 对象转换为 JSON 字符串。

在本章中，您将学习以下内容：

+   SOAP 是什么？

+   使用 SOAP 的库

+   什么是 RESTful API？

+   使用标准库进行 RESTful API

+   处理 JSON 数据

# SOAP 是什么？

**SOAP**是**简单对象访问协议**。SOAP 是允许进程使用不同操作系统的标准通信协议系统。这些通过 HTTP 和 XML 进行通信。它是一种 Web 服务技术。SOAP API 主要用于创建，更新，删除和恢复数据等任务。SOAP API 使用 Web 服务描述语言来描述 Web 服务提供的功能。SOAP 描述所有功能和数据类型。它构建了一个基于 XML 的协议。

# 使用 SOAP 的库

在本节中，我们将学习有关 Python 用于 SOAP 的库。以下是用于 SOAP 的各种库：

+   SOAPpy

+   `Zeep`

+   `Ladon`

+   `suds-jurko`

+   `pysimplesoap`

这些是 Python 的 SOAP API 库。在本节中，我们将只学习有关 Zeep 库的知识。

要使用 Zeep 的功能，您首先需要安装它。在终端中运行以下命令以安装 Zeep：

```py
 $ pip3 install Zeep
```

`Zeep`模块用于 WSDL 文档。它为服务和文档生成代码，并为 SOAP 服务器提供编程接口。`lxml`库用于解析 XML 文档。

现在，我们将看一个例子。创建一个`soap_example.py`脚本，并在其中写入以下代码：

```py
import zeep w = 'http://www.soapclient.com/xml/soapresponder.wsdl' c = zeep.Client(wsdl=w) print(c.service.Method1('Hello', 'World'))
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~$ python3 soap_example.py Output : Your input parameters are Hello and World
```

在上面的例子中，我们首先导入了`zeep`模块。我们首先提到了网站名称。然后我们创建了`zeep`客户端对象。我们之前使用的 WSDL 定义了一个简单的`Method1`函数，通过`zeep`通过`client.service.Method1`提供。它接受两个参数并返回一个字符串。

# 什么是 RESTful API？

**REST**代表**表述性状态转移**。RESTful API 是在 Web 服务开发中使用的一种通信方法。它是一种作为互联网上不同系统之间通信渠道的 Web 服务风格。它是一个应用程序接口，用于使用`HTTP`请求`GET`，`PUT`，`POST`和`DELETE`数据。

REST 的优势在于它使用的带宽较少，适合互联网使用。REST API 使用统一的接口。所有资源都由`GET`，`POST`，`PUT`和`DELETE`操作处理。`REST` API 使用`GET`来检索资源，使用`PUT`来更新资源或更改资源状态，使用`POST`来创建资源，使用`DELETE`来删除资源。使用 REST API 的系统提供快速性能和可靠性。

REST API 独立处理每个请求。从客户端到服务器的请求必须包含理解该请求所需的所有信息。

# 使用标准库进行 RESTful API

在本节中，我们将学习如何使用 RESTful API。为此，我们将使用 Python 的`requests`和 JSON 模块。我们现在将看一个例子。首先，我们将使用`requests`模块从 API 获取信息。我们将看到`GET`和`POST`请求。

首先，您必须安装`requests`库，如下所示：

```py
 $ pip3 install requests
```

现在，我们将看一个例子。创建一个`rest_get_example.py`脚本，并在其中写入以下内容：

```py
import requests req_obj = requests.get('https://www.imdb.com/news/top?ref_=nv_tp_nw') print(req_obj)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 rest_get_example.py Output: <Response [200]>
```

在前面的示例中，我们导入了`requests`模块来获取请求。接下来，我们创建了一个请求对象`req_obj`，并指定了我们想要获取请求的链接。然后，我们打印了它。我们得到的输出是状态码`200`，表示成功。

现在，我们将看到`POST`请求的示例。`POST`请求用于向服务器发送数据。创建一个`rest_post_example.py`脚本，并在其中写入以下内容：

```py
import requests import json url_name = 'http://httpbin.org/post' data = {"Name" : "John"} data_json = json.dumps(data) headers = {'Content-type': 'application/json'} response = requests.post(url_name, data=data_json, headers=headers) print(response)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 rest_post_example.py Output: <Response [200]>
```

在前面的示例中，我们学习了关于`POST`请求。首先，我们导入了必要的模块 requests 和 JSON。接下来，我们提到了 URL。此外，我们以字典格式输入了要发布的数据。接下来，我们提到了标头。然后，我们使用`POST`请求发布。我们得到的输出是状态码`200`，这是一个成功的代码。

# 处理 JSON 数据

在本节中，我们将学习有关 JSON 数据。**JSON**代表**JavaScript 对象表示**。JSON 是一种数据交换格式。它将 Python 对象编码为 JSON 字符串，并将 JSON 字符串解码为 Python 对象。Python 有一个 JSON 模块，用于格式化 JSON 输出。它具有用于序列化和反序列化 JSON 的函数。

+   `json.dump(obj, fileObj)`: 这个函数将一个对象序列化为一个 JSON 格式的流。

+   `json.dumps(obj)`: 这个函数将一个对象序列化为一个 JSON 格式的字符串。

+   `json.load(JSONfile)`: 这个函数将一个 JSON 文件反序列化为一个 Python 对象。

+   `json.loads(JSONfile)`: 这个函数将一个字符串类型的 JSON 文件反序列化为一个 Python 对象。

它还列出了编码和解码的两个类：

+   `JSONEncoder`: 用于将 Python 对象转换为 JSON 格式。

+   `JSONDecoder`: 用于将 JSON 格式的文件转换为 Python 对象。

现在，我们将看到一些使用 JSON 模块的示例。首先，我们将看到从 JSON 到 Python 的转换。为此，创建一个名为`json_to_python.py`的脚本，并在其中写入以下代码：

```py
import json j_obj =  '{ "Name":"Harry", "Age":26, "Department":"HR"}' p_obj = json.loads(j_obj) print(p_obj["Name"]) print(p_obj["Department"])
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 json_to_python.py Output: Harry HR
```

在前面的示例中，我们编写了一个代码，将 JSON 字符串转换为 Python 对象。`json.loads()`函数用于将 JSON 字符串转换为 Python 对象。

现在，我们将看到如何将 Python 转换为 JSON。为此，创建一个`python_to_json.py`脚本，并在其中写入以下代码：

```py
import json emp_dict1 =  '{ "Name":"Harry", "Age":26, "Department":"HR"}' json_obj = json.dumps(emp_dict1) print(json_obj)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 python_to_json.py Output: "{ \"Name\":\"Harry\", \"Age\":26, \"Department\":\"HR\"}"
```

在前面的示例中，我们将 Python 对象转换为 JSON 字符串。`json.dumps()`函数用于这种转换。

现在，我们将看到如何将各种类型的 Python 对象转换为 JSON 字符串。为此，创建一个`python_object_to_json.py`脚本，并在其中写入以下内容：

```py
import json python_dict =  {"Name": "Harry", "Age": 26} python_list =  ["Mumbai", "Pune"] python_tuple =  ("Basketball", "Cricket") python_str =  ("hello_world") python_int =  (150) python_float =  (59.66) python_T =  (True) python_F =  (False) python_N =  (None) json_obj = json.dumps(python_dict) json_arr1 = json.dumps(python_list) json_arr2 = json.dumps(python_tuple) json_str = json.dumps(python_str) json_num1 = json.dumps(python_int) json_num2 = json.dumps(python_float) json_t = json.dumps(python_T) json_f = json.dumps(python_F) json_n = json.dumps(python_N) print("json object : ", json_obj) print("json array1 : ", json_arr1) print("json array2 : ", json_arr2) print("json string : ", json_str) print("json number1 : ", json_num1) print("json number2 : ", json_num2) print("json true", json_t) print("json false", json_f) print("json null", json_n)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 python_object_to_json.py Output: json object :  {"Name": "Harry", "Age": 26} json array1 :  ["Mumbai", "Pune"] json array2 :  ["Basketball", "Cricket"] json string :  "hello_world" json number1 :  150 json number2 :  59.66 json true true json false false json null null
```

在前面的示例中，我们使用`json.dumps()`函数将各种类型的 Python 对象转换为 JSON 字符串。转换后，Python 列表和元组被转换为数组。整数和浮点数在 JSON 中被视为数字。以下是从 Python 到 JSON 的转换图表：

| **Python** | **JSON** |
| --- | --- |
| `dict` | Object |
| `list` | Array |
| `tuple` | Array |
| `str` | String |
| `int` | Number |
| `float` | Number |
| `True` | true |
| `False` | false |
| `None` | null |

# 总结

在这一章中，您学习了关于 SOAP API 和 RESTful API。您学习了关于`zeep` Python 库用于 SOAP API 和 requests 库用于 REST API。您还学会了如何处理 JSON 数据，例如将 JSON 转换为 Python，反之亦然。

在下一章中，您将学习有关网页抓取和用于执行此任务的 Python 库。

# 问题

1.  SOAP 和 REST API 之间有什么区别？

1.  `json.loads`和`json.load`之间有什么区别？

1.  JSON 支持所有平台吗？

1.  以下代码片段的输出是什么？

```py
boolean_value = False
print(json.dumps(boolean_value))
```

1.  以下代码片段的输出是什么？

```py
>> weird_json = '{"x": 1, "x": 2, "x": 3}'
>>> json.loads(weird_json)
```

# 进一步阅读

+   JSON 文档：[`docs.python.org/3/library/json.html`](https://docs.python.org/3/library/json.html)

+   REST API 信息：[`searchmicroservices.techtarget.com/definition/REST-representational-state-transfer`](https://searchmicroservices.techtarget.com/definition/REST-representational-state-transfer)
