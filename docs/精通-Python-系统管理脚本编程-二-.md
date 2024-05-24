# 精通 Python 系统管理脚本编程（二）

> 原文：[`zh.annas-archive.org/md5/c33d6613eafa4d86b92059a00f7aa16f`](https://zh.annas-archive.org/md5/c33d6613eafa4d86b92059a00f7aa16f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：单元测试-单元测试框架简介

测试您的项目是软件开发的重要部分。在本章中，我们将学习 Python 中的单元测试。Python 有一个名为`unittest`的模块，这是一个单元测试框架。我们将在本章学习`unittest`框架。

在本章中，您将学习以下主题：

+   单元测试框架简介

+   创建单元测试任务

# 什么是 unittest？

`unittest`是 Python 中的一个单元测试框架。它支持多个任务，如测试固件、编写测试用例、将测试用例聚合到测试套件中以及运行测试。

`unittest`支持四个主要概念，列在这里：

+   `test fixture`: 这包括为执行一个或多个测试准备和清理活动

+   `test case`: 这包括您的单个单元测试。通过使用`unittest`的`TestCase`基类，我们可以创建新的测试用例

+   `test suite`: 这包括一组测试用例、测试套件或两者。这是为了一起执行测试用例

+   `test runner`: 这包括安排测试执行并向用户提供输出

Python 有一个`unittest`模块，我们将在脚本中导入它。`unittest`模块有`TestCase`类用于创建测试用例。

可以将单独的测试用例创建为方法。这些方法名称以单词*test*开头。因此，测试运行器将知道哪些方法代表测试用例。

# 创建单元测试

在本节中，我们将创建单元测试。为此，我们将创建两个脚本。一个将是您的常规脚本，另一个将包含用于测试的代码。

首先，创建一个名为`arithmetic.py`的脚本，并在其中编写以下代码：

```py
# In this script, we are going to create a 4 functions: add_numbers, sub_numbers, mul_numbers, div_numbers. def add_numbers(x, y):
 return x + y def sub_numbers(x, y):
 return x - y def mul_numbers(x, y):
 return x * y def div_numbers(x, y):
 return (x / y)
```

在上面的脚本中，我们创建了四个函数：`add_numbers`、`sub_numbers`、`mul_numbers`和`div_numbers`。现在，我们将为这些函数编写测试用例。首先，我们将学习如何为`add_numbers`函数编写测试用例。创建一个名为`test_addition.py`的脚本，并在其中编写以下代码：

```py
import arithmetic import unittest # Testing add_numbers function from arithmetic. class Test_addition(unittest.TestCase): # Testing Integers def test_add_numbers_int(self): sum = arithmetic.add_numbers(50, 50) self.assertEqual(sum, 100) # Testing Floats def test_add_numbers_float(self): sum = arithmetic.add_numbers(50.55, 78) self.assertEqual(sum, 128.55) # Testing Strings def test_add_numbers_strings(self): sum = arithmetic.add_numbers('hello','python') self.assertEqual(sum, 'hellopython')  if __name__ == '__main__': unittest.main()
```

在上面的脚本中，我们为`add_numbers`函数编写了三个测试用例。第一个是测试整数，第二个是测试浮点数，第三个是测试字符串。在字符串中，添加意味着连接两个字符串。类似地，您可以为减法、乘法和除法编写测试用例。

现在，我们将运行我们的`test_addition.py`测试脚本，并看看运行此脚本后我们得到什么结果。

按照以下方式运行脚本，您将获得以下输出：

```py
student@ubuntu:~$ python3 test_addition.py ... ---------------------------------------------------------------------- Ran 3 tests in 0.000s
OK
```

在这里，我们得到了`OK`，这意味着我们的测试成功了。

每当运行测试脚本时，您有三种可能的测试结果：

| **结果** | **描述** |
| --- | --- |
| `OK` | 成功 |
| `FAIL` | 测试失败-引发`AssertionError`异常 |
| `ERROR` | 引发除`AssertionError`之外的异常 |

# 单元测试中使用的方法

每当我们使用`unittest`时，我们在脚本中使用一些方法。这些方法如下：

+   `assertEqual()`和`assertNotEqual()`: 这检查预期结果

+   `assertTrue()`和`assertFalse()`: 这验证条件

+   `assertRaises()`: 这验证特定异常是否被引发

+   `setUp()`和`tearDown()`: 这定义了在每个测试方法之前和之后执行的指令

您也可以从命令行使用`unittest`模块。因此，您可以按照以下方式运行先前的测试脚本：

```py
student@ubuntu:~$ python3 -m unittest test_addition.py ... ---------------------------------------------------------------------- Ran 3 tests in 0.000s
OK
```

现在，我们将看另一个例子。我们将创建两个脚本：`if_example.py`和`test_if.py`。`if_example.py`将是我们的常规脚本，`test_if.py`将包含测试用例。在此测试中，我们正在检查输入的数字是否等于`100`。如果等于`100`，则我们的测试将是`成功`的。如果不是，它必须显示一个`FAILED`结果。

创建一个名为`if_example.py`的脚本，并在其中编写以下代码：

```py
def check_if():
 a = int(input("Enter a number \n")) if (a == 100): print("a is equal to 100") else: print("a is not equal to 100") return a
```

现在，创建一个名为`test_if.py`的测试脚本，并在其中编写以下代码：

```py
import if_example import unittest  class Test_if(unittest.TestCase): def test_if(self): result = if_example.check_if() self.assertEqual(result, 100) if __name__ == '__main__':
 unittest.main()
```

按以下方式运行测试脚本：

```py
student@ubuntu:~/Desktop$ python3 -m unittest test_if.py Enter a number 100 a is equal to 100 . ---------------------------------------------------------------------- Ran 1 test in 1.912s OK 
```

我们运行脚本以获得成功的测试结果。现在，我们将输入除`100`之外的一些值，我们必须得到一个`FAILED`的结果。按以下方式运行脚本：

```py
student@ubuntu:~/Desktop$ python3 -m unittest test_if.py Enter a number 50 a is not equal to 100 F ====================================================================== FAIL: test_if (test_if.Test_if) ---------------------------------------------------------------------- Traceback (most recent call last):
 File "/home/student/Desktop/test_if.py", line 7, in test_if self.assertEqual(result, 100) AssertionError: 50 != 100
---------------------------------------------------------------------- Ran 1 test in 1.521s
FAILED (failures=1)
```

# 摘要

在本章中，我们学习了 Python 的单元测试框架`unittest`。我们还学习了如何创建测试用例以及单元测试中使用的方法。

在下一章中，我们将学习如何自动化系统管理员的常规管理活动。您将学习如何接受输入，处理密码，执行外部命令，读取配置文件，向脚本添加警告代码，设置 CPU 限制，启动 web 浏览器，使用`os`模块并进行备份。

# 问题

1.  什么是单元测试、自动化测试和手动测试？

1.  除了`unittest`之外还有哪些替代模块？

1.  编写测试用例有什么用？

1.  什么是 PEP8 标准？

# 进一步阅读

+   单元测试文档：[`docs.python.org/3/library/unittest.html `](https://docs.python.org/3/library/unittest.html)

+   Python 中的 PEP8 编码标准：[`www.python.org/dev/peps/pep-0008/ `](https://www.python.org/dev/peps/pep-0008/)


# 第四章：自动化常规管理活动

系统管理员执行各种管理活动。这些活动可能包括文件处理、日志记录、管理 CPU 和内存、处理密码，以及最重要的是进行备份。这些活动需要自动化。在本章中，我们将学习如何使用 Python 自动化这些活动。

在本章中，我们将涵盖以下主题：

+   通过重定向、管道和输入文件接受输入

+   在脚本中在运行时处理密码

+   执行外部命令并获取它们的输出

+   在运行时提示密码和验证

+   读取配置文件

+   向脚本添加日志和警告代码

+   限制 CPU 和内存使用

+   启动 Web 浏览器

+   使用`os`模块处理目录和文件

+   进行备份（使用`rsync`）

# 通过重定向、管道和输入文件接受输入

在本节中，我们将学习用户如何通过重定向、管道和外部输入文件接受输入。

接受重定向输入时，我们使用`stdin`。`pipe`是另一种重定向形式。这个概念意味着将一个程序的输出作为另一个程序的输入。我们可以通过外部文件和使用 Python 来接受输入。

# 通过重定向输入

`stdin`和`stdout`是`os`模块创建的对象。我们将编写一个脚本，其中我们将使用`stdin`和`stdout`。

创建一个名为`redirection.py`的脚本，并在其中编写以下代码：

```py
import sys class Redirection(object):
 def __init__(self, in_obj, out_obj): self.input = in_obj self.output = out_obj def read_line(self): res = self.input.readline() self.output.write(res) return resif __name__ == '__main__':
 if not sys.stdin.isatty(): sys.stdin = Redirection(in_obj=sys.stdin, out_obj=sys.stdout) a = input('Enter a string: ') b = input('Enter another string: ') print ('Entered strings are: ', repr(a), 'and', repr(b)) 
```

如下运行上述程序：

```py
$ python3 redirection.py 
```

我们将收到以下输出：

```py
Output: Enter a string: hello Enter another string: python Entered strings are:  'hello' and 'python'
```

每当程序在交互会话中运行时，`stdin`是键盘输入，`stdout`是用户的终端。`input()`函数用于从用户那里获取输入，`print()`是在终端（`stdout`）上写入的方式。

# 通过管道输入

管道是另一种重定向形式。这种技术用于将信息从一个程序传递到另一个程序。`|`符号表示管道。通过使用管道技术，我们可以以一种使一个命令的输出作为下一个命令的输入的方式使用两个以上的命令。

现在，我们将看看如何使用管道接受输入。为此，首先我们将编写一个返回`floor`除法的简单脚本。创建一个名为`accept_by_pipe.py`的脚本，并在其中编写以下代码：

```py
import sys for n in sys.stdin:
 print ( int(n.strip())//2 ) 
```

运行脚本，您将得到以下输出：

```py
$ echo 15 | python3 accept_by_pipe.py Output: 7 
```

在上面的脚本中，`stdin`是键盘输入。我们对我们在运行时输入的数字执行`floor`除法。floor 除法仅返回商的整数部分。当我们运行程序时，我们传递`15`，然后是管道`|`符号，然后是我们的脚本名称。因此，我们将`15`作为输入提供给我们的脚本。因此进行了 floor 除法，我们得到输出为`7`。

我们可以向我们的脚本传递多个输入。因此，在以下执行中，我们已经传递了多个输入值，如`15`、`45`和`20`。为了处理多个输入值，我们在脚本中编写了一个`for`循环。因此，它将首先接受`15`作为输入，然后是`45`，然后是`20`。输出将以新行打印出每个输入，因为我们在输入值之间写了`\n`。为了启用对反斜杠的这种解释，我们传递了`-e`标志：

```py
$ echo -e '15\n45\n20' | python3 accept_by_pipe.py Output: 7 22 10
```

运行后，我们得到了`15`、`45`和`20`的 floor 除法分别为`7`、`22`和`10`，显示在新行上。

# 通过输入文件输入

在本节中，我们将学习如何从输入文件中获取输入。在 Python 中，从输入文件中获取输入更容易。我们将看一个例子。但首先，我们将创建一个名为`sample.txt`的简单文本文件，并在其中编写以下代码：

`Sample.txt`：

```py
Hello World Hello Python
```

现在，创建一个名为`accept_by_input_file.py`的脚本，并在其中编写以下代码：

```py
i = open('sample.txt','r')
o = open('sample_output.txt','w')

a = i.read()
o.write(a)
```

运行程序，您将得到以下输出：

```py
$ python3 accept_by_input_file.py $ cat sample_output.txt Hello World Hello Python
```

# 在脚本中在运行时处理密码

在本节中，我们将看一个简单的处理脚本密码的例子。我们将创建一个名为`handling_password.py`的脚本，并在其中编写以下内容：

```py
import sys import paramiko import time ip_address = "192.168.2.106" username = "student" password = "training" ssh_client = paramiko.SSHClient() ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy()) ssh_client.load_system_host_keys() ssh_client.connect(hostname=ip_address,\
 username=username, password=password) print ("Successful connection", ip_address) ssh_client.invoke_shell() remote_connection = ssh_client.exec_command('cd Desktop; mkdir work\n') remote_connection = ssh_client.exec_command('mkdir test_folder\n') #print( remote_connection.read() ) ssh_client.close
```

运行上述脚本，您将收到以下输出：

```py
$ python3 handling_password.py  Output: Successful connection 192.168.2.106
```

在上述脚本中，我们使用了`paramiko`模块。`paramiko`模块是`ssh`的 Python 实现，提供了客户端-服务器功能。

按以下方式安装`paramiko`：

```py
pip3 install paramiko
```

在上述脚本中，我们远程连接到主机`192.168.2.106`。我们在脚本中提供了主机的用户名和密码。

运行此脚本后，在`192.168.2.106`桌面上，您将找到一个`work`文件夹，并且`test_folder`可以在`192.168.2.106`的`home/`目录中找到。

# 执行外部命令并获取它们的输出

在本节中，我们将学习 Python 的 subprocess 模块。使用`subprocess`，很容易生成新进程并获取它们的返回代码，执行外部命令并启动新应用程序。

我们将看一下如何在 Python 中执行外部命令并获取它们的输出，使用`subprocess`模块。我们将创建一个名为`execute_external_commands.py`的脚本，并在其中编写以下代码：

```py
import subprocess subprocess.call(["touch", "sample.txt"]) subprocess.call(["ls"]) print("Sample file created") subprocess.call(["rm", "sample.txt"]) 
```

```py
subprocess.call(["ls"]) print("Sample file deleted")
```

运行程序，您将得到以下输出：

```py
$ python3 execute_external_commands.py Output: 1.py     accept_by_pipe.py      sample_output.txt       sample.txt accept_by_input_file.py         execute_external_commands.py         output.txt        sample.py Sample.txt file created 1.py     accept_by_input_file.py         accept_by_pipe.py execute_external_commands.py  output.txt            sample_output.txt       sample.py Sample.txt file deleted
```

# 使用 subprocess 模块捕获输出

在本节中，我们将学习如何捕获输出。我们将为`stdout`参数传递`PIPE`以捕获输出。编写一个名为`capture_output.py`的脚本，并在其中编写以下代码：

```py
import subprocess res = subprocess.run(['ls', '-1'], stdout=subprocess.PIPE,) print('returncode:', res.returncode) print(' {} bytes in stdout:\n{}'.format(len(res.stdout), res.stdout.decode('utf-8'))) 
```

按以下方式执行脚本：

```py
student@ubuntu:~$ python3 capture_output.py 
```

在执行时，我们将收到以下输出：

```py
Output: returncode: 0 191 bytes in stdout: 1.py accept_by_input_file.py accept_by_pipe.py execute_external_commands.py getpass_example.py ouput.txt output.txt password_prompt_again.py sample_output.txt sample.py capture_output.py
```

在上述脚本中，我们导入了 Python 的 subprocess 模块，它有助于捕获输出。subprocess 模块用于创建新进程。它还有助于连接输入/输出管道并获取返回代码。`subprocess.run()`将运行作为参数传递的命令。`Returncode`将是子进程的退出状态。在输出中，如果返回代码为`0`，表示它成功运行。

# 运行时提示密码和验证

在本节中，我们将学习如何在运行时处理密码，使用`getpass 模块`。Python 中的`getpass()`模块提示用户输入密码而不回显。`getpass`模块用于在程序通过终端与用户交互时处理密码提示。

我们将看一些如何使用`getpass`模块的例子：

1.  创建一个名为`no_prompt.py`的脚本，并在其中编写以下代码：

```py
import getpass try:
 p = getpass.getpass() except Exception as error:
 print('ERROR', error) else:
 print('Password entered:', p)
```

在此脚本中，不为用户提供提示。因此，默认情况下，它设置为`Password`提示。

按以下方式运行脚本：

```py
$ python3 no_prompt.py Output : Password: Password entered: abcd
```

1.  我们将提供一个输入密码的提示。因此，在其中创建一个名为`with_prompt.py`的脚本，并在其中编写以下代码：

```py
import getpass try:
 p = getpass.getpass("Enter your password: ") except Exception as error:
 print('ERROR', error) else:
 print('Password entered:', p)
```

现在，我们已经编写了一个脚本，用于提供密码的提示。按以下方式运行程序：

```py
$ python3 with_prompt.py Output: Enter your password: Password entered: abcd
```

在这里，我们为用户提供了“输入密码”的提示。

现在，我们将编写一个脚本，如果输入错误的密码，它将只是打印一个简单的消息，但不会再提示输入正确的密码。

1.  编写一个名为`getpass_example.py`的脚本，并在其中编写以下代码：

```py
import getpass passwd = getpass.getpass(prompt='Enter your password: ') if passwd.lower() == '#pythonworld':
 print('Welcome!!') else:
 print('The password entered is incorrect!!')
```

按以下方式运行程序（这里我们输入了正确的密码，即`#pythonworld`）：

```py
$ python3 getpass_example.py Output: Enter your password: Welcome!!
```

现在，我们将输入一个错误的密码，并检查我们收到什么消息：

```py
$ python3 getpass_example.py Output: Enter your password: The password entered is incorrect!!
```

在这里，我们编写了一个脚本，如果我们输入错误的密码，就不会再要求输入密码。

现在，我们将编写一个脚本，当我们提供错误的密码时，它将再次要求输入正确的密码。使用`getuser()`来获取用户的登录名。`getuser()`函数将返回系统登录的用户。创建一个名为`password_prompt_again.py`的脚本，并在其中编写以下代码：

```py
import getpass user_name = getpass.getuser() print ("User Name : %s" % user_name) while True:
 passwd = getpass.getpass("Enter your Password : ") if passwd == '#pythonworld': print ("Welcome!!!") break else: print ("The password you entered is incorrect.")
```

运行程序，您将得到以下输出：

```py
student@ubuntu:~$ python3 password_prompt_again.py User Name : student Enter your Password : The password you entered is incorrect. Enter your Password : Welcome!!!
```

# 读取配置文件

在本节中，我们将学习 Python 的`configparser`模块。通过使用`configparser`模块，您可以管理应用程序的用户可编辑的配置文件。

这些配置文件的常见用途是，用户或系统管理员可以使用简单的文本编辑器编辑文件以设置应用程序默认值，然后应用程序将读取并解析它们，并根据其中写入的内容进行操作。

要读取配置文件，`configparser`有`read()`方法。现在，我们将编写一个名为`read_config_file.py`的简单脚本。在那之前，创建一个名为`read_simple.ini`的`.ini`文件，并在其中写入以下内容：`read_simple.ini`

```py
[bug_tracker] url = https://timesofindia.indiatimes.com/
```

创建`read_config_file.py`并输入以下内容：

```py
from configparser import ConfigParser p = ConfigParser() p.read('read_simple.ini') print(p.get('bug_tracker', 'url'))
```

运行`read_config_file.py`，您将获得以下输出：

```py
$ python3 read_config_file.py  Output: https://timesofindia.indiatimes.com/
```

`read()`方法接受多个文件名。每当扫描每个文件名并且该文件存在时，它将被打开并读取。现在，我们将编写一个用于读取多个文件名的脚本。创建一个名为`read_many_config_file.py`的脚本，并在其中编写以下代码：

```py
from configparser import ConfigParser import glob p = ConfigParser() files = ['hello.ini', 'bye.ini', 'read_simple.ini', 'welcome.ini'] files_found = p.read(files) files_missing = set(files) - set(files_found) print('Files found:  ', sorted(files_found)) print('Files missing:  ', sorted(files_missing))
```

运行上述脚本，您将获得以下输出：

```py
$ python3 read_many_config_file.py  Output Files found:   ['read_simple.ini'] Files missing:   ['bye.ini', 'hello.ini', 'welcome.ini']
```

在上面的示例中，我们使用了 Python 的`configparser`模块，该模块有助于管理配置文件。首先，我们创建了一个名为`files`的列表。`read()`函数将读取配置文件。在示例中，我们创建了一个名为`files_found`的变量，它将存储目录中存在的配置文件的名称。接下来，我们创建了另一个名为`files_missing`的变量，它将返回目录中不存在的文件名。最后，我们打印存在和缺失的文件名。

# 向脚本添加日志记录和警告代码

在本节中，我们将学习 Python 的日志记录和警告模块。日志记录模块将跟踪程序中发生的事件。警告模块警告程序员有关语言和库中所做更改的信息。

现在，我们将看一个简单的日志记录示例。我们将编写一个名为`logging_example.py`的脚本，并在其中编写以下代码：

```py
import logging LOG_FILENAME = 'log.txt' logging.basicConfig(filename=LOG_FILENAME, level=logging.DEBUG,) logging.debug('This message should go to the log file') with open(LOG_FILENAME, 'rt') as f:
 prg = f.read() print('FILE:') print(prg)
```

运行以下程序：

```py
$ python3 logging_example.py Output: FILE: DEBUG:root:This message should go to the log file
```

检查`hello.py`，您会看到在该脚本中打印的调试消息：

```py
$ cat log.txt  Output: DEBUG:root:This message should go to the log file
```

现在，我们将编写一个名为`logging_warnings_codes.py`的脚本，并在其中编写以下代码：

```py
import logging import warnings logging.basicConfig(level=logging.INFO,) warnings.warn('This warning is not sent to the logs') logging.captureWarnings(True) warnings.warn('This warning is sent to the logs')
```

运行以下脚本：

```py
$ python3 logging_warnings_codes.py Output: logging_warnings_codes.py:6: UserWarning: This warning is not sent to the logs
 warnings.warn('This warning is not sent to the logs') WARNING:py.warnings:logging_warnings_codes.py:10: UserWarning: This warning is sent to the logs
 warnings.warn('This warning is sent to the logs')
```

# 生成警告

`warn()`用于生成警告。现在，我们将看一个生成警告的简单示例。编写一个名为`generate_warnings.py`的脚本，并在其中编写以下代码：

```py
import warnings warnings.simplefilter('error', UserWarning) print('Before') warnings.warn('Write your warning message here') print('After')
```

如下所示运行脚本：

```py
$ python3 generate_warnings.py Output: Before: Traceback (most recent call last):
 File "generate_warnings.py", line 6, in <module> warnings.warn('Write your warning message here') UserWarning: Write your warning message here
```

在上面的脚本中，我们通过`warn()`传递了一个警告消息。我们使用了一个简单的过滤器，以便您的警告将被视为错误，并且程序员将相应地解决该错误。

# 限制 CPU 和内存使用

在本节中，我们将学习如何限制 CPU 和内存使用。首先，我们将编写一个用于限制 CPU 使用的脚本。创建一个名为`put_cpu_limit.py`的脚本，并在其中编写以下代码：

```py
import resource import sys import signal import time def time_expired(n, stack):
 print('EXPIRED :', time.ctime()) raise SystemExit('(time ran out)') signal.signal(signal.SIGXCPU, time_expired) # Adjust the CPU time limit soft, hard = resource.getrlimit(resource.RLIMIT_CPU) print('Soft limit starts as  :', soft) resource.setrlimit(resource.RLIMIT_CPU, (10, hard)) soft, hard = resource.getrlimit(resource.RLIMIT_CPU) print('Soft limit changed to :', soft) print() # Consume some CPU time in a pointless exercise print('Starting:', time.ctime()) for i in range(200000):
 for i in range(200000): v = i * i # We should never make it this far print('Exiting :', time.ctime())
```

如下所示运行上述脚本：

```py
$ python3 put_cpu_limit.py Output: Soft limit starts as  : -1 Soft limit changed to : 10 Starting: Thu Sep  6 16:13:20 2018 EXPIRED : Thu Sep  6 16:13:31 2018 (time ran out)
```

在上面的脚本中，我们使用`setrlimit()`来限制 CPU 使用。因此，在我们的脚本中，我们将限制设置为 10 秒。

# 启动 webbrowser

在本节中，我们将学习 Python 的`webbrowser`模块。该模块具有在浏览器应用程序中打开 URL 的功能。我们将看一个简单的示例。创建一个名为`open_web.py`的脚本，并在其中编写以下代码：

```py
import webbrowser webbrowser.open('https://timesofindia.indiatimes.com/world')
```

如下所示运行脚本：

```py
$ python3 open_web.py Output:
Url mentioned in open() will be opened in your browser.
webbrowser – Command line interface
```

您还可以通过命令行使用 Python 的`webbrowser`模块，并且可以使用所有功能。要通过命令行使用`webbrowser`，运行以下命令：

```py
$ python3 -m webbrowser -n https://www.google.com/
```

在这里，[`www.google.com/`](https://www.google.com/)将在浏览器窗口中打开。您可以使用以下两个选项：

+   `-n`：打开一个新窗口

+   `-t`：打开一个新标签

# 使用 os 模块处理目录和文件

在本节中，我们将学习 Python 的`os`模块。Python 的`os`模块有助于实现操作系统任务。如果我们想执行操作系统任务，我们需要导入`os`模块。

我们将看一些与处理文件和目录相关的示例。

# 创建和删除目录

在本节中，我们将创建一个脚本，我们将看到可以用于处理文件系统上的目录的函数，其中将包括创建、列出和删除内容。创建一个名为`os_dir_example.py`的脚本，并在其中编写以下代码：

```py
import os directory_name = 'abcd' print('Creating', directory_name) os.makedirs(directory_name) file_name = os.path.join(directory_name, 'sample_example.txt') print('Creating', file_name) with open(file_name, 'wt') as f:
 f.write('sample example file') print('Cleaning up') os.unlink(file_name) os.rmdir(directory_name)       # Will delete the directory
```

按以下方式运行脚本：

```py
$ python3 os_dir_example.py Output: Creating abcd Creating abcd/sample_example.txt Cleaning up
```

使用`mkdir()`创建目录时，所有父目录必须已经创建。但是，使用`makedirs()`创建目录时，它将创建任何在路径中提到但不存在的目录。`unlink()`将删除文件路径，`rmdir()`将删除目录路径。

# 检查文件系统的内容

在本节中，我们将使用`listdir()`列出目录的所有内容。创建一个名为`list_dir.py`的脚本，并在其中编写以下代码：

```py
import os import sys print(sorted(os.listdir(sys.argv[1])))
```

按以下方式运行脚本：

```py
$ python3 list_dir.py /home/student/ ['.ICEauthority', '.bash_history', '.bash_logout', '.bashrc', '.cache', '.config', '.gnupg', '.local', '.mozilla', '.pam_environment', '.profile', '.python_history', '.ssh', '.sudo_as_admin_successful', '.viminfo', '1.sh', '1.sh.x', '1.sh.x.c', 'Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Public', 'Templates', 'Videos', 'examples.desktop', 'execute_external_commands.py', 'log.txt', 'numbers.txt', 'python_learning', 'work']
```

因此，通过使用`listdir()`，您可以列出文件夹的所有内容。

# 备份（使用 rsync）

这是系统管理员必须做的最重要的工作。在本节中，我们将学习如何使用`rsync`进行备份。`rsync`命令用于在本地和远程复制文件和目录，并使用`rsync`执行数据备份。为此，我们将编写一个名为`take_backup.py`的脚本，并在其中编写以下代码：

```py
import os import shutil import time from sh import rsync def check_dir(os_dir):
 if not os.path.exists(os_dir): print (os_dir, "does not exist.") exit(1) def ask_for_confirm():
 ans = input("Do you want to Continue? yes/no\n") global con_exit if ans == 'yes': con_exit = 0 return con_exit elif ans == "no": con_exit = 1 return con_exit else:1 print ("Answer with yes or no.") ask_for_confirm() def delete_files(ending):
 for r, d, f in os.walk(backup_dir): for files in f: if files.endswith("." + ending): os.remove(os.path.join(r, files)) backup_dir = input("Enter directory to backup\n")   # Enter directory name check_dir(backup_dir) print (backup_dir, "saved.") time.sleep(3) backup_to_dir= input("Where to backup?\n") check_dir(backup_to_dir) print ("Doing the backup now!") ask_for_confirm() if con_exit == 1:
 print ("Aborting the backup process!") exit(1) rsync("-auhv", "--delete", "--exclude=lost+found", "--exclude=/sys", "--exclude=/tmp", "--exclude=/proc", "--exclude=/mnt", "--exclude=/dev", "--exclude=/backup", backup_dir, backup_to_dir)
```

按以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 take_backup.py Output : Enter directory to backup /home/student/work /home/student/work saved. Where to backup? /home/student/Desktop Doing the backup now! Do you want to Continue? yes/no yes
```

现在，检查`Desktop/directory`，您将在该目录中看到您的工作文件夹。`rsync`命令有一些选项，即以下选项：

+   `-a`：存档

+   `-u`：更新

+   `-h`：人类可读格式

+   `-v`：详细

+   `--delete`：从接收方删除多余的文件

+   `--exclude`：排除规则

# 摘要

在本章中，我们学习了如何自动化常规管理任务。我们学习了通过各种技术接受输入，运行时提示密码，执行外部命令，读取配置文件，在脚本中添加警告，通过脚本和命令行启动`webbrowser`，使用`os`模块处理文件和目录以及进行备份。

在下一章中，您将学习更多关于`os`模块和数据处理的知识。此外，您还将学习`tarfile`模块以及如何使用它。

# 问题

1.  如何使用`readline`模块？

1.  用于读取、创建新文件、删除文件、列出当前目录中文件的 Linux 命令是什么？

1.  有哪些包可用于在 Python 中运行 Linux/Windows 命令？

1.  如何读取或在配置`ini`文件中设置新值

1.  列出用于查找`cpu`使用情况的库？

1.  列出接受用户输入的不同方法？

1.  排序和排序有什么区别？

# 进一步阅读

+   学习 Linux 的基本命令：[`maker.pro/linux/tutorial/basic-linux-commands-for-beginners`](https://maker.pro/linux/tutorial/basic-linux-commands-for-beginners)

+   Selenium webdriver 文档：[`selenium-python.readthedocs.io/index.html`](https://selenium-python.readthedocs.io/index.html)


# 第五章：处理文件，目录和数据

系统管理员执行处理各种文件，目录和数据等任务。在本章中，我们将学习`os`模块。`os`模块提供了与操作系统交互的功能。Python 程序员可以轻松使用此`os`模块执行文件和目录操作。`os`模块为处理文件，路径，目录和数据的程序员提供了工具。

在本章中，您将学习以下内容：

+   使用 os 模块处理目录

+   复制，移动，重命名和删除数据

+   处理路径，目录和文件

+   比较数据

+   合并数据

+   模式匹配文件和目录

+   元数据：关于数据的数据

+   压缩和恢复

+   使用`tarfile`模块创建 TAR 存档

+   使用`tarfile`模块检查 TAR 文件的内容

# 使用 os 模块处理目录

目录是文件和子目录的集合。`os`模块提供了各种函数，允许我们与操作系统交互。在本节中，我们将学习一些在处理目录时可以使用的函数。

# 获取工作目录

要开始处理目录，首先我们将获取当前工作目录的名称。`os`模块有一个`getcwd()`函数，使用它我们可以获取当前工作目录。启动`python3`控制台并输入以下命令以获取目录名称：

```py
$ python3 Python 3.6.5 (default, Apr  1 2018, 05:46:30) [GCC 7.3.0] on linux Type "help", "copyright", "credits" or "license" for more information. >>> import os >>> os.getcwd() '/home/student' **>>** 
```

# 更改目录

使用`os`模块，我们可以更改当前工作目录。为此，`os`模块具有`chdir()`函数，例如：

```py
>>> os.chdir('/home/student/work') >>> print(os.getcwd()) /home/student/work >>> 
```

# 列出文件和目录

在 Python 中列出目录内容很容易。我们将使用`os`模块，该模块具有一个名为`listdir()`的函数，该函数将返回工作目录中文件和目录的名称：

```py
>>> os.listdir() ['Public', 'python_learning', '.ICEauthority', '.python_history', 'work', '.bashrc', 'Pictures', '.gnupg', '.cache', '.bash_logout', '.sudo_as_admin_successful', '.bash_history', '.config', '.viminfo', 'Desktop', 'Documents', 'examples.desktop', 'Videos', '.ssh', 'Templates', '.profile', 'dir', '.pam_environment', 'Downloads', '.local', '.dbus', 'Music', '.mozilla'] >>> 
```

# 重命名目录

Python 中的`os`模块具有一个`rename()`函数，可帮助更改目录的名称：

```py
>>> os.rename('work', 'work1') >>> os.listdir() ['Public', 'work1', 'python_learning', '.ICEauthority', '.python_history', '.bashrc', 'Pictures', '.gnupg', '.cache', '.bash_logout', '.sudo_as_admin_successful', '.bash_history', '.config', '.viminfo', 'Desktop', 'Documents', 'examples.desktop', 'Videos', '.ssh', 'Templates', '.profile', 'dir', '.pam_environment', 'Downloads', '.local', '.dbus', 'Music', '.mozilla'] **>>** 
```

# 复制，移动，重命名和删除数据

我们将学习系统管理员在数据上执行的四种基本操作，即复制，移动，重命名和删除。Python 有一个名为`shutil`的内置模块，可以执行这些任务。使用`shutil`模块，我们还可以对数据执行高级操作。要在程序中使用`shutil`模块，只需编写`import shutil`导入语句。`shutil`模块提供了一些支持文件复制和删除操作的函数。让我们逐一了解这些操作。

# 复制数据

在本节中，我们将看到如何使用`shutil`模块复制文件。为此，首先我们将创建一个`hello.py`文件并在其中写入一些文本。

`hello.py`：

```py
print ("") print ("Hello World\n") print ("Hello Python\n")
```

现在，我们将编写将内容复制到`shutil_copy_example.py`脚本的代码。在其中写入以下内容：

```py
import shutil import os shutil.copy('hello.py', 'welcome.py') print("Copy Successful")
```

按照以下方式运行脚本：

```py
$ python3 shutil_copy_example.py Output: Copy Successful
```

检查`welcome.py`脚本的存在，并且您将发现`hello.py`的内容已成功复制到`welcome.py`中。

# 移动数据

在这里，我们将看到如何移动数据。我们将使用`shutil.move()`来实现这个目的。`shutil.move(source, destination)`将文件从源移动到目标。现在，我们将创建一个`shutil_move_example.py`脚本，并在其中写入以下内容：

```py
import shutil shutil.move('/home/student/sample.txt', '/home/student/Desktop/.')
```

按照以下方式运行脚本：

```py
$ python3 shutil_move_example.py
```

在此脚本中，我们要移动的文件是`sample.txt`，它位于`/home/student`目录中。`/home/student`是我们的源文件夹，`/home/student/Desktop`是我们的目标文件夹。因此，在运行脚本后，`sample.txt`将从`/home/student`移动到`/home/student/Desktop`目录。

# 重命名数据

在上一节中，我们学习了如何使用`shutil.move()`将文件从源移动到目标。使用`shutil.move()`，文件可以被重命名。创建一个`shutil_rename_example.py`脚本，并在其中写入以下内容：

```py
import shutil shutil.move('hello.py', 'hello_renamed.py')
```

按照以下方式运行脚本：

```py
$ python3 shutil_rename_example.py
```

输出：

现在，检查您的文件名是否已重命名为`hello_renamed.py`。

# 删除数据

我们将学习如何使用 Python 的`os`模块删除文件和文件夹。`os`模块的`remove()`方法将删除一个文件。如果您尝试使用此方法删除目录，它将给出一个`OSError`。要删除目录，请使用`rmdir()`。

现在，创建一个`os_remove_file_directory.py`脚本，并在其中写入以下内容：

```py
import os os.remove('sample.txt') print("File removed successfully") os.rmdir('work1') print("Directory removed successfully")
```

按照以下方式运行脚本：

```py
$ python3 os_remove_file_directory.py Output: File removed successfully Directory removed successfully
```

# 处理路径

现在，我们将学习关于`os.path()`的知识。它用于路径操作。在本节中，我们将看一些`os`模块为路径名提供的函数。

启动`python3`控制台：

```py
student@ubuntu:~$ python3
Python 3.6.6 (default, Sep 12 2018, 18:26:19)
[GCC 8.0.1 20180414 (experimental) [trunk revision 259383]] on linux
Type "help", "copyright", "credits" or "license" for more information.
<q>>></q>
```

+   `os.path.absname(path)`: 返回路径名的绝对版本。

```py
>>> import os >>> os.path.abspath('sample.txt') '/home/student/work/sample.txt'
```

+   `os.path.dirname(path)`: 返回路径的目录名。

```py
>>> os.path.dirname('/home/student/work/sample.txt') '/home/student/work'
```

+   `os.path.basename(path)`: 返回路径的基本名称。

```py
>>> os.path.basename('/home/student/work/sample.txt') 'sample.txt'
```

+   `os.path.exists(path)`: 如果路径指向现有路径，则返回`True`。

```py
>>> os.path.exists('/home/student/work/sample.txt') True
```

+   `os.path.getsize(path)`: 返回以字节为单位的输入路径的大小。

```py
>>> os.path.getsize('/home/student/work/sample.txt') 39
```

+   `os.path.isfile(path)`: 检查输入的路径是否为现有文件。如果是文件，则返回`True`。

```py
>>> os.path.isfile('/home/student/work/sample.txt') True
```

+   `os.path.isdir(path)`: 检查输入的路径是否为现有目录。如果是目录，则返回`True`。

```py
>>> os.path.isdir('/home/student/work/sample.txt') False
```

# 比较数据

在这里，我们将学习如何在 Python 中比较数据。我们将使用`pandas`模块来实现这个目的。

Pandas 是一个开源的数据分析库，提供了易于使用的数据结构和数据分析工具。它使导入和分析数据变得更容易。

在开始示例之前，请确保您的系统上已安装了`pandas`。您可以按照以下方式安装 pandas：

```py
pip3 install pandas     --- For Python3 
or
 pip install pandas       --- For python2
```

我们将学习使用 pandas 比较数据的一个例子。首先，我们将创建两个`csv`文件：`student1.csv`和`student2.csv`。我们将比较这两个`csv`文件的数据，并且输出应该返回比较结果。创建两个`csv`文件如下：

创建`student1.csv`文件内容如下：

```py
Id,Name,Gender,Age,Address 101,John,Male,20,New York 102,Mary,Female,18,London 103,Aditya,Male,22,Mumbai 104,Leo,Male,22,Chicago 105,Sam,Male,21,Paris 106,Tina,Female,23,Sydney
```

创建`student2.csv`文件内容如下：

```py
Id,Name,Gender,Age,Address 101,John,Male,21,New York 102,Mary,Female,20,London 103,Aditya,Male,22,Mumbai 104,Leo,Male,23,Chicago 105,Sam,Male,21,Paris 106,Tina,Female,23,Sydney
```

现在，我们将创建一个`compare_data.py`脚本，并在其中写入以下内容：

```py
import pandas as pd df1 = pd.read_csv("student1.csv") df2 = pd.read_csv("student2.csv") s1 = set([ tuple(values) for values in df1.values.tolist()]) s2 = set([ tuple(values) for values in df2.values.tolist()]) s1.symmetric_difference(s2) print (pd.DataFrame(list(s1.difference(s2))), '\n') print (pd.DataFrame(list(s2.difference(s1))), '\n')
```

按照以下方式运行脚本：

```py
$ python3 compare_data.py Output:
 0     1       2   3         4 0  102  Mary  Female  18    London 1  104   Leo    Male  22   Chicago 2  101  John    Male  20  New York

 0     1       2   3         4 0  101  John    Male  21  New York 1  104   Leo    Male  23   Chicago 2  102  Mary  Female  20    London
```

在前面的例子中，我们正在比较两个`csv`文件之间的数据：`student1.csv`和`student2.csv`。我们首先将我们的数据帧(`df1`，`df2`)转换为集合(`s1`，`s2`)。然后，我们使用`symmetric_difference()`集合。因此，它将检查`s1`和`s2`之间的对称差异，然后我们将打印结果。

# 合并数据

我们将学习如何在 Python 中合并数据。为此，我们将使用 Python 的 pandas 库。为了合并数据，我们将使用在上一节中已创建的两个`csv`文件，`student1.csv`和`student2.csv`。

现在，创建一个`merge_data.py`脚本，并在其中写入以下代码：

```py
import pandas as pd df1 = pd.read_csv("student1.csv") df2 = pd.read_csv("student2.csv") result = pd.concat([df1, df2]) print(result)
```

按如下方式运行脚本：

```py
$ python3 merge_data.py Output:
 Id    Name  Gender  Age   Address 0  101    John    Male   20  New York 1  102    Mary  Female   18    London 2  103  Aditya    Male   22    Mumbai 3  104     Leo    Male   22   Chicago 4  105     Sam    Male   21     Paris 5  106    Tina  Female   23    Sydney 0  101    John    Male   21  New York 1  102    Mary  Female   20    London 2  103  Aditya    Male   22    Mumbai 3  104     Leo    Male   23   Chicago 4  105     Sam    Male   21     Paris 5  106    Tina  Female   23    Sydney
```

# 模式匹配文件和目录

在本节中，我们将学习有关文件和目录的模式匹配。Python 有`glob`模块，用于查找与特定模式匹配的文件和目录的名称。

现在，我们将看一个例子。首先，创建一个`pattern_match.py`脚本，并在其中写入以下内容：

```py
import glob file_match = glob.glob('*.txt') print(file_match) file_match = glob.glob('[0-9].txt') print(file_match) file_match = glob.glob('**/*.txt', recursive=True) print(file_match) file_match = glob.glob('**/', recursive=True) print(file_match)
```

按照以下方式运行脚本：

```py
$ python3 pattern_match.py Output: ['file1.txt', 'filea.txt', 'fileb.txt', 'file2.txt', '2.txt', '1.txt', 'file.txt'] ['2.txt', '1.txt'] ['file1.txt', 'filea.txt', 'fileb.txt', 'file2.txt', '2.txt', '1.txt', 'file.txt', 'dir1/3.txt', 'dir1/4.txt'] ['dir1/']
```

在上一个例子中，我们使用了 Python 的`glob`模块进行模式匹配。`glob`(路径名)将返回与路径名匹配的名称列表。在我们的脚本中，我们在三个不同的`glob()`函数中传递了三个路径名。在第一个`glob()`中，我们传递了路径名`*.txt;`，这将返回所有具有`.txt`扩展名的文件名。在第二个`glob()`中，我们传递了`[0-9].txt`，这将返回以数字开头的文件名。在第三个`glob()`中，我们传递了`**/*.txt`，它将返回文件名以及目录名。它还将返回这些目录中的文件名。在第四个`glob()`中，我们传递了`**/`，它将仅返回目录名。

# 元数据：关于数据的数据

在本节中，我们将学习`pyPdf`模块，该模块有助于从`pdf`文件中提取元数据。但首先，什么是元数据？元数据是关于数据的数据。元数据是描述主要数据的结构化信息。元数据是数据的摘要。它包含有关实际数据的基本信息。它有助于找到数据的特定实例。

确保您的目录中有`pdf`文件，您想从中提取信息。

首先，我们必须安装`pyPdf`模块，如下所示：

```py
pip install pyPdf
```

现在，我们将编写一个`metadata_example.py`脚本，并查看如何从中获取元数据信息。我们将在 Python 2 中编写此脚本：

```py
import pyPdf def main():
 file_name = '/home/student/sample_pdf.pdf' pdfFile = pyPdf.PdfFileReader(file(file_name,'rb')) pdf_data = pdfFile.getDocumentInfo() print ("----Metadata of the file----") for md in pdf_data: print (md+ ":" +pdf_data[md]) if __name__ == '__main__':
 main()
```

按照以下方式运行脚本：

```py
student@ubuntu:~$ python metadata_example.py ----Metadata of the file---- /Producer:Acrobat Distiller Command 3.0 for SunOS 4.1.3 and later (SPARC) /CreationDate:D:19980930143358
```

在前面的脚本中，我们使用了 Python 2 的`pyPdf`模块。首先，我们创建了一个`file_name`变量，用于存储我们的`pdf`的路径。使用`PdfFileReader()`，数据被读取。`pdf_data`变量将保存有关您的`pdf`的信息。最后，我们编写了一个 for 循环来获取元数据信息。

# 压缩和恢复

在本节中，我们将学习`shutil`模块的`make_archive()`函数，该函数将压缩整个目录。为此，我们将编写一个`compress_a_directory.py`脚本，并在其中写入以下内容：

```py
import shutil shutil.make_archive('work', 'zip', 'work/')
```

按照以下方式运行脚本：

```py
$ python3 compress_a_directory.py
```

在前面的脚本中，在`shutil.make_archive()`函数中，我们将第一个参数作为我们压缩文件的名称。`zip`将是我们的压缩技术。然后，`work/`将是我们要压缩的目录的名称。

现在，要从压缩文件中恢复数据，我们将使用`shutil`模块的`unpack_archive()`函数。创建一个`unzip_a_directory.py`脚本，并在其中写入以下内容：

```py
import shutil shutil.unpack_archive('work1.zip')
```

按照以下方式运行脚本：

```py
$ python3 unzip_a_directory.py
```

现在，检查您的目录。解压目录后，您将获得所有内容。

# 使用 tarfile 模块创建 TAR 存档

本节将帮助您了解如何使用 Python 的`tarfile`模块创建 tar 存档。

`tarfile`模块用于使用`gzip`、`bz2`压缩技术读取和写入 tar 存档。确保必要的文件和目录存在。现在，创建一个`tarfile_example.py`脚本，并在其中写入以下内容：

```py
import tarfile tar_file = tarfile.open("work.tar.gz", "w:gz") for name in ["welcome.py", "hello.py", "hello.txt", "sample.txt", "sample1.txt"]:
 tar_file.add(name) tar_file.close()
```

按照以下方式运行脚本：

```py
$ python3 tarfile_example.py
```

现在，检查您当前的工作目录；您会看到`work.tar.gz`已经被创建。

# 使用 tarfile 模块检查 TAR 文件的内容

在本节中，我们将学习如何在不实际提取 tar 文件的情况下检查已创建的 tar 存档的内容。我们将使用 Python 的`tarfile`模块进行操作。

创建一个`examine_tar_file_content.py`脚本，并在其中写入以下内容：

```py
import tarfile tar_file = tarfile.open("work.tar.gz", "r:gz") print(tar_file.getnames())
```

按照以下方式运行脚本：

```py
$ python3 examine_tar_file_content.py Output: ['welcome.py', 'hello.py', 'hello.txt', 'sample.txt', 'sample1.txt']
```

在先前的示例中，我们使用了`tarfile`模块来检查创建的 tar 文件的内容。我们使用了`getnames()`函数来读取数据。

# 总结

在本章中，我们学习了处理文件和目录的 Python 脚本。我们还学习了如何使用`os`模块处理目录。我们学习了如何复制、移动、重命名和删除文件和目录。我们还学习了 Python 中的 pandas 模块，用于比较和合并数据。我们学习了如何创建 tar 文件并使用`tarfile`模块读取 tar 文件的内容。我们还在搜索文件和目录时进行了模式匹配。

在下一章中，我们将学习`tar`存档和 ZIP 创建。

# 问题

1.  如何处理不同路径，而不考虑不同的操作系统（Windows，Llinux）？

1.  Python 中`print()`的不同参数是什么？

1.  在 Python 中，`dir()`关键字的用途是什么？

1.  `pandas`中的数据框，系列是什么？

1.  什么是列表推导？

1.  我们可以使用集合推导和字典推导吗？如果可以，如何操作？

1.  如何使用 pandas dataframe 打印第一个/最后一个`N`行？

1.  使用列表推导编写一个打印奇数的程序

1.  `sys.argv` 的类型是什么？

1.  a) 集合

1.  b) 列表

1.  c) 元组

1.  d) 字符串

# 进一步阅读

+   `pathlib` 文档： [`docs.python.org/3/library/pathlib.html`](https://docs.python.org/3/library/pathlib.html)

+   [`pandas` 文档：](https://pandas.pydata.org/pandas-docs/stable/)[`pandas.pydata.org/pandas-docs/stable/`](https://pandas.pydata.org/pandas-docs/stable/)

+   `os` 模块文档：[`docs.python.org/3/library/os.html`](https://docs.python.org/3/library/os.html)


# 第六章：文件存档、加密和解密

在上一章中，我们学习了如何处理文件、目录和数据。我们还学习了`tarfile`模块。在本章中，我们将学习文件存档、加密和解密。存档在管理文件、目录和数据方面起着重要作用。但首先，什么是存档？存档是将文件和目录存储到单个文件中的过程。Python 有`tarfile`模块用于创建这样的存档文件。

在本章中，我们将涵盖以下主题：

+   创建和解压存档

+   Tar 存档

+   ZIP 创建

+   文件加密和解密

# 创建和解压存档

在本节中，我们将学习如何使用 Python 的`shutil`模块创建和解压存档。`shutil`模块有`make_archive()`函数，用于创建新的存档文件。使用`make_archive()`，我们可以存档整个目录及其内容。

# 创建存档

现在，我们将编写一个名为`shutil_make_archive.py`的脚本，并在其中编写以下内容：

```py
import tarfile
import shutil
import sys

shutil.make_archive(
 'work_sample', 'gztar',
 root_dir='..',
 base_dir='work',
)
print('Archive contents:')
with tarfile.open('work_sample.tar.gz', 'r') as t_file:
 for names in t_file.getnames():
 print(names)
```

运行程序，您将得到以下输出：

```py
$ python3 shutil_make_archive.py
Archive contents:
work
work/bye.py
work/shutil_make_archive.py
work/welcome.py
work/hello.py
```

在前面的例子中，为了创建一个存档文件，我们使用了 Python 的`shutil`和`tarfile`模块。在`shutil.make_archive()`中，我们指定了`work_sample`，这将是存档文件的名称，并且将以`gz`格式。我们在基本目录属性中指定了我们的工作目录名称。最后，我们打印了已存档的文件的名称。

# 解压存档

要解压缩存档，`shutil`模块有`unpack_archive()`函数。使用此函数，我们可以提取存档文件。我们传递了存档文件名和我们想要提取内容的目录。如果没有传递目录名称，则它将提取内容到您当前的工作目录中。

现在，创建一个名为`shutil_unpack_archive.py`的脚本，并在其中编写以下代码：

```py
import pathlib
import shutil
import sys
import tempfile
with tempfile.TemporaryDirectory() as d:
 shutil.unpack_archive('work_sample.tar.gz', extract_dir='/home/student/work',)
 prefix_len = len(d) + 1
 for extracted in pathlib.Path(d).rglob('*'):
 print(str(extracted)[prefix_len:])
```

按照以下方式运行脚本：

```py
student@ubuntu:~/work$ python3 shutil_unpack_archive.py
```

现在，检查您的`work/`目录，您将在其中找到`work/`文件夹，其中将有提取的文件。

# Tar 存档

在本节中，我们将学习`tarfile`模块。我们还将学习如何测试输入的文件名，评估它是否是有效的存档文件。我们将看看如何将新文件添加到已存档的文件中，如何使用`tarfile`模块读取元数据，以及如何使用`extractall()`函数从存档中提取文件。

首先，我们将测试输入的文件名是否是有效的存档文件。为了测试这一点，`tarfile`模块有`is_tarfile()`函数，它返回一个布尔值。

创建一个名为`check_archive_file.py`的脚本，并在其中编写以下内容：

```py
import tarfile

for f_name in ['hello.py', 'work.tar.gz', 'welcome.py', 'nofile.tar', 'sample.tar.xz']:
 try:
 print('{:} {}'.format(f_name, tarfile.is_tarfile(f_name)))
 except IOError as err:
 print('{:} {}'.format(f_name, err))
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 check_archive_file.py
hello.py          False
work.tar.gz      True
welcome.py     False
nofile.tar         [Errno 2] No such file or directory: 'nofile.tar'
sample.tar.xz   True
```

因此，`tarfile.is_tarfile()`将检查列表中提到的每个文件名。`hello.py，welcome.py`文件不是 tar 文件，所以我们得到了一个布尔值`False`。`work.tar.gz`和`sample.tar.xz`是 tar 文件，所以我们得到了布尔值`True`。而我们的目录中没有`nofile.tar`这样的文件，所以我们得到了一个异常，因为我们在脚本中写了它。

现在，我们将在已创建的存档文件中添加一个新文件。创建一个名为`add_to_archive.py`的脚本，并在其中编写以下代码：

```py
import shutil
import os
import tarfile
print('creating archive')
shutil.make_archive('work', 'tar', root_dir='..', base_dir='work',)
print('\nArchive contents:')
with tarfile.open('work.tar', 'r') as t_file:
 for names in t_file.getnames():
 print(names)
os.system('touch sample.txt')
print('adding sample.txt')
with tarfile.open('work.tar', mode='a') as t:
 t.add('sample.txt')
print('contents:',)
with tarfile.open('work.tar', mode='r') as t:
 print([m.name for m in t.getmembers()])
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 add_to_archive.py
Output :
creating archive
Archive contents:
work
work/bye.py
work/shutil_make_archive.py
work/check_archive_file.py
work/welcome.py
work/add_to_archive.py
work/shutil_unpack_archive.py
work/hello.py
adding sample.txt
contents:
['work', 'work/bye.py', 'work/shutil_make_archive.py', 'work/check_archive_file.py', 'work/welcome.py', 'work/add_to_archive.py', 'work/shutil_unpack_archive.py', 'work/hello.py', 'sample.txt']
```

在这个例子中，我们首先使用`shutil.make_archive()`创建了一个存档文件，然后打印了存档文件的内容。然后我们在下一个语句中创建了一个`sample.txt`文件。现在，我们想要将`sample.txt`添加到已创建的`work.tar`中。在这里，我们使用了追加模式`a`。接下来，我们再次显示存档文件的内容。

现在，我们将学习如何从存档文件中读取元数据。`getmembers()`函数将加载文件的元数据。创建一个名为`read_metadata.py`的脚本，并在其中编写以下内容：

```py
import tarfile
import time
with tarfile.open('work.tar', 'r') as t:
 for file_info in t.getmembers():
 print(file_info.name)
 print("Size   :", file_info.size, 'bytes')
 print("Type   :", file_info.type)
 print()
```

运行脚本，你将得到以下输出：

```py
student@ubuntu:~/work$ python3 read_metadata.py
Output:
work/bye.py
Size : 30 bytes
Type : b'0' 
work/shutil_make_archive.py
Size : 243 bytes
Type : b'0'
work/check_archive_file.py
Size : 233 bytes
Type : b'0'

work/welcome.py
Size : 48 bytes
Type : b'0'

work/add_to_archive.py
Size : 491 bytes
Type : b'0'

work/shutil_unpack_archive.py
Size : 279 bytes
Type : b'0'
```

现在，我们将使用`extractall()`函数从存档中提取内容。为此，创建一个名为`extract_contents.py`的脚本，并在其中写入以下代码：

```py
import tarfile
import os
os.mkdir('work')
with tarfile.open('work.tar', 'r') as t:
 t.extractall('work')
print(os.listdir('work'))
```

运行脚本，你将得到以下输出：

```py
student@ubuntu:~/work$ python3 extract_contents.py
```

检查你的当前工作目录，你会发现`work/`目录。导航到该目录，你可以找到你提取的文件。

# ZIP 创建

在本节中，我们将学习关于 ZIP 文件的知识。我们将学习`python`的`zipfile`模块，如何创建 ZIP 文件，如何测试输入的文件名是否是有效的`zip`文件名，读取元数据等等。

首先，我们将学习如何使用`shutil`模块的`make_archive()`函数创建一个`zip`文件。创建一个名为`make_zip_file.py`的脚本，并在其中写入以下代码：

```py
import shutil
shutil.make_archive('work', 'zip', 'work')
```

按如下方式运行脚本：

```py
student@ubuntu:~$ python3 make_zip_file.py
```

现在检查你的当前工作目录，你会看到`work.zip`。

现在，我们将测试输入的文件名是否是一个`zip`文件。为此，`zipfile`模块有`is_zipfile()`函数。

创建一个名为`check_zip_file.py`的脚本，并在其中写入以下内容：

```py
import zipfile
for f_name in ['hello.py', 'work.zip', 'welcome.py', 'sample.txt', 'test.zip']:
 try:
 print('{:}           {}'.format(f_name, zipfile.is_zipfile(f_name)))
 except IOError as err:
 print('{:}           {}'.format(f_name, err))
```

按如下方式运行脚本：

```py
student@ubuntu:~$ python3 check_zip_file.py
Output :
hello.py          False
work.zip         True
welcome.py     False
sample.txt       False
test.zip            True
```

在这个例子中，我们使用了一个`for`循环，我们在其中检查列表中的文件名。`is_zipfile()`函数将逐个检查文件名，并将布尔值作为结果。

现在，我们将看看如何使用 Python 的`zipfile`模块从存档的 ZIP 文件中读取元数据。创建一个名为`read_metadata.py`的脚本，并在其中写入以下内容：

```py
import zipfile

def meta_info(names):
 with zipfile.ZipFile(names) as zf:
 for info in zf.infolist():
 print(info.filename)
 if info.create_system == 0:
 system = 'Windows'
 elif info.create_system == 3:
 system = 'Unix'
 else:
 system = 'UNKNOWN'
 print("System         :", system)
 print("Zip Version    :", info.create_version)
 print("Compressed     :", info.compress_size, 'bytes')
 print("Uncompressed   :", info.file_size, 'bytes')
 print()

if __name__ == '__main__':
 meta_info('work.zip')
```

按如下方式执行脚本：

```py
student@ubuntu:~$ python3 read_metadata.py
Output:
sample.txt
System         : Unix
Zip Version    : 20
Compressed     : 2 bytes
Uncompressed   : 0 bytes

bye.py
System         : Unix
Zip Version    : 20
Compressed     : 32 bytes
Uncompressed   : 30 bytes

extract_contents.py
System         : Unix
Zip Version    : 20
Compressed     : 95 bytes
Uncompressed   : 132 bytes

shutil_make_archive.py
System         : Unix
Zip Version    : 20
Compressed     : 160 bytes
Uncompressed   : 243 bytes
```

为了获取`zip`文件的元数据信息，我们使用了`ZipFile`类的`infolist()`方法。

# 文件加密和解密

在本节中，我们将学习 Python 的`pyAesCrypt`模块。`pyAesCrypt`是一个文件加密模块，它使用`AES256-CBC`来加密/解密文件和二进制流。

按如下方式安装`pyAesCrypt`：

```py
pip3 install pyAesCrypt
```

创建一个名为`file_encrypt.py`的脚本，并在其中写入以下代码：

```py
import pyAesCrypt

from os import stat, remove
# encryption/decryption buffer size - 64K
bufferSize = 64 * 1024
password = "#Training"
with open("sample.txt", "rb") as fIn:
 with open("sample.txt.aes", "wb") as fOut:
 pyAesCrypt.encryptStream(fIn, fOut, password, bufferSize)
# get encrypted file size
encFileSize = stat("sample.txt.aes").st_size 
```

按如下方式运行脚本：

```py
student@ubuntu:~/work$ python3 file_encrypt.py
Output :
```

请检查你的当前工作目录。你会在其中找到加密文件`sample.txt.aes`。

在这个例子中，我们已经提到了缓冲区大小和密码。接下来，我们提到了要加密的文件名。在`encryptStream`中，我们提到了`fIn`，这是我们要加密的文件，以及`fOut`，这是我们加密后的文件名。我们将加密后的文件存储为`sample.txt.aes`。

现在，我们将解密`sample.txt.aes`文件以获取文件内容。创建一个名为`file_decrypt.py`的脚本，并在其中写入以下内容：

```py
import pyAesCrypt
from os import stat, remove
bufferSize = 64 * 1024
password = "#Training"
encFileSize = stat("sample.txt.aes").st_size
with open("sample.txt.aes", "rb") as fIn:
 with open("sampleout.txt", "wb") as fOut:
 try:
 pyAesCrypt.decryptStream(fIn, fOut, password, bufferSize, encFileSize)
 except ValueError:
 remove("sampleout.txt")
```

按如下方式运行脚本：

```py
student@ubuntu:~/work$ python3 file_decrypt.py
```

现在，检查你的当前工作目录。将会创建一个名为`sampleout.txt`的文件。那就是你的解密文件。

在这个例子中，我们提到了要解密的文件名，即`sample.txt.aes`。接下来，我们的解密文件将是`sampleout.txt`。在`decryptStream()`中，我们提到了`fIn`，这是我们要解密的文件，以及`fOut`，这是`解密`文件的名称。

# 总结

在本章中，我们学习了如何创建和提取存档文件。存档在管理文件、目录和数据方面起着重要作用。它还将文件和目录存储到一个单一文件中。

我们详细学习了 Python 模块`tarfile`和`zipfile`，它们使你能够创建、提取和测试存档文件。你将能够将一个新文件添加到已存档的文件中，读取元数据，从存档中提取文件。你还学习了使用`pyAescrypt`模块进行文件加密和解密。

在下一章中，你将学习 Python 中的文本处理和正则表达式。Python 有一个非常强大的库叫做正则表达式，它可以执行搜索和提取数据等任务。

# 问题

1.  我们能使用密码保护来压缩数据吗？如果可以，怎么做？

1.  什么是 Python 中的上下文管理器？

1.  什么是 pickling 和 unpickling？

1.  Python 中有哪些不同类型的函数？

# 进一步阅读

+   数据压缩和归档：[`docs.python.org/3/library/archiving.html`](https://docs.python.org/3/library/archiving.html)

+   `tempfile`文档：[`docs.python.org/2/library/tempfile.html`](https://docs.python.org/2/library/tempfile.html)

+   密码学 Python 文档：[`docs.python.org/3/library/crypto.html`](https://docs.python.org/3/library/crypto.html)

+   `shutil`文档：[`docs.python.org/3/library/shutil.html`](https://docs.python.org/3/library/shutil.html)


# 第七章：文本处理和正则表达式

在本章中，我们将学习有关文本处理和正则表达式的知识。文本处理是创建或修改文本的过程。Python 有一个非常强大的名为正则表达式的库，可以执行搜索和提取数据等任务。您将学习如何在文件中执行此操作，还将学习读取和写入文件。

我们将学习有关 Python 正则表达式和处理文本的`re`模块。我们将学习`re`模块的`match()`、`search()`、`findall()`和`sub()`函数。我们还将学习使用`textwrap`模块在 Python 中进行文本包装。最后，我们将学习有关 Unicode 字符。

在本章中，我们将涵盖以下主题：

+   文本包装

+   正则表达式

+   Unicode 字符串

# 文本包装

在本节中，我们将学习有关`textwrap` Python 模块。该模块提供了执行所有工作的`TextWrapper`类。`textwrap`模块用于格式化和包装纯文本。该模块提供了五个主要函数：`wrap()`、`fill()`、`dedent()`、`indent()`和`shorten()`。我们现在将逐一学习这些函数。

# wrap()函数

`wrap()`函数用于将整个段落包装成单个字符串。输出将是输出行的列表。

语法是`textwrap.wrap(text, width)`：

+   `text`：要包装的文本。

+   `width`：包装行的最大长度。默认值为`70`。

现在，我们将看到`wrap()`的一个示例。创建一个`wrap_example.py`脚本，并在其中写入以下内容：

```py
import textwrap

sample_string = '''Python is an interpreted high-level programming language for general-purpose programming. Created by Guido van Rossum and first released in 1991, Python has a design philosophy that emphasizes code readability, notably using significant whitespace.'''

w = textwrap.wrap(text=sample_string, width=30)
print(w)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 wrap_example.py
['Python is an interpreted high-', 'level programming language for', 'general-purpose programming.', 'Created by Guido van Rossum', 'and first released in', '1991, Python has a design', 'philosophy that emphasizes', 'code readability,  notably', 'using significant whitespace.']
```

在前面的示例中，我们使用了 Python 的`textwrap`模块。首先，我们创建了一个名为`sample_string`的字符串。接下来，使用`TextWrapper`类指定了宽度。然后，使用`wrap`函数将字符串包装到宽度为`30`。然后，我们打印了这些行。

# fill()函数

`fill()`函数与`textwrap.wrap`类似，只是它返回连接成单个以换行符分隔的字符串的数据。此函数将文本包装并返回包含包装文本的单个字符串。

此函数的语法是：

```py
textwrap.fill(text, width)
```

+   `text`：要包装的文本。

+   `width`：包装行的最大长度。默认值为`70`。

现在，我们将看到`fill()`的一个示例。创建一个`fill_example.py`脚本，并在其中写入以下内容：

```py
import textwrap  sample_string = '''Python is an interpreted high-level programming language.'''  w = textwrap.fill(text=sample_string, width=50) print(w)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 fill_example.py
Python is an interpreted high-level programming
language.
```

在前面的示例中，我们使用了`fill()`函数。过程与我们在`wrap()`中所做的相同。首先，我们创建了一个字符串变量。接下来，我们创建了`textwrap`对象。然后，我们应用了`fill()`函数。最后，我们打印了输出。

# dedent()函数

`dedent()`是`textwrap`模块的另一个函数。此函数从文本的每一行中删除常见的前导`空格`。

此函数的语法如下：

```py
 textwrap.dedent(text)
```

`text`是要`dedent`的文本。

现在，我们将看到`dedent()`的一个示例。创建一个`dedent_example.py`脚本，并在其中写入以下内容：

```py
import textwrap  str1 = ''' Hello Python World \tThis is Python 101 Scripting language\n Python is an interpreted high-level programming language for general-purpose programming. ''' print("Original: \n", str1) print()  t = textwrap.dedent(str1) print("Dedented: \n", t)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 dedent_example.py 
Hello Python World   This is Python 101
Scripting language

Python is an interpreted high-level programming language for general-purpose programming.
```

在前面的示例中，我们创建了一个`str1`字符串变量。然后我们使用`textwrap.dedent()`来删除常见的前导空格。制表符和空格被视为空格，但它们不相等。因此，唯一的常见空格，在我们的情况下是`tab`，被移除。

# indent()函数

`indent()`函数用于在文本的选定行开头添加指定的前缀。

此函数的语法是：

```py
 textwrap.indent(text, prefix)
```

+   `text`：主字符串

+   `prefix`：要添加的前缀

创建一个`indent_example.py`脚本，并在其中写入以下内容：

```py
import textwrap  str1 = "Python is an interpreted high-level programming language for general-purpose programming. Created by Guido van Rossum and first released in 1991, \n\nPython has a design philosophy that emphasizes code readability, notably using significant whitespace."  w = textwrap.fill(str1, width=30) i = textwrap.indent(w, '*') print(i)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 indent_example.py *Python is an interpreted high- *level programming language for *general-purpose programming. *Created by Guido van Rossum *and first released in 1991, *Python has a design philosophy *that emphasizes code *readability, notably using *significant whitespace.
```

在上面的示例中，我们使用了`textwrap`模块的`fill()`和`indent()`函数。首先，我们使用`fill`方法将数据存储到变量`w`中。接下来，我们使用了`indent`方法。使用`indent()`，输出中的每一行都将有一个`*`前缀。然后，我们打印了输出。

# shorten()函数

`textwrap`模块的这个函数用于将文本截断以适应指定的宽度。例如，如果您想要创建摘要或预览，请使用`shorten()`函数。使用`shorten()`，文本中的所有空格将被标准化为单个空格。

此函数的语法是：

```py
            textwrap.shorten(text, width)
```

现在我们将看一个`shorten()`的例子。创建一个`shorten_example.py`脚本，并在其中写入以下内容：

```py
import textwrap str1 = "Python is an interpreted high-level programming language for general-purpose programming. Created by Guido van Rossum and first released in 1991, \n\nPython has a design philosophy that emphasizes code readability, notably using significant whitespace." s = textwrap.shorten(str1, width=50) print(s)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 shorten_example.py Python is an interpreted high-level [...]
```

在上面的示例中，我们使用了`shorten()`函数来截断我们的文本，并将该文本适应指定的宽度。首先，所有空格都被截断为单个空格。如果结果适合指定的宽度，则结果将显示在屏幕上。如果不适合，则指定宽度的单词将显示在屏幕上，其余部分将放在占位符中。

# 正则表达式

在本节中，我们将学习 Python 中的正则表达式。正则表达式是一种专门的编程语言，它嵌入在 Python 中，并通过`re`模块提供给用户使用。我们可以定义要匹配的字符串集的规则。使用正则表达式，我们可以从文件、代码、文档、电子表格等中提取特定信息。

在 Python 中，正则表达式表示为`re`，可以通过`re`模块导入。正则表达式支持四种功能：

+   标识符

+   修饰符

+   空白字符

+   标志

下表列出了标识符，并对每个标识符进行了描述：

| **标识符** | **描述** |
| --- | --- |
| `\w` | 匹配字母数字字符，包括下划线(`_`) |
| `\W` | 匹配非字母数字字符，不包括下划线(`_`) |
| `\d` | 匹配数字 |
| `\D` | 匹配非数字 |
| `\s` | 匹配空格 |
| `\S` | 匹配除空格之外的任何字符 |
| `.` | 匹配句号(`.`) |
| `\b` | 匹配除换行符之外的任何字符 |

下表列出了修饰符，并对每个修饰符进行了描述：

| **修饰符** | **描述** |
| --- | --- |
| `^` | 匹配字符串的开头 |
| `$` | 匹配字符串的结尾 |
| `?` | 匹配`0`或`1` |
| `*` | 匹配`0`或更多 |
| `+` | 匹配`1`或更多 |
| `&#124;` | 匹配`x/y`中的任意一个 |
| `[ ]` | 匹配范围 |
| `{x}` | 前置代码的数量 |

下表列出了空白字符，并对每个字符进行了描述：

| **字符** | **描述** |
| --- | --- |
| `\s` | 空格 |
| `\t` | 制表符 |
| `\n` | 换行 |
| `\e` | 转义 |
| `\f` | 换页符 |
| `\r` | 回车 |

下表列出了标志，并对每个标志进行了描述：

| **标志** | **描述** |
| --- | --- |
| `re.IGNORECASE` | 不区分大小写匹配 |
| `re.DOTALL` | 匹配包括换行符在内的任何字符 |
| `re.MULTILINE` | 多行匹配 |
| `Re.ASCII` | 仅使转义匹配 ASCII 字符 |

现在我们将看一些正则表达式的示例。我们将学习`match()`、`search()`、`findall()`和`sub()`函数。

要在 Python 中使用正则表达式，必须在脚本中导入`re`模块，以便能够使用正则表达式的所有函数和方法。

现在我们将逐一学习这些功能。

# match()函数

`match()`函数是`re`模块的一个函数。此函数将使用指定的`re`模式与字符串匹配。如果找到匹配项，将返回一个`match`对象。`match`对象将包含有关匹配的信息。如果找不到匹配项，我们将得到结果为`None`。`match`对象有两种方法：

+   `group(num)`: 返回整个匹配

+   `groups()`: 返回一个元组中的所有匹配子组

这个函数的语法如下：

```py
re.match(pattern, string)
```

现在，我们要看一个`re.match()`的例子。创建一个`re_match.py`脚本，并在其中写入以下内容：

```py
import re  str_line = "This is python tutorial. Do you enjoy learning python ?" obj = re.match(r'(.*) enjoy (.*?) .*', str_line) if obj:
 print(obj.groups())
```

运行脚本，你会得到以下输出：

```py
student@ubuntu:~/work$ python3 re_match.py
('This is python tutorial. Do you', 'learning')
```

在前面的脚本中，我们导入了`re`模块以在 Python 中使用正则表达式。然后我们创建了一个`str_line`字符串。接下来，我们创建了一个`obj`匹配对象，并将匹配模式的结果存储在其中。在这个例子中，`(.*) enjoy (.*?) .*`模式将打印`enjoy`关键字之前的所有内容，并且只会打印`enjoy`关键字之后的一个单词。接下来，我们使用了`match`对象的`groups()`方法。它将以元组的形式打印所有匹配的子字符串。因此，你将得到的输出是，`('This is python tutorial. Do you', 'learning')`。

# search()函数

`re`模块的`search()`函数将在字符串中搜索。它将寻找指定的`re`模式的任何位置。`search()`将接受一个模式和文本，并在我们指定的字符串中搜索匹配项。当找到匹配项时，它将返回一个`match`对象。如果找不到匹配项，它将返回`None`。`match`对象有两个方法：

+   `group(num)`: 返回整个匹配

+   `groups()`: 返回一个元组中的所有匹配子组

这个函数的语法如下：

```py
re.search(pattern, string)
```

创建一个`re_search.py`脚本，并在其中写入以下内容：

```py
import re pattern = ['programming', 'hello'] str_line = 'Python programming is fun' for p in pattern:
 print("Searching for %s in %s" % (p, str_line)) if re.search(p, str_line): print("Match found") else: print("No match found")
```

运行脚本，你会得到以下输出：

```py
student@ubuntu:~/work$ python3 re_search.py Searching for programming in Python programming is fun Match found Searching for hello in Python programming is fun No match found
```

在前面的例子中，我们使用了`match`对象的`search()`方法来查找`re`模式。在导入 re 模块之后，我们在列表中指定了模式。在那个列表中，我们写了两个字符串：`programming`和`hello`。接下来，我们创建了一个字符串：`Python programming is fun`。我们写了一个 for 循环，它将逐个检查指定的模式。如果找到匹配项，将执行`if`块。如果找不到匹配项，将执行`else`块。

# findall()函数

这是`match`对象的方法之一。`findall()`方法找到所有匹配项，然后将它们作为字符串列表返回。列表的每个元素表示一个匹配项。此方法搜索模式而不重叠。

创建一个`re_findall_example.py`脚本，并在其中写入以下内容：

```py
import re pattern = 'Red' colors = 'Red, Blue, Black, Red, Green' p = re.findall(pattern, colors) print(p) str_line = 'Peter Piper picked a peck of pickled peppers. How many pickled peppers did Peter Piper pick?' pt = re.findall('pe\w+', str_line) pt1 = re.findall('pic\w+', str_line) print(pt) print(pt1) line = 'Hello hello HELLO bye' p = re.findall('he\w+', line, re.IGNORECASE) print(p)
```

运行脚本，你会得到以下输出：

```py
student@ubuntu:~/work$ python3 re_findall_example.py
['Red', 'Red']
['per', 'peck', 'peppers', 'peppers', 'per']
['picked', 'pickled', 'pickled', 'pick']
['Hello', 'hello', 'HELLO']
```

在前面的脚本中，我们写了`findall()`方法的三个例子。在第一个例子中，我们定义了一个模式和一个字符串。我们使用`findall()`方法从字符串中找到该模式，然后打印它。在第二个例子中，我们创建了一个字符串，然后使用`findall()`找到前两个字母是`pe`的单词，并打印它们。我们将得到前两个字母是`pe`的单词列表。

此外，我们找到了前三个字母是`pic`的单词，然后打印它们。在这里，我们也会得到字符串列表。在第三个例子中，我们创建了一个字符串，在其中我们指定了大写和小写的`hello`，还有一个单词：`bye`。使用`findall()`，我们找到了前两个字母是`he`的单词。同样在`findall()`中，我们使用了一个`re.IGNORECASE`标志，它会忽略单词的大小写并打印它们。

# sub()函数

这是 re 模块中最重要的函数之一。`sub()`用于用指定的替换字符串替换`re`模式。它将用替换字符串替换`re`模式的所有出现。语法如下：

```py
   re.sub(pattern, repl_str, string, count=0)
```

+   `pattern`: `re`模式。

+   `repl_str`: 替换字符串。

+   `string`: 主字符串。

+   `count`: 要替换的出现次数。默认值为`0`，表示替换所有出现。

现在我们要创建一个`re_sub.py`脚本，并在其中写入以下内容：

```py
import re

str_line = 'Peter Piper picked a peck of pickled peppers. How many pickled peppers did Peter Piper pick?'

print("Original: ", str_line)
p = re.sub('Peter', 'Mary', str_line)
print("Replaced: ", p)

p = re.sub('Peter', 'Mary', str_line, count=1)
print("Replacing only one occurrence of Peter… ")
print("Replaced: ", p)
```

运行脚本，你会得到以下输出：

```py
student@ubuntu:~/work$ python3 re_sub.py
Original:  Peter Piper picked a peck of pickled peppers. How many pickled peppers did Peter Piper pick?
Replaced:  Mary Piper picked a peck of pickled peppers. How many pickled peppers did Mary Piper pick?
Replacing only one occurrence of Peter...
Replaced:  Mary Piper picked a peck of pickled peppers. How many pickled peppers did Peter Piper pick?
```

在上面的例子中，我们使用`sub()`来用指定的替换字符串替换`re`模式。我们用 Mary 替换了 Peter。所以，所有的 Peter 都将被替换为 Mary。接下来，我们还包括了`count`参数。我们提到了`count=1`：这意味着只有一个 Peter 的出现将被替换，其他的 Peter 的出现将保持不变。

现在，我们将学习 re 模块的`subn()`函数。`subn()`函数与`sub()`的功能相同，但还有额外的功能。`subn()`函数将返回一个包含新字符串和执行的替换次数的元组。让我们看一个`subn()`的例子。创建一个`re_subn.py`脚本，并在其中写入以下内容：

```py
import re

print("str1:- ")
str1 = "Sky is blue. Sky is beautiful."

print("Original: ", str1)
p = re.subn('beautiful', 'stunning', str1)
print("Replaced: ", p)
print()

print("str_line:- ")
str_line = 'Peter Piper picked a peck of pickled peppers. How many pickled peppers did Peter Piper pick?'

print("Original: ", str_line)
p = re.subn('Peter', 'Mary', str_line)
print("Replaced: ", p)
```

运行脚本，您将得到以下输出：

```py
student@ubuntu:~/work$ python3 re_subn.py
str1:-
Original:  Sky is blue. Sky is beautiful.
Replaced:  ('Sky is blue. Sky is stunning.', 1)

str_line:-
Original:  Peter Piper picked a peck of pickled peppers. How many pickled peppers did Peter Piper pick?
Replaced:  ('Mary Piper picked a peck of pickled peppers. How many pickled peppers did Mary Piper pick?', 2)
```

在上面的例子中，我们使用了`subn()`函数来替换 RE 模式。结果，我们得到了一个包含替换后的字符串和替换次数的元组。

# Unicode 字符串

在本节中，我们将学习如何在 Python 中打印 Unicode 字符串。Python 以一种非常简单的方式处理 Unicode 字符串。字符串类型实际上保存的是 Unicode 字符串，而不是字节序列。

在您的系统中启动`python3`控制台，并开始编写以下内容：

```py
student@ubuntu:~/work$ python3
Python 3.6.6 (default, Sep 12 2018, 18:26:19)
[GCC 8.0.1 20180414 (experimental) [trunk revision 259383]] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 
>>> print ('\u2713')

>>> print ('\u2724')

>>> print ('\u2750')

>>> print ('\u2780')

>>> chinese = '\u4e16\u754c\u60a8\u597d!
>>> chinese
![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/5088de25-a7d1-4cde-8821-03151178533d.png) ----- (Meaning “Hello world!”)
>>>
>>> s = '\u092E\u0941\u0902\u092C\u0908'
>>> s
'मुंबई'                            ------(Unicode translated in Marathi)
>>>
>>> s = '\u10d2\u10d0\u10db\u10d0\u10e0\u10ef\u10dd\u10d1\u10d0'
>>> s
'გამარჯობა'                 ------(Meaning “Hello” in Georgian)
>>>
>>> s = '\u03b3\u03b5\u03b9\u03b1\u03c3\u03b1\u03c2'
>>> s
'γειασας'                     ------(Meaning “Hello” in Greek)
>>> 
```

# Unicode 代码点

在本节中，我们将学习 Unicode 代码点。Python 有一个强大的内置函数`ord()`，用于从给定字符获取 Unicode 代码点。因此，让我们看一个从字符获取 Unicode 代码点的例子，如下所示：

```py
>>> str1 = u'Office'
>>> for char in str1:
... print('U+%04x' % ord(char))
...
U+004f
U+0066
U+0066
U+0069
U+0063
U+0065
>>> str2 = ![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-sc-sys-adm/img/89322582-8eec-4421-a610-31da6e1876bf.png)
>>> for char in str2:
... print('U+%04x' % ord(char))
...
U+4e2d
U+6587

```

# 编码

从 Unicode 代码点到字节字符串的转换称为编码。因此，让我们看一个将 Unicode 代码点编码的例子，如下所示：

```py
>>> str = u'Office'
>>> enc_str = type(str.encode('utf-8'))
>>> enc_str
<class 'bytes'>
```

# 解码

从字节字符串到 Unicode 代码点的转换称为解码。因此，让我们看一个将字节字符串解码为 Unicode 代码点的例子，如下所示：

```py
>>> str = bytes('Office', encoding='utf-8')
>>> dec_str = str.decode('utf-8')
>>> dec_str
'Office'
```

# 避免 UnicodeDecodeError

每当字节字符串无法解码为 Unicode 代码点时，就会发生`UnicodeDecodeError`。为了避免这种异常，我们可以在`decode`的`error`参数中传递`replace`、`backslashreplace`或`ignore`，如下所示：

```py
>>> str = b"\xaf"
>>> str.decode('utf-8', 'strict')
 Traceback (most recent call last):
 File "<stdin>", line 1, in <module>
UnicodeDecodeError: 'utf-8' codec can't decode byte 0xaf in position 0: invalid start byte

>>> str.decode('utf-8', "replace")
'\ufffd'
>>> str.decode('utf-8', "backslashreplace")
'\\xaf'
>>> str.decode('utf-8', "ignore")
' '
```

# 摘要

在本章中，我们学习了正则表达式，使用它可以定义一组我们想要匹配的字符串的规则。我们学习了`re`模块的四个函数：`match()`、`search()`、`findall()`和`sub()`。

我们学习了`textwrap`模块，它用于格式化和包装纯文本。我们还学习了`textwrap`模块的`wrap()`、`fill()`、`dedent()`、`indent()`和`shorten()`函数。最后，我们学习了 Unicode 字符以及如何在 Python 中打印 Unicode 字符串。

在下一章中，我们将学习如何使用 Python 对信息进行标准文档化和报告。

# 问题

1.  Python 中的正则表达式是什么？

1.  编写一个 Python 程序来检查一个字符串是否只包含某个字符集（在本例中为`a–z`、`A–Z`和`0–9`）。

1.  Python 中的哪个模块支持正则表达式？

a) `re`

b) `regex`

c) `pyregex`

d) 以上都不是

1.  `re.match`函数的作用是什么？

a) 在字符串的开头匹配模式

b) 在字符串的任何位置匹配模式

c) 这样的函数不存在

d) 以上都不是

1.  以下的输出是什么？

句子："we are humans"

匹配：`re.match(r'(.*) (.*?) (.*)'`, `sentence)`

`print(matched.group())`

a) `('we', 'are', 'humans')`

b) `(we, are, humans)`

c) `('we', 'humans')`

d) `'we are humans'`

# 进一步阅读

+   正则表达式：[`docs.python.org/3.2/library/re.html`](https://docs.python.org/3.2/library/re.html)

+   Textwrap 文档：[`docs.python.org/3/library/textwrap.html`](https://docs.python.org/3/library/textwrap.html)

+   Unicode 文档：[`docs.python.org/3/howto/unicode.html`](https://docs.python.org/3/howto/unicode.html)
