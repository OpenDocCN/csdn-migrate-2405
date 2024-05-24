# 精通 Python 网络安全（五）

> 原文：[`zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c`](https://zh.annas-archive.org/md5/2fd2c4f6d02f5009e067781f7b1aee0c)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：密码学和隐写术

本章涵盖了 Python 中用于加密和解密信息的主要模块，如 pycrypto 和 cryptography。我们还涵盖了隐写术技术以及如何使用`stepic`模块在图像中隐藏信息。

本章将涵盖以下主题：

+   用于加密和解密信息的`pycrypto`模块

+   用于加密和解密信息的`cryptography`模块

+   在图像中隐藏信息的主要隐写术技术

+   如何使用`stepic`模块在图像中隐藏信息

# 技术要求

本章的示例和源代码可在 GitHub 存储库的`chapter13`文件夹中找到：[`github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security`](https://github.com/PacktPublishing/Mastering-Python-for-Networking-and-Security)。

您需要在本地计算机上安装至少 4GB 内存的 Python 发行版。

# 使用 pycrypto 加密和解密信息

在本节中，我们将回顾加密算法和用于加密和解密数据的`pycrypto`模块。

# 密码学简介

密码学可以定义为隐藏信息的实践，包括消息完整性检查、发送者/接收者身份验证和数字签名等技术。

以下是四种最常见的密码算法：

+   **哈希函数：** 也称为单向加密，它们没有密钥。`hash`函数为明文输入输出固定长度的哈希值，理论上不可能恢复明文的长度或内容。单向`加密`函数在网站中用于以一种无法检索的方式存储密码。

+   **带密钥的哈希函数：** 用于构建消息认证码（MAC）；MAC 旨在防止暴力攻击。因此，它们被故意设计成慢速的。

+   **对称加密：** 使用可变密钥对一些文本输入输出密文，我们可以使用相同的密钥解密密文。使用相同密钥进行加密和解密的算法称为对称密钥算法。

+   **公钥算法：** 对于公钥算法，我们有两个不同的密钥：一个用于加密，另一个用于解密。这种做法使用一对密钥：一个用于加密，另一个用于解密。这种技术的用户发布他们的公钥，同时保持他们的私钥保密。这使得任何人都可以使用公钥发送加密的消息，只有私钥的持有者才能解密。这些算法被设计成即使攻击者知道相应的公钥，也极其困难找到私钥。

例如，对于哈希函数，Python 提供了一些模块，比如`hashlib`。

以下脚本返回文件的`md5`校验和。

你可以在`hashlib`文件夹内的`md5.py`文件中找到以下代码：

```py
import hashlib

def md5Checksum(filePath):
    fh = open(filePath, 'rb')
    m = hashlib.md5()
    while True:
        data = fh.read(8192)
        if not data:
            break
        m.update(data)
    return m.hexdigest()

print('The MD5 checksum is', md5Checksum('md5.py'))
```

上一个脚本的输出是：

`MD5 校验和为 8eec2037fe92612b9a141a45b60bec26`

# pycrypto 简介

在使用 Python 加密信息时，我们有一些选项，但其中最可靠的之一是 PyCrypto 加密库，它支持分组加密、流加密和哈希计算的功能。

`PyCrypto`模块提供了在 Python 程序中实现强加密所需的所有函数，包括哈希函数和加密算法。

例如，`pycrypto`支持的分组密码有：

+   AES

+   ARC2

+   Blowfish

+   CAST

+   DES

+   DES3

+   IDEA

+   RC5

总的来说，所有这些密码都是以相同的方式使用的。

我们可以使用`Crypto.Cipher`包来导入特定的密码类型：

`from Crypto.Cipher import [Chiper_Type]`

我们可以使用新的方法构造函数来初始化密码：

`new ([key], [mode], [Vector IV])`

使用这种方法，只有密钥是必需的，我们必须考虑加密类型是否需要具有特定大小。可能的模式有`MODE_ECB`、`MODE_CBC`、`MODE_CFB`、`MODE_PGP`、`MODE_OFB`、`MODE_CTR`和`MODE_OPENPGP`。

如果使用`MODE_CBC`或`MODE_CFB`模式，则必须初始化第三个参数（向量 IV），这允许给密码提供初始值。一些密码可能有可选参数，例如 AES，可以使用`block_size`和`key_size`参数指定块和密钥大小。

与 hashlib 一样，`pycrypto`也支持哈希函数。使用`pycrypto`的通用哈希函数类似：

+   我们可以使用**`Crypto.Hash`**包来导入特定的哈希类型：`from Crypto.Hash import [Hash Type]`

+   我们可以使用 update 方法设置我们需要获取哈希的数据：`update('data')`

+   我们可以使用`hexdigest()`方法生成哈希：`hexdigest()`

以下是我们在获取文件的校验和时看到的相同示例，这次我们使用`pycrypt`而不是`hashlib`。

在`pycrypto`文件夹内的`hash.py`文件中可以找到以下代码：

```py
from Crypto.Hash import MD5

def md5Checksum(filePath):
    fh = open(filePath, 'rb')
    m = MD5.new()
    while True:
        data = fh.read(8192)
        if not data:
            break
        m.update(data)
    return m.hexdigest()

print('The MD5 checksum is' + md5Checksum('hash.py'))
```

要加密和解密数据，我们可以使用`**encrypt**`和`**decrypt**`函数：

```py
encrypt ('clear text')
decrypt ('encrypted text')
```

# 使用 DES 算法进行加密和解密

DES 是一种分组密码，这意味着要加密的文本是 8 的倍数，因此我在文本末尾添加了空格。当我解密它时，我将它们删除了。

以下脚本加密用户和密码，并最后，模拟服务器已收到这些凭据，解密并显示这些数据。

在`pycrypto`文件夹内的`Encrypt_decrypt_DES.py`文件中可以找到以下代码：

```py
from Crypto.Cipher import DES

# How we use DES, the blocks are 8 characters
# Fill with spaces the user until 8 characters
user =  "user    "
password = "password"

# we create the cipher with DES
cipher = DES.new('mycipher')

# encrypt username and password
cipher_user = cipher.encrypt(user)
cipher_password = cipher.encrypt(password)

# we send credentials
print("User: " + cipher_user)
print("Password: " + cipher_password)
# We simulate the server where the messages arrive encrypted.

# we decode messages and remove spaces with strip()
cipher = DES.new('mycipher')
decipher_user = cipher.decrypt(cipher_user).strip()
decipher_password = cipher.decrypt(cipher_password)
print("SERVER decipher:")
print("User: " + decipher_user)
print("Password: " + decipher_password)
```

该程序使用 DES 加密数据，因此它首先导入`DES`模块并使用以下指令创建编码器：

`cipher = DES.new('mycipher')`

‘`mycipher`’参数值是加密密钥。一旦创建了密码，就像在示例程序中看到的那样，加密和解密非常简单。

# 使用 AES 算法进行加密和解密

AES 加密需要一个强大的密钥。密钥越强大，加密就越强大。我们的 AES 密钥需要是 16、24 或 32 字节长，我们的**初始化向量**需要是**16 字节**长。这将使用`random`和`string`模块生成。

要使用 AES 等加密算法，我们可以从**`Crypto.Cipher.AES`**包中导入它。由于 PyCrypto 块级加密 API 非常低级，因此对于 AES-128、AES-196 和 AES-256，它只接受 16、24 或 32 字节长的密钥。密钥越长，加密就越强大。

另外，对于使用 pycrypto 进行 AES 加密，需要确保数据的长度是 16 字节的倍数。如果不是，则填充缓冲区，并在输出的开头包含数据的大小，以便接收方可以正确解密。

在`pycrypto`文件夹内的`Encrypt_decrypt_AES.py`文件中可以找到以下代码：

```py
# AES pycrypto package
from Crypto.Cipher import AES

# key has to be 16, 24 or 32 bytes long
encrypt_AES = AES.new('secret-key-12345', AES.MODE_CBC, 'This is an IV-12')

# Fill with spaces the user until 32 characters
message = "This is the secret message      "

ciphertext = encrypt_AES.encrypt(message)
print("Cipher text: " , ciphertext)

# key must be identical
decrypt_AES = AES.new('secret-key-12345', AES.MODE_CBC, 'This is an IV-12')
message_decrypted = decrypt_AES.decrypt(ciphertext)

print("Decrypted text: ", message_decrypted.strip())
```

上一个脚本的**输出**是：

`('密码文本：'，'\xf2\xda\x92:\xc0\xb8\xd8PX\xc1\x07\xc2\xad"\xe4\x12\x16\x1e)(\xf4\xae\xdeW\xaf_\x9d\xbd\xf4\xc3\x87\xc4')`

`('解密文本：'，'这是秘密消息')`

# 使用 AES 进行文件加密

AES 加密要求每个写入的块的大小是 16 字节的倍数。因此，我们以块的形式读取、加密和写入数据。块大小需要是 16 的倍数。

以下脚本加密由参数提供的文件。

在`pycrypto`文件夹内的`aes-file-encrypt.py`文件中可以找到以下代码：

```py
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os, random, struct

def encrypt_file(key, filename):
    chunk_size = 64*1024
    output_filename = filename + '.encrypted'

    # Initialization vector
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))

    #create the encryption cipher
    encryptor = AES.new(key, AES.MODE_CBC, iv)

    #Determine the size of the file
    filesize = os.path.getsize(filename)

    #Open the output file and write the size of the file. 
    #We use the struct package for the purpose.
    with open(filename, 'rb') as inputfile:
        with open(output_filename, 'wb') as outputfile:
            outputfile.write(struct.pack('<Q', filesize))
            outputfile.write(iv)

            while True:
                chunk = inputfile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)
                outputfile.write(encryptor.encrypt(chunk))

password = "password"

def getKey(password):
    hasher = SHA256.new(password)
    return hasher.digest()

encrypt_file(getKey(password), 'file.txt');
```

上一个脚本的输出是一个名为`file.txt.encrypted`的文件，其中包含原始文件的相同内容，但信息不可读。

上一个脚本的工作方式是首先加载所有所需的模块并定义加密文件的函数：

```py
from Crypto.Cipher import AES
import os, random, struct
def encrypt_file(key, filename, chunk_size=64*1024):
output_filename = filename + '.encrypted'
```

此外，我们需要获取我们的初始化向量。需要一个 16 字节的初始化向量，生成如下：

```py
# Initialization vector
iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
```

然后我们可以在`PyCrypto`模块中初始化 AES 加密方法：

```py
encryptor = AES.new(key, AES.MODE_CBC, iv)
filesize = os.path.getsize(filename)
```

# 使用 AES 进行文件解密

要解密，我们需要反转前面的过程，使用 AES 解密文件。

您可以在`pycrypto`文件夹中的**`aes-file-decrypt.py`**文件中找到以下代码：

```py
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
import os, random, struct

def decrypt_file(key, filename):
    chunk_size = 64*1024
    output_filename = os.path.splitext(filename)[0]

    #open the encrypted file and read the file size and the initialization vector. 
    #The IV is required for creating the cipher.
    with open(filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)

        #create the cipher using the key and the IV.
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        #We also write the decrypted data to a verification file, 
        #so we can check the results of the encryption 
        #and decryption by comparing with the original file.
        with open(output_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(origsize)

password = "password"

def getKey(password):
    hasher = SHA256.new(password)
    return hasher.digest()

decrypt_file(getKey(password), 'file.txt.encrypted');
```

# 使用密码学对信息进行加密和解密

在本节中，我们将回顾用于加密和解密数据的`cryptography`模块。`Cryptography`是一个更近期的模块，比`pycrypto`具有更好的性能和安全性。

# 密码学简介

密码学可在`pypi`存储库中找到，并且可以使用`pip install cryptography`命令进行安装。

在[`pypi.org/project/cryptography`](https://pypi.org/project/cryptography) URL 中，我们可以看到此模块的最新版本。

有关安装和支持的平台的更多信息，请查看[`cryptography.io/en/latest/installation/`](https://cryptography.io/en/latest/installation/)。

密码学包括常见加密算法的高级和低级接口，如对称密码、消息摘要和密钥派生函数。例如，我们可以使用`fernet`包进行对称加密。

# 使用 fernet 包进行对称加密

Fernet 是对称加密的一种实现，并保证加密消息不能在没有密钥的情况下被篡改或读取。

要生成密钥，我们可以使用`Fernet`接口中的`generate_key()`方法。

您可以在 cryptography 文件夹中的`encrypt_decrypt.py`文件中找到以下代码：

```py
from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

print("Key "+str(cipher_suite))
message = "Secret message"

cipher_text = cipher_suite.encrypt(message)
plain_text = cipher_suite.decrypt(cipher_text)

print("\n\nCipher text: "+cipher_text)

print("\n\nPlain text: "+plain_text)
```

这是先前脚本的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/8ff216ff-69d5-4ad1-be86-befeb736603c.png)

# 使用 fernet 包的密码

可以使用 Fernet 使用密码。为此，您需要通过密钥派生函数（如**PBKDF2HMAC**）运行密码。

**PBKDF2（基于密码的密钥派生函数 2）**通常用于从密码派生加密密钥。

有关密钥派生函数的更多信息，请访问[`cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/`](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/)。

在这个例子中，我们使用这个函数从密码生成一个密钥，并使用该密钥创建我们用于加密和解密数据的 Fernet 对象。在这种情况下，要加密的数据是一个简单的消息字符串。我们可以使用`verify()`方法，检查从提供的密钥派生新密钥是否生成与 expected_key 相同的密钥。

您可以在 cryptography 文件夹中的`encrypt_decrypt_kdf.py`文件中找到以下代码：

```py
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = "password"
salt = os.urandom(16)
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())

key = kdf.derive(password)

kdf = PBKDF2HMAC(algorithm=hashes.SHA256(),length=32,salt=salt,iterations=100000,backend=default_backend())

#verify() method checks whether deriving a new key from 
#the supplied key generates the same key as the expected_key, 
#and raises an exception if they do not match.
kdf.verify(password, key)

key = base64.urlsafe_b64encode(key)
fernet = Fernet(key)
token = fernet.encrypt("Secret message")

print("Token: "+token)
print("Message: "+fernet.decrypt(token))
```

这是先前脚本的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/9c13daa7-c80c-44a2-82b6-1c19d484817e.png)

如果我们使用`verify()`方法验证密钥，并且在过程中检查到密钥不匹配，它会引发`cryptography.exceptions.InvalidKey`异常：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/26d6ed93-5f7b-43d5-b0fb-ff9448d2e7ab.png)

# 使用 ciphers 包进行对称加密

`cryptography`模块中的 ciphers 包提供了用于对称加密的`cryptography.hazmat.primitives.ciphers.Cipher`类。

Cipher 对象将算法（如 AES）与模式（如 CBC 或 CTR）结合在一起。

在下面的脚本中，我们可以看到使用 AES 加密然后解密内容的示例。

您可以在 cryptography 文件夹中的`encrypt_decrypt_AES.py`文件中找到以下代码：

```py
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
key = os.urandom(32)
iv = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)

encryptor = cipher.encryptor()
print(encryptor)

message_encrypted = encryptor.update("a secret message")

print("\n\nCipher text: "+message_encrypted)
ct = message_encrypted + encryptor.finalize()

decryptor = cipher.decryptor()

print("\n\nPlain text: "+decryptor.update(ct))
```

这是先前脚本的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/ab420ee2-3e50-4975-b462-08b648925f9e.png)

# 在图像中隐藏信息的隐写术技术

在本节中，我们将回顾隐写术技术和`python`模块 stepic，用于在图像中隐藏信息。

# 隐写术简介

隐写术（[`en.wikipedia.org/wiki/Steganography`](http://en.wikipedia.org/wiki/Steganography)）是密码学的一个特定分支，它允许我们将秘密信息隐藏在公共信息中，也就是在表面上无害的信息中。

隐藏信息的主要技术之一是使用**最不显著位（LSB）**。

当通过图像的每个像素时，我们获得一个由整数（0）到（255）组成的 RGB 三元组，由于每个数字都有其自己的二进制表示，我们将该三元组转换为其等效的二进制；例如，由（148，28，202）组成的像素的二进制等效为（10010100，00011100，11001010）。

目标是编辑最不显著的位，也就是最右边的位。在下面的 LSB 列中，我们已经改变了位（用红色标出），但其余部分仍然完好无损，RGB 三元组的结果发生了一些变化，但变化很小。如果它们在两种颜色中被小心地设置，很不可能发现任何视觉差异，但实际上发生了变化，改变了最不显著的位之后，RGB 三元组与一开始的不同，但颜色显然是相同的。

我们可以改变信息并发送它，而攻击者并不会意识到有什么奇怪的地方。

一切都是 0 和 1，我们可以使 LSB 遵循我们想要的顺序，例如，如果我们想要隐藏单词“Hacking”，我们必须记住每个字母（字符）可以由一个字节表示，即“H”= 01001000，所以如果我们有 3 个像素，我们可以使用 LSB 隐藏该序列。

在这张图片中，我们可以看到“H”字母的二进制和 LSB 格式的表示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/c79ec798-3c4c-4d66-9ce4-ab30a1ae8ec2.png)

由于每个像素有三个组成它的值，而且在每个值中我们只能改变一个位，所以需要三个像素来隐藏字母“H”，因为它的二进制表示对应于八位。前面的表格非常直观；为了得到原始图像的三个像素，我们取出它们各自的 RGB，而且由于我们想要以二进制形式隐藏字母“H”，我们只需按照“H”的顺序替换最不显著的位。然后我们重新构建这三个像素，只是现在我们在其中隐藏了一个字母，它们的值已经改变，但对人眼来说没有可察觉的变化。

通过这种方式，我们不仅可以隐藏文本，还可以隐藏各种信息，因为一切都可以用二进制值来表示；恢复信息的方法只是接收被改变的图像并开始读取最不显著的位，因为每八位，我们有一个字符的表示。

在下一个脚本中，我们将使用 Python 实现这种技术。

您可以在`steganography_LSB.py`文件中的 steganography 文件夹中找到以下代码。

首先，我们定义了用于获取、设置**最不显著位（LSB）**的函数，并设置了`extract_message()`方法，该方法读取图像并访问每个像素对的 LSB。

```py
#!/usr/bin/env python

#Hide data in lsbs of an image
#python 3.x compatible

from PIL import Image

def get_pixel_pairs(iterable):
    a = iter(iterable)
    return zip(a, a)

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

def extract_message(image):
    c_image = Image.open(image)
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

```

现在，我们定义我们的`hide_message`方法，它读取图像并使用 LSB 在图像中隐藏消息：

```py
def hide_message(image, message, outfile):
    message += chr(0)
    c_image = Image.open(image)
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

 print("Testing hide message in python_secrets.png with LSB ...")
 print(hide_message('python.png', 'Hidden message', 'python_secrets.png'))
 print("Hide test passed, testing message extraction ...")
 print(extract_message('python_secrets.png'))
```

# 使用 Stepic 进行隐写术

Stepic 提供了一个`Python`模块和一个命令行界面，用于在图像中隐藏任意数据。它轻微地修改图像中像素的颜色以存储数据。

要设置 stepic，只需使用`pip install stepic`命令进行安装。

Stepic 的`Steganographer`类是该模块的主要类，我们可以看到可用于在图像中编码和解码数据的方法：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/ms-py-net-sec/img/5d0c2b78-ae66-4ca7-99d1-b282cd23d612.png)

在下一个脚本中，与 Python 2.x 版本兼容，我们可以看到这些函数的实现。

您可以在`**stepic.py**`文件中的`steganography`文件夹中找到以下代码：

```py
# stepic - Python image steganography
'''Python image steganography
Stepic hides arbitrary data inside PIL images.
Stepic uses the Python Image Library
(apt: python-imaging, web: <http://www.pythonware.com/products/pil/>).
'''
from PIL import Image

def _validate_image(image):
    if image.mode not in ('RGB', 'RGBA', 'CMYK'):
        raise ValueError('Unsupported pixel format: ''image must be RGB, RGBA, or CMYK')
    if image.format == 'JPEG':
        raise ValueError('JPEG format incompatible with steganography')

```

在这部分代码中，我们可以看到与使用 LSB 在图像中编码数据相关的方法。

Stepic 从左到右读取图像像素，从顶部开始。每个像素由 0 到 255 之间的三个整数三元组定义，第一个提供红色分量，第二个提供绿色，第三个提供蓝色。它一次读取三个像素，每个像素包含三个值：红色，绿色和蓝色。每组像素有九个值。一个字节的数据有八位，所以如果每种颜色都可以稍微修改，通过将最不显著的位设置为零或一，这三个像素可以存储一个字节，还剩下一个颜色值：

```py
def encode_imdata(imdata, data):
    '''given a sequence of pixels, returns an iterator of pixels with encoded data'''

    datalen = len(data)
    if datalen == 0:
        raise ValueError('data is empty')
    if datalen * 3 > len(imdata):
        raise ValueError('data is too large for image')

    imdata = iter(imdata)
    for i in xrange(datalen):
        pixels = [value & ~1 for value in
            imdata.next()[:3] + imdata.next()[:3] + imdata.next()[:3]]
        byte = ord(data[i])
        for j in xrange(7, -1, -1):
            pixels[j] |= byte & 1
            byte >>= 1
        if i == datalen - 1:
            pixels[-1] |= 1
            pixels = tuple(pixels)
            yield pixels[0:3]
            yield pixels[3:6]
            yield pixels[6:9]

def encode_inplace(image, data):
    '''hides data in an image'''
    _validate_image(image)
    w = image.size[0]
    (x, y) = (0, 0)
    for pixel in encode_imdata(image.getdata(), data):
        image.putpixel((x, y), pixel)
        if x == w - 1:
            x = 0
            y += 1
        else:
            x += 1

def encode(image, data):
    '''generates an image with hidden data, starting with an existing
       image and arbitrary data'''

    image = image.copy()
    encode_inplace(image, data)
    return image
```

在代码的这一部分中，我们可以看到与使用 LSB 从图像中解码数据相关的方法。基本上，给定图像中的一系列像素，它返回一个编码在图像中的字符的迭代器：

```py
def decode_imdata(imdata):
    '''Given a sequence of pixels, returns an iterator of characters
    encoded in the image'''

    imdata = iter(imdata)
    while True:
        pixels = list(imdata.next()[:3] + imdata.next()[:3] + imdata.next()[:3])
        byte = 0
        for c in xrange(7):
            byte |= pixels[c] & 1
            byte <<= 1
        byte |= pixels[7] & 1
        yield chr(byte)
        if pixels[-1] & 1:
            break

def decode(image):
    '''extracts data from an image'''
    _validate_image(image)
    return ''.join(decode_imdata(image.getdata()))
```

Stepic 使用这个剩余值的最不显著位(**[`en.wikipedia.org/wiki/Least_significant_bit`](http://en.wikipedia.org/wiki/Least_significant_bit)**)来表示数据的结束。编码方案不会透露图像是否包含数据，因此 Stepic 将始终从任何图像中提取至少一个字节的数据，无论是否有人有意地在那里隐藏数据。

要解码它，我们可以使用以下函数：

```py
decode_imdata(imdata)
```

我们可以看到，这个函数是`encode_imdata(imdata, data)`函数的逆函数，它一次从左到右，从上到下读取三个像素，直到最后一个像素的最后一个颜色的最后一个位读取到 1。

# 使用 stepic 在图像中隐藏数据

在接下来的脚本中，我们使用`PIL`模块中的 Image 包来读取图像。一旦我们读取了图像，我们使用 stepic 中的 encode 函数将一些文本隐藏在图像中。我们将这些信息保存在第二个图像中，并使用 decode 函数来获取隐藏的文本。

您可以在`steganography`文件夹中的`stepic_example.py`文件中找到以下代码：

```py
from PIL import Image
import stepic

#Open an image file in which you want to hide data
image = Image.open("python.png")

#Encode some text into the source image. 
#This returns another Image instance, which can save to a new file

image2 = stepic.encode(image, 'This is the hidden text')
image2.save('python_secrets.png','PNG')

#Use the decode() function to extract data from an image:

image2 = Image.open('python_secrets.png')
s = stepic.decode(image2) 
data = s.decode()
print("Decoded data: " + data)
```

# 总结

本章的一个目标是学习`pycrypto`和`cryptography`模块，它们允许我们使用 AES 和 DES 算法对信息进行加密和解密。我们还研究了隐写术技术，如最不显著位，以及如何使用 stepic 模块在图像中隐藏信息。

为了结束这本书，我想强调读者应该更多地了解他们认为最重要的主题。每一章都涵盖了基本的思想，从那里，读者可以使用*进一步阅读*部分找到更多信息的资源。

# 问题

1.  哪种算法类型使用相同的密钥来加密和解密数据？

1.  哪种算法类型使用两个不同的密钥，一个用于加密，另一个用于解密？

1.  我们可以在 pycrypto 中使用哪个包来使用 AES 等加密算法？

1.  哪种算法需要确保数据的长度是 16 字节的倍数？

1.  我们可以使用`cryptography`模块的哪个包进行对称加密？

1.  用于从密码生成加密密钥的算法是什么？

1.  fernet 包为对称加密提供了什么，用于生成密钥的方法是什么？

1.  哪个类提供了密码包对称加密？

1.  stepic 的哪个方法生成带有隐藏数据的图像，从现有的开始

图像和任意数据？

1.  从 pycrypto 中包含一些`hash`函数的哪个包允许单向加密？

# 进一步阅读

在这些链接中，您将找到有关本章中提到的工具及其官方文档的更多信息：

`Pycryptodome`是基于`pypi`存储库中可用的`pycrypto`库的模块：

[`pypi.org/project/pycryptodome/`](https://pypi.org/project/pycryptodome/)

[`github.com/Legrandin/pycryptodome`](https://github.com/Legrandin/pycryptodome)

[`www.pycryptodome.org/en/latest/`](https://www.pycryptodome.org/en/latest/)

在这些链接中，我们可以看到与`Pycrypto`模块相关的其他示例：

[`github.com/X-Vector/Crypt0x/tree/master/Crypt0x`](https://github.com/X-Vector/Crypt0x/tree/master/Crypt0x)

[`github.com/jmortega/pycon-security_criptography`](https://github.com/jmortega/pycon-security_criptography)

如果您需要更深入地探索密码生成，您可以找到其他有趣的模块，比如 Secrets：

[`docs.python.org/3/library/secrets.html#module-secrets`](https://docs.python.org/3/library/secrets.html#module-secrets)

`secrets`模块用于生成适用于管理数据（如密码、帐户验证、安全令牌和相关机密信息）的具有密码学强度的随机数。


# 第十四章：评估

# 第一章：使用 Python 脚本

1.  Python 2.x 和 3.x 之间有什么区别？

Python 3.x 中的 Unicode 支持已经得到改进。其他更改涉及`print`和`exec`函数，这些函数已经调整为更易读和一致。

1.  Python 开发人员使用的主要编程范式是什么？

面向对象编程。

1.  Python 中的哪种数据结构允许我们将值与键关联起来？

Python 字典数据结构提供了一个哈希表，可以存储任意数量的 Python 对象。字典由包含键和值的项目对组成。

1.  Python 脚本的主要开发环境是什么？

PyCharm、Wing IDE 和 Python IDLE。

1.  作为 Python 开发安全工具的一套最佳实践，我们可以遵循什么方法论？

**安全工具开发的开放方法论**（**OMSTD**）

1.  帮助创建隔离的 Python 环境的 Python 模块是什么？

`virtualenv`

1.  哪个工具允许我们创建一个基础项目，从而可以开始开发我们自己的工具？

**安全工具构建者**（**SBT**）

1.  在 Python 开发环境中如何调试变量？

通过添加断点。这样，我们可以在我们设置断点的地方调试并查看变量的内容。

1.  在 PyCharm 中如何添加断点？

我们可以在调试工具窗口中使用`call`函数设置断点。

1.  如何在 Wing IDE 中添加断点？

我们可以在调试选项菜单中使用`call`函数设置断点。

# 第二章：系统编程包

1.  允许我们与 Python 解释器交互的主要模块是什么？

系统（`sys`）模块。

1.  允许我们与操作系统环境、文件系统和权限交互的主要模块是什么？

操作系统（`os`）模块

1.  用于列出当前工作目录内容的模块和方法是什么？

操作系统（`os`）模块和`getcwd()`方法。

1.  哪个模块用于通过`call()`函数执行命令或调用进程？

`>>> subprocess.call("cls", shell=True)`

1.  在 Python 中，我们可以采用什么方法来轻松安全地处理文件和异常？

我们可以使用上下文管理器方法和`with`语句。

1.  进程和线程之间有什么区别？

进程是完整的程序。线程类似于进程：它们也是正在执行的代码。但是，线程在进程内执行，并且进程的线程之间共享资源，如内存。

1.  Python 中用于创建和管理线程的主要模块是什么？

有两个选项：

`thread`模块提供了编写多线程程序的原始操作。

`threading`模块提供了更方便的接口。

1.  Python 在处理线程时存在的限制是什么？

Python 中的线程执行受全局解释器锁（GIL）控制，因此一次只能执行一个线程，而不受机器处理器数量的影响。

1.  提供了一个高级接口，以异步方式执行输入/输出任务的类是哪个？`ThreadPoolExecutors`提供了一个简单的抽象，可以同时启动多个线程，并使用这些线程以并发方式执行任务。

1.  `threading`模块中用于确定哪个线程执行了的函数是什么？

我们可以使用`threading.current_thread()`函数来确定哪个线程执行了当前任务。

# 第三章：套接字编程

1.  `sockets`模块的哪个方法允许从 IP 地址获取域名？

通过`gethostbyaddr(address)`方法，我们可以从 IP 地址获取域名。

1.  `socket`模块的哪个方法允许服务器套接字接受来自另一台主机的客户端套接字的请求？

`socket.accept()`用于接受来自客户端的连接。此方法返回两个值：`client_socket`和`client_address`，其中`client_socket`是用于在连接上发送和接收数据的新套接字对象。

1.  `socket`模块的哪种方法允许将数据发送到给定的地址？

`socket.sendto(data, address)`用于将数据发送到给定的地址。

1.  `socket`模块的哪种方法允许您将主机和端口与特定的套接字关联起来？

`bind(IP,PORT)`方法允许将主机和端口与特定的套接字关联；例如，

`>>> server.bind((“localhost”, 9999))`.

1.  TCP 和 UDP 协议之间的区别是什么，以及如何在 Python 中使用`socket`模块实现它们？

TCP 和 UDP 之间的主要区别是 UDP 不是面向连接的。这意味着我们的数据包没有保证会到达目的地，并且如果传递失败，也不会收到错误通知。

1.  `socket`模块的哪种方法允许您将主机名转换为 IPv4 地址格式？

`socket.gethostbyname(hostname)`

1.  `socket`模块的哪种方法允许您使用套接字实现端口扫描并检查端口状态？

`socket.connect_ex(address)`用于使用套接字实现端口扫描。

1.  `socket`模块的哪个异常允许您捕获与等待时间到期相关的异常？

`socket.timeout`

1.  `socket`模块的哪个异常允许您捕获在搜索 IP 地址信息时发生的错误？

`socket.gaierror`异常，带有消息“连接到服务器的错误：[Errno 11001] getaddrinfo 失败”。

1.  `socket`模块的哪个异常允许您捕获通用输入和输出错误和通信？

`socket.error`

# 第四章：HTTP 编程

1.  哪个模块最容易使用，因为它旨在简化对 REST API 的请求？

`requests`模块。

1.  通过传递一个字典类型的数据结构来进行 POST 请求的正确方法是什么，该数据结构将被发送到请求的正文中？

`response = requests.post(url, data=data)`

1.  通过代理服务器正确地进行 POST 请求并同时修改标头信息的方法是什么？

`requests.post(url,headers=headers,proxies=proxy)`

1.  如果我们需要通过代理发送请求，需要挂载哪种数据结构？

字典数据结构；例如，`proxy = {“protocol”:”ip:port”}`。

1.  如果在`response`对象中有服务器的响应，我们如何获得服务器返回的 HTTP 请求代码？

`response.status_code`

1.  我们可以使用哪个模块来指示我们将使用`PoolManager`类预留的连接数？

`urllib3`

1.  `requests`库的哪个模块提供执行摘要类型身份验证的可能性？

`HTTPDigestAuth`

1.  基本身份验证机制使用什么编码系统发送用户名和密码？

HTTP 基本身份验证机制基于表单，使用`Base64`对由冒号分隔的用户名和密码组合进行编码。

1.  使用一种单向哈希加密算法（MD5）来改进基本身份验证过程的机制是什么？

HTTP 摘要身份验证机制使用 MD5 加密用户、密钥和领域哈希。

1.  用于识别我们用于向 URL 发送请求的浏览器和操作系统的标头是哪个？

**User-Agent**标头。

# 第五章：分析网络流量

1.  Scapy 函数可以以与`tcpdump`和 Wireshark 等工具相同的方式捕获数据包是什么？

`scapy> pkts = sniff (iface = "eth0", count = n)`，其中`n`是数据包的数量。

1.  使用 Scapy 以循环的形式每五秒发送一个数据包的最佳方法是什么？

`scapy> sendp (packet, loop=1, inter=5)`

1.  在 Scapy 中必须调用哪个方法来检查某个机器上的某个端口（`port`）是否打开或关闭，并且显示有关数据包发送方式的详细信息？

`scapy> sr1(IP(dst=host)/TCP(dport=port), verbose=True)`

1.  在 Scapy 中实现 `traceroute` 命令需要哪些函数？

`IP`/`UDP`/`sr1`

1.  哪个 Python 扩展模块与 `libpcap` 数据包捕获库进行接口？

`Pcapy.`

1.  `Pcapy` 接口中的哪个方法允许我们在特定设备上捕获数据包？

我们可以使用 Pcapy 接口中的 `open_live` 方法来捕获特定设备上的数据包，并且可以指定每次捕获的字节数和其他参数，比如混杂模式和超时。

1.  在 Scapy 中发送数据包的方法有哪些？

`send(): sends layer-3 packets`

`sendp(): sends layer-2 packets`

1.  `sniff` 函数的哪个参数允许我们定义一个将应用于每个捕获数据包的函数？

`prn` 参数将出现在许多其他函数中，并且如文档中所述，是指函数作为输入参数。以下是一个例子：

`>>> packet=sniff(filter="tcp", iface="eth0", prn=lambda x:x.summary())`

1.  Scapy 支持哪种格式来应用网络数据包过滤器？

**伯克利数据包过滤器**（**BPFs**）

1.  哪个命令允许您跟踪数据包（IP 数据包）从计算机 A 到计算机 B 的路径？

`**traceroute**`

# 第六章：从服务器收集信息

1.  我们需要什么来访问 Shodan 开发者 API？

在 Shodan 网站注册并使用 `API_KEY`，这将使您访问他们的服务。

1.  在 Shodan API 中应该调用哪个方法以获取有关给定主机的信息，该方法返回什么数据结构？

该方法是 `host()` 方法，它返回字典数据结构。

1.  哪个模块可以用于获取服务器的横幅？

我们需要使用 `sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)` 创建一个套接字，使用 `sock.sendall(http_get)` 发送 GET 请求，最后使用 `data = sock.recvfrom(1024)` 接收数据。

1.  应该调用哪个方法并传递哪些参数以获取 `DNSPython` 模块中的 IPv6 地址记录？

`dns.resolver.query('domain','AAAA')`

1.  应该调用哪个方法并传递哪些参数以获取 `DNSPython` 模块中邮件服务器的记录？

`dns.resolver.query('domain','MX')`

1.  应该调用哪个方法并传递哪些参数以获取 `DNSPython` 模块中的名称服务器记录？

`dns.resolver.query('domain','NS')`

1.  哪个项目包含文件和文件夹，其中包含在各种渗透测试中收集的已知攻击模式？

`FuzzDB` 项目提供了分为不同目录的类别，这些目录包含可预测的资源位置模式和用于检测带有恶意有效负载或易受攻击路由的漏洞模式。

1.  应该使用哪个模块来查找可能存在漏洞的服务器上的登录页面？

`fuzzdb.Discovery.PredictableRes.Logins`

1.  哪个 FuzzDB 项目模块允许我们获取用于检测 SQL 注入型漏洞的字符串？

`fuzzdb.attack_payloads.sql_injection.detect.GenericBlind`

1.  DNS 服务器用哪个端口来解析邮件服务器名称的请求？

`53(UDP)`

# 第七章：与 FTP、SSH 和 SNMP 服务器交互

1.  如何使用 `ftplib` 模块通过 `connect()` 和 `login()` 方法连接到 FTP 服务器？

`ftp = FTP()`

`ftp.connect(host, 21)`

`ftp.login(‘user’, ‘password’)`

1.  `ftplib` 模块的哪个方法允许列出 FTP 服务器的文件？

`FTP.dir()`

1.  Paramiko 模块的哪个方法允许我们连接到 SSH 服务器，并使用哪些参数（主机、用户名、密码）？

`ssh = paramiko.SSHClient()`

`ssh.connect(host, username=’username’, password=’password’)`

1.  Paramiko 模块的哪种方法允许我们打开一个会话以便随后执行命令？

`ssh_session = client.get_transport().open_session()`

1.  我们如何使用找到的路由和密码从 RSA 证书登录到 SSH 服务器？

`rsa_key= RSAKey.from_private_key_file('path_key_rsa',password)`

`client.connect('host',username='',pkey= rsa_key,password='')`

1.  `PySNMP`模块的哪个主要类允许对 SNMP 代理进行查询？

`CommandGenerator`。以下是其使用示例：

`from pysnmp.entity.rfc3413.oneliner import cmdgen`

`cmdGen = cmdgen.CommandGenerator()`

1.  在不中断会话或提示用户的情况下，通知 Paramiko 首次接受服务器密钥的指令是什么？

`ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())`

1.  通过`Transport()`方法连接到 SSH 服务器的另一种对象类型提供了另一种身份验证方式？

`transport = paramiko.Transport(ip_address)`

`transport.start_client()`

1.  基于 Paramiko 的 Python FTP 模块，以安全方式与 FTP 服务器建立连接是什么？

`pysftp`，它基于 paramiko。

1.  我们需要使用`ftplib`的哪种方法来下载文件，以及需要执行哪个`ftp`命令？

`file_handler = open(DOWNLOAD_FILE_NAME, 'wb')`

`ftp_cmd = 'RETR %s' %DOWNLOAD_FILE_NAME`

`ftp_client.retrbinary(ftp_cmd,file_handler.write)`

# 第八章：使用 Nmap 扫描器

1.  哪种方法允许我们查看已被定位扫描的机器？

`nmap.all_hosts()`

1.  如果我们想执行异步扫描并在扫描结束时执行脚本，我们如何调用`scan`函数？

`nmasync.scan('ip','ports',arguments='--script=/usr/local/share/nmap/scripts/')`

1.  我们可以使用哪种方法以字典格式获取扫描结果？

`nmap.csv()`

1.  用于执行异步扫描的 Nmap 模块是什么类型的？

`nma = nmap.PortScannerAsync()`

1.  用于执行同步扫描的 Nmap 模块是什么类型的？

`nma = nmap.PortScanner()`

1.  如何在给定的主机和给定的端口上启动同步扫描，如果我们使用`self.nmsync = nmap.PortScanner()`指令初始化对象？

`self.nmsync.scan(hostname, port)`

1.  我们可以使用哪种方法来检查特定网络中的主机是否在线？

我们可以使用`state()`函数来查看主机是否在线。以下是其使用示例：

`nmap[‘127.0.0.1’].state()`

1.  当我们使用`PortScannerAsync()`类执行异步扫描时，需要定义哪个函数？

在执行扫描时，我们可以指定一个额外的回调参数，其中定义了`return`函数，该函数将在扫描结束时执行。以下是一个例子：

`def callback_result(host, scan_result)`

`nmasync.scan(hosts=’127.0.0.1’, arguments=’-sP’, callback=callback_result)`

1.  如果我们需要知道 FTP 服务是否允许匿名身份验证而无需输入用户名和密码，我们需要在端口`21`上运行哪个脚本？

`ftp-anon.nse`

1.  如果我们需要知道 MySQL 服务是否允许匿名身份验证而无需输入用户名和密码，我们需要在端口`3306`上运行哪个脚本？

`mysql-enum.nse`

# 第九章：与 Metasploit 框架连接

1.  与模块交互和执行 Metasploit 中的利用的接口是什么？

`msfconsole`

1.  使用 Metasploit 框架利用系统的主要步骤是什么？

使用 Metasploit 框架利用系统的五个步骤如下：

1. 配置主动利用

2. 验证利用选项

3. 选择目标

4. 选择有效载荷

5. 启动利用

1.  Metasploit 框架用于客户端和 Metasploit 服务器实例之间交换信息的接口名称是什么？

MSGRPC 接口使用`MessagePack`格式在 Metasploit Framework 实例和客户端之间交换信息。

1.  `generic/shell_bind_tcp`和`generic/shell_reverse_tcp`之间的区别是什么？

它们之间的区别在于，使用`generic/shell_bind_tcp`时，连接是从攻击者的机器到受害者的机器建立的，而使用`generic/shell_reverse_tcp`时，连接是从受害者的机器建立的，这需要攻击者的机器有一个监听以检测该连接的程序。

1.  我们可以执行哪个命令来连接`msfconsole`？

`./msfrpcd -U user -P password -p 55553 -n -f`

这样，Metasploit 的 RPC 接口在端口`55553`上监听。

1.  我们需要使用哪个函数以与`msfconsole`实用程序相同的方式与框架交互？

1.  我们使用`console.create`函数，然后使用该函数返回的控制台标识符，如下所示：

导入 msfrpc

`client = msfrpc.Msfrpc({'uri':'/msfrpc', 'port':'5553', 'host':'127.0.0.1', 'ssl': True})`

`client.call('console.create')`

1.  使用 Metasploit Framework 在客户端和 Metasploit 服务器实例之间交换信息的远程访问接口的名称是什么？

`MSGRPC`

1.  我们如何可以从 Metasploit 服务器获取所有利用的列表？

要获取利用，可以在使用该工具时使用`**show exploits**`命令。

1.  Metasploit Framework 中哪些模块可以访问 Apache Tomcat 中的应用程序管理器并利用 Apache Tomcat 服务器以获取会话 meterpreter？

在 Metasploit Framework 中，有一个名为`tomcat_mgr_login`的辅助模块，它为攻击者提供用户名和密码以访问 Tomcat Manager。

1.  在 Tomcat 服务器上执行利用时建立 meterpreter 会话的有效负载名称是什么？

`java/meterpreter/bind_tcp`

# 第十章：与漏洞扫描仪交互

1.  考虑一组标准化和易于衡量的标准，评分漏洞的主要机制是什么？

**通用漏洞评分系统**（**CVSS**）

1.  我们使用哪个包和类来与 Python 交互 Nessus？

`from nessrest import ness6rest`

1.  `nessrest`模块中哪个方法在特定目标上启动扫描？

`scan = ness6rest.Scanner(url="https://nessusscanner:8834", login="username", password="password")`

1.  `nessrest`模块中哪个方法获取特定目标扫描的详细信息？

`scan_details(self, name)`方法获取所请求扫描的详细信息。

1.  用 Python 连接`nexpose`服务器的主要类是什么？

要使用`nexpose`服务器连接 Python，我们使用`pynexpose.py`文件中的`NeXposeServer`类。

1.  负责列出所有检测到的漏洞并返回特定漏洞详情的方法是什么？

`vulnerability_listing()`和`vulnerability_details()`方法负责列出所有检测到的漏洞并返回特定漏洞的详情。

1.  允许我们解析并获取从`nexpose`服务器获取的信息的 Python 模块的名称是什么？

`BeautifulSoup`。

1.  允许我们连接到`NexPose`漏洞扫描仪的 Python 模块的名称是什么？

`Pynexpose`模块允许从 Python 对位于 Web 服务器上的漏洞扫描器进行编程访问。

1.  允许我们连接到`Nessus`漏洞扫描仪的 Python 模块的名称是什么？

`nessrest`。

1.  `Nexpose`服务器以何种格式返回响应以便从 Python 中简单处理？

XML。

# 第十一章：识别 Web 应用程序中的服务器漏洞

1.  哪种类型的漏洞是一种攻击，将恶意脚本注入到网页中，以重定向用户到假网站或收集个人信息？

**跨站脚本**（**XSS**）允许攻击者在受害者的浏览器中执行脚本，从而允许他们劫持用户会话或将用户重定向到恶意站点。

1.  攻击者将 SQL 数据库命令插入到 Web 应用程序使用的订单表单的数据输入字段的技术是什么？

SQL 注入是一种利用`未经验证`输入漏洞来窃取数据的技术。基本上，它是一种代码注入技术，攻击者执行恶意 SQL 查询，控制 Web 应用程序的数据库。

您希望防止浏览器运行潜在有害的 JavaScript 命令。什么工具可以帮助您检测与 JavaScript 相关的 Web 应用程序中的漏洞？

您可以使用`xssscrapy`来检测 XSS 漏洞。

1.  什么工具允许您从网站获取数据结构？

`Scrapy`是 Python 的一个框架，允许您执行网络抓取任务和网络爬行过程以及数据分析。它允许您递归扫描网站的内容，并对内容应用一组规则，以提取可能对您有用的信息。

1.  什么工具允许您检测与 JavaScript 相关的 Web 应用程序中的漏洞？

`Sqlmap`和`xsscrapy`。

1.  w3af 工具的哪个配置文件执行扫描以识别更高风险的漏洞，如 SQL 注入和 XSS？

`audit_high_risk`配置文件执行扫描以识别更高风险的漏洞，如 SQL 注入和 XSS。

1.  w3af API 中的主要类是包含启用插件、建立攻击目标和管理配置文件所需的所有方法和属性的类是什么？

在整个攻击过程中，最重要的是管理`core.controllers.w3afCore`模块的`w3afCore`类。该类的实例包含启用插件、建立攻击目标、管理配置文件以及启动、中断和停止攻击过程所需的所有方法和属性。

1.  哪个`slmap`选项列出所有可用的数据库？

`dbs`选项。以下是其使用示例：

`>>>sqlmap -u http://testphp.productweb.com/showproducts.php?cat=1 –dbs`

1.  允许在服务器中扫描 Heartbleed 漏洞的 Nmap 脚本的名称是什么？

`ssl-heartbleed`

1.  哪个过程允许我们与服务器建立 SSL 连接，包括对称和非对称密钥的交换，以在客户端和服务器之间建立加密连接？

`HandShake`确定将用于加密通信的密码套件，验证服务器，并在实际数据传输之前建立安全连接。

# 第十二章：从文档、图像和浏览器中提取地理位置和元数据

1.  哪个 Python 模块允许我们从 IP 地址检索地理信息？

`pygeoip`允许您从 IP 地址检索地理信息。它基于 GeoIP 数据库，这些数据库根据类型（类型为`city`、`region`、`country`、`ISP`）分布在几个文件中。

1.  哪个模块使用 Google Geocoding API v3 服务来检索特定地址的坐标？

`pygeocoder`是一个简化使用 Google 地理位置功能的 Python 模块。使用此模块，您可以轻松找到与坐标对应的地址，反之亦然。我们还可以使用它来验证和格式化地址。

1.  允许根据地点的描述和特定位置进行查询的`pygeocoder`模块的主要类是什么？

该模块的主要类是`Geocoder`类，它允许根据地点的描述和特定位置进行查询。

1.  哪个方法允许反转过程，从对应于纬度和经度的坐标中恢复给定站点的地址？

`results = Geocoder.reverse_geocode(results.latitude, results.longitude)`

1.  `pygeoip`模块中的哪个方法允许我们从传递的 IP 地址获取国家名称的值？

`country_name_by_addr(<ip_address>)`

1.  `pygeoip`模块中的哪个方法允许我们从 IP 地址获取以字典形式的地理数据（国家、城市、地区、纬度、经度）？

`record_by_addr(<ip_address>)`

1.  `pygeoip`模块中的哪个方法允许我们从域名中获取组织的名称？

`org_by_name(<domain_name>)`

1.  哪个 Python 模块允许我们从 PDF 文档中提取元数据？

`PyPDF2`

1.  我们可以使用哪个类和方法来从 PDF 文档中获取信息？

`PyPDF2`模块提供了提取文档信息以及加密和解密文档的功能。要提取元数据，我们可以使用`PdfFileReader`类和`getDocumentInfo()`方法，它返回一个包含文档数据的字典。

1.  哪个模块允许我们从 EXIF 格式的标签中提取图像信息？

`PIL.ExifTags`用于获取图像的 EXIF 标签信息；图像对象的`_getexif()`方法可用。

# 第十三章：密码学和隐写术

1.  哪种算法类型使用相同的密钥来加密和解密数据？

对称加密。

1.  哪种算法类型使用两个不同的密钥，一个用于加密，另一个用于解密？

公钥算法使用两个不同的密钥：一个用于加密，另一个用于解密。这项技术的用户发布其公钥，同时保持其私钥保密。这使得任何人都可以使用公钥加密发送给他们的消息，只有私钥的持有者才能解密。

1.  在`pycrypto`中，我们可以使用哪个包来使用诸如 AES 之类的加密算法？

`from Crypto.Cipher import AES`

1.  对于哪种算法，我们需要确保数据的长度是 16 字节的倍数？

AES 加密。

1.  对于密码模块，我们可以使用哪个包进行对称加密？

`fernet`包是对称加密的一种实现，并保证加密的消息在没有密钥的情况下无法被篡改或阅读。以下是其使用示例：

`from cryptography.fernet import Fernet`

1.  从密码中派生加密密钥使用哪种算法？

**基于密码的密钥派生函数 2**（**PBKDF2**）。对于密码模块，我们可以使用`cryptography.hazmat.primitives.kdf.pbkdf2`包中的`PBKDF2HMAC`。

1.  `fernet`包为对称加密提供了什么，并且用于生成密钥的方法是什么？

`fernet`包是对称加密的一种实现，并保证加密的消息在没有密钥的情况下无法被篡改或阅读。要生成密钥，我们可以使用以下代码：

`from cryptography.fernet import Fernet`

`key = Fernet.generate_key()`

1.  哪个类提供了`ciphers`包的对称加密？

`cryptography.hazmat.primitives.ciphers.Cipher`

1.  `stepic`中的哪个方法生成带有隐藏数据的图像，从现有图像和任意数据开始？

`encode(image,data)`

1.  `pycrypto`中的哪个包包含一些哈希函数，允许单向加密？

`from Crypto.Hash import [Hash Type]`
