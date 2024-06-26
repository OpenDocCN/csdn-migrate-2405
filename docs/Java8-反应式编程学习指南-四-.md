# Java8 反应式编程学习指南（四）

> 原文：[`zh.annas-archive.org/md5/A4E30A017482EBE61466A691985993DC`](https://zh.annas-archive.org/md5/A4E30A017482EBE61466A691985993DC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：网络安全

在本章中，我们将探讨 Java 为应用程序之间的安全通信提供的支持。我们将研究几个主题，包括以下内容：

+   基本加密过程

+   使用密钥库存储密钥和证书

+   在简单的服务器/客户端中添加加密

+   使用 TLS\SSL 进行安全的客户端/服务器通信

+   安全散列

# 安全

在首次遇到时，许多与安全相关的术语的含义和目的可能令人生畏。这些术语大多适用于网络应用程序。我们将从对这些术语的简要概述开始。在本章的后续部分，我们将更详细地讨论与我们讨论相关的术语。

对大多数与安全相关的问题至关重要的是加密。这是将需要保护的信息使用密钥或一组密钥转换为加密形式的过程。接收加密信息的接收者可以使用密钥或一组密钥来解密信息并将其恢复为其原始形式。这种技术可以防止未经授权的人访问信息。

我们将演示对称和非对称加密技术的使用。对称加密使用单个密钥加密和解密消息。非对称加密使用一对密钥。这些密钥通常存储在一个称为**密钥库**的文件中，我们将进行演示。

对称加密通常更快，但需要发送方和接收方以安全的方式共享其密钥。对于远程分散的各方来说，这可能是一个问题。非对称加密速度较慢，但使用公钥和私钥对，简化了密钥的共享，这是我们将要看到的。非对称加密是数字证书的一种使能技术，提供了验证文档真实性的手段。

安全商务是常见的，对于每天在全球范围内进行的在线交易至关重要。**传输层安全**（**TLS**）和**安全套接字层**（**SSL**）是允许在互联网上进行安全可靠通信的协议。这是**超文本传输安全协议**（**HTTPS**）的基础，用于进行互联网上的大多数交易。该协议支持以下内容：

+   服务器和客户端认证

+   数据加密

+   数据完整性

安全散列是一种用于创建证书的技术。**证书**用于验证数据的真实性，并使用散列值。Java 提供了对这个过程的支持，我们将进行演示。

让我们从简要介绍常见网络安全术语开始，以提供本章的高层视角。具体术语将在后续章节中更详细地探讨。

## 安全通信术语

在处理安全通信时使用了几个术语。这些包括以下内容：

+   **认证**：这是验证用户或系统的过程

+   **授权**：这是允许访问受保护资源的过程

+   **加密**：这是对信息进行编码，然后解码以保护它免受未经授权的个人的过程

+   **散列算法**：这提供了为文档生成唯一值的方式，并且它们用于支持其他安全技术

+   **数字签名**：这提供了一种数字验证文档的方式

+   **证书**：这些通常用作链，并支持确认主体和其他参与者的身份

认证和授权是相关的。认证是确定一个人或系统是否是其声称的人或系统的过程。通常使用 ID 和密码来实现。然而，还有其他认证技术，如智能卡，生物特征签名，如指纹或虹膜扫描。

授权是确定个人或系统可以访问哪些资源的过程。验证个人是否是他们所说的人是一回事。确保用户只能访问授权资源是另一回事。

加密已经发展并将继续改进。Java 支持对称和非对称加密技术。这个过程从生成密钥开始，这些密钥通常存储在密钥库中。需要加密或解密数据的应用程序将访问密钥库以检索适当的密钥。密钥库本身需要受到保护，以防止被篡改或以其他方式被破坏。

哈希是将数据转换为代表数据的数字的过程。哈希算法执行这个操作，它必须很快。然而，只给出哈希值时，要推导出原始数据是极其困难，甚至是不可能的。这被称为单向哈希函数。

这种技术的优势在于数据可以与哈希值一起发送给接收者。数据没有加密，但哈希值使用一组非对称密钥进行了加密。接收者可以使用原始哈希算法为接收到的数据计算一个哈希值。如果这个新的哈希值与发送的哈希值匹配，那么接收者可以确信数据在传输过程中没有被修改或损坏。这提供了一种更可靠的传输数据的方式，不需要加密，但可以给出一些保证它没有被修改的保证。

证书是前面过程的一部分，它使用哈希函数和非对称密钥。**证书链**提供了一种验证证书是否有效的方法，假设可以信任链的根。

# 加密基础

在本节中，我们将探讨 Java 如何支持对称和非对称加密。正如我们将看到的，这两种技术都有各种可用的加密算法。

## 对称加密技术

对称加密使用单个密钥来加密和解密消息。这种加密类型被分类为流密码或块密码。关于这些算法的更多细节可以在[`en.wikipedia.org/wiki/Symmetric-key_algorithm`](https://en.wikipedia.org/wiki/Symmetric-key_algorithm)找到。提供者提供了加密算法的实现，我们经常在它们之间进行选择。

Java 支持的对称算法包括以下这些，其中括号中是密钥大小（以位为单位）：

+   AES（128）

+   DES（56）

+   DESede（168）

+   HmacSHA1

+   HmacSHA256

可以加密不同长度的数据。块密码算法用于处理大块数据。下面列出了几种块密码操作模式。我们不会在这里详细介绍这些模式的工作原理，但可以在[`en.wikipedia.org/wiki/Block_cipher_mode_of_operation`](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)找到更多信息：

+   ECB

+   CBC

+   CFB

+   OFB

+   PCBC

在我们可以加密或解密数据之前，我们需要一个密钥。

### 生成密钥

生成密钥的常见方法是使用`KeyGenerator`类。该类没有公共构造函数，但重载的`getInstance`方法将返回一个`KeyGenerator`实例。以下示例使用 AES 算法和默认提供者。该方法的其他版本允许选择提供者：

```java
    KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
```

`generateKey`方法返回一个实现了`SecretKey`接口的对象实例，如下所示。这是用于支持对称加密和解密的密钥：

```java
    SecretKey secretKey = keyGenerator.generateKey();
```

有了密钥，我们现在可以加密数据了。

### 使用对称密钥加密文本

我们将在后面的部分中使用以下的`encrypt`方法。这个方法接收要加密的文本和一个秘钥。术语**明文**经常用来指代未加密的数据。

`Cipher`类提供了加密过程的框架。`getInstance`方法返回一个使用 AES 算法的类的实例。`Cipher`实例被初始化为使用`Cipher.ENCRYPT_MODE`作为第一个参数进行加密，秘钥作为第二个参数。`doFinal`方法加密明文字节数组并返回加密后的字节数组。`Base64`类的`getEncoder`返回一个编码器，用于编码加密后的字节：

```java
    public static String encrypt(
            String plainText, SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            byte[] plainTextBytes = plainText.getBytes();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedBytes = 
                cipher.doFinal(plainTextBytes);
            Base64.Encoder encoder = Base64.getEncoder();
            String encryptedText = 
                encoder.encodeToString(encryptedBytes);
            return encryptedText;
        } catch (NoSuchAlgorithmException|NoSuchPaddingException | 
                InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException ex) {
            // Handle exceptions
        }
        return null;
    }
```

编码加密后的字节数组用于将其转换为字符串，以便以后使用。编码字符串可以是一种有用的安全技术，如[`javarevisited.blogspot.sg/2012/03/why-character-array-is-better-than.html`](http://javarevisited.blogspot.sg/2012/03/why-character-array-is-better-than.html)中所解释的那样。

### 解密文本

解密文本的过程在接下来展示的解密方法中进行了说明。它使用一个反向过程，其中加密字节被解码，`Cipher`类的`init`方法被初始化为使用秘钥解密字节：

```java
    public static String decrypt(String encryptedText, 
            SecretKey secretKey) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            Base64.Decoder decoder = Base64.getDecoder();
            byte[] encryptedBytes = decoder.decode(encryptedText);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedBytes = 
                cipher.doFinal(encryptedBytes);
            String decryptedText = new String(decryptedBytes);
            return decryptedText;
        } catch (NoSuchAlgorithmException|NoSuchPaddingException | 
                InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException ex) {
            // Handle exceptions
        }
        return null;
    }
```

我们将在*对称加密客户端/服务器*部分中的回显客户端/服务器应用程序中使用这些方法。

## 非对称加密技术

非对称加密使用公钥和私钥。私钥由一个实体持有。公钥对所有人都是可用的。数据可以使用任一密钥加密：

+   如果数据使用私钥加密，那么可以使用公钥解密。

+   如果数据使用公钥加密，那么可以使用私钥解密。

如果私钥所有者发送一条使用私钥加密的消息，那么接收者可以使用公钥解密。他们都可以读取消息，但他们知道只有私钥所有者才能发送这条消息。

如果其他人使用公钥加密一条消息，那么只有私钥所有者可以读取该消息。然而，所有者无法确定谁实际发送了消息。可能是一个冒名顶替者。

然而，如果双方都有自己的公钥/私钥，我们可以保证只有发送者和接收者可以看到其内容。我们还可以保证发送者就是他们所说的那个人。

假设 Sue 想要给 Bob 发送一条消息。Sue 将使用她的私钥加密消息 M。我们称这条消息为 M1。然后她使用 Bob 的公钥加密 M1，得到 M2。消息 M2 然后发送给 Bob。现在，只有 Bob 可以使用他的私钥解密这条消息。这将返回 M1。Bob 现在可以使用 Sue 的公钥解密 M1 以获得原始消息 M。他知道这是来自 Sue 的，因为只有 Sue 的公钥可以起作用。

发送消息的这个过程要求两个参与者都拥有自己的公钥/私钥。除此之外，这种方法不如使用对称密钥高效。另一种方法是使用非对称密钥来传输一个秘钥给参与者。然后这个秘钥可以用于实际的消息传输。这就是 SSL 中使用的技术。

有几种非对称算法。Java 支持以下加密算法：

+   RSA

+   Diffie-Hellman

+   DSA

我们将使用一个名为`AsymmetricKeyUtility`的实用类来演示非对称加密/解密。这个类封装了创建、保存、加载和检索公钥和私钥的方法。我们将在这里解释这些方法是如何工作的，并在非对称回显客户端/服务器应用程序中稍后使用它们。

```java
public class AsymmetricKeyUtility {

    public static void savePrivateKey(PrivateKey privateKey) {
        ...
    }

    public static PrivateKey getPrivateKey() {
        ...
    }

    public static void savePublicKey(PublicKey publicKey) {
        ...
    }

    public static PublicKey getPublicKey() {
        ...
    }

    public static byte[] encrypt(PublicKey publicKey, 
            String message) { 
        ...
    }    

    public static String decrypt(PrivateKey privateKey, 
        byte[] encodedData) { 
        ...
    }

    public static void main(String[] args) {
        ...
    }
}
```

### 生成和保存非对称密钥

`main`方法将创建密钥，保存它们，然后测试它们是否能正常工作。`KeyPairGenerator`方法将生成密钥。要使用非对称加密，我们使用 RSA 算法获取该类的实例。`initialize`方法指定密钥使用 1,024 位。`generateKeyPair`方法生成密钥，`getPrivate`和`getPublic`方法分别返回私钥和公钥：

```java
    public static void main(String[] args) {
        try {
            KeyPairGenerator keyPairGenerator = 
                KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            PrivateKey privateKey = keyPair.getPrivate();
            PublicKey publicKey = keyPair.getPublic();
            ...
        } catch (NoSuchAlgorithmException ex) {
            // Handle exceptions
        }
```

我们将使用一组方法将这些密钥保存并检索到单独的文件中。这种方法并不是最安全的，但它将简化回声客户端/服务器的使用。下面的语句调用了保存方法：

```java
            savePrivateKey(privateKey);
            savePublicKey(publicKey);
```

用于检索密钥的方法在这里被调用：

```java
            privateKey = getPrivateKey();
            publicKey = getPublicKey();
```

下一个代码序列测试了加密/解密过程。创建了一条消息，并使用公钥将其传递给`encrypt`方法。调用`decrypt`方法来解密消息。`encodedData`变量引用了加密数据：

```java
            String message = "The message";
            System.out.println("Message: " + message);
            byte[] encodedData = encrypt(publicKey,message);
            System.out.println("Decrypted Message: " + 
                    decrypt(privateKey,encodedData));
```

此示例的输出如下：

**消息：消息**

**解密消息：消息**

相反，我们可以使用私钥进行加密，使用公钥进行解密，以达到相同的结果。

### 使用非对称密钥加密/解密文本

现在，让我们来看一下`encrypt`和`decrypt`方法的具体内容。`encrypt`方法使用`getInstance`获取 RSA 算法的实例。`init`方法指定`Cipher`对象将使用公钥加密消息。`doFinal`方法执行实际的加密并返回包含加密消息的字节数组：

```java
    public static byte[] encrypt(PublicKey publicKey, String message) { 
        byte[] encodedData = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA ");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedBytes = 
                cipher.doFinal(message.getBytes());
            encodedData = Base64.getEncoder().withoutPadding()
                .encode(encryptedBytes);
        } catch (NoSuchAlgorithmException|NoSuchPaddingException | 
                InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException ex) {
            // Handle exceptions
        }
        return encodedData;
    }
```

接下来描述了`decrypt`方法。它指定`Cipher`实例将使用私钥解密消息。传递给它的加密消息在`doFinal`方法解密之前必须解码。然后返回解密的字符串：

```java
    public static String decrypt(PrivateKey privateKey, 
            byte[] encodedData) { 
        String message = null;
        try {
            Cipher cipher = Cipher.getInstance("RSA ");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decodedData = 
                Base64.getDecoder().decode(encodedData);
            byte[] decryptedBytes = cipher.doFinal(decodedData); 
            message = new String(decryptedBytes);
        } catch (NoSuchAlgorithmException|NoSuchPaddingException | 
                InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException ex) {
            // Handle exceptions
        }
        return message;
    }
```

这两种方法都捕获了在加密/解密过程中可能发生的许多异常。我们在这里不讨论这些异常。

### 将非对称密钥保存到文件

接下来的两种方法说明了保存和检索私钥的一种技术。`PKCS8EncodedKeySpec`类支持私钥的编码。编码的密钥保存到`private.key`文件中：

```java
    public static void savePrivateKey(PrivateKey privateKey) {
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = 
                new PKCS8EncodedKeySpec(privateKey.getEncoded());
            FileOutputStream fos = 
                new FileOutputStream("private.key");
            fos.write(pkcs8EncodedKeySpec.getEncoded());
            fos.close();
        } catch (FileNotFoundException ex) {
            // Handle exceptions
        } catch (IOException ex) {
            // Handle exceptions
        }
    }
```

接下来描述的`getPrivateKey`方法从文件中返回私钥。`KeyFactory`类的`generatePrivate`方法根据`PKCS8EncodedKeySpec`规范创建密钥：

```java
    public static PrivateKey getPrivateKey() {
        try {
            File privateKeyFile = new File("private.key");
            FileInputStream fis = 
                new FileInputStream("private.key");
            byte[] encodedPrivateKey = 
                new byte[(int) privateKeyFile.length()];
            fis.read(encodedPrivateKey);
            fis.close();
            PKCS8EncodedKeySpec privateKeySpec = 
                new PKCS8EncodedKeySpec(encodedPrivateKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = 
                keyFactory.generatePrivate(privateKeySpec);
            return privateKey;
        } catch (FileNotFoundException ex) {
            // Handle exceptions
        } catch (IOException | NoSuchAlgorithmException | 
                 InvalidKeySpecException ex) {
            // Handle exceptions
        } 
        return null;
    }
```

接下来描述了公钥的保存和获取方法。它们在使用的文件和`X509EncodedKeySpec`类的使用上有所不同。该类表示公钥：

```java
    public static void savePublicKey(PublicKey publicKey) {
        try {
            X509EncodedKeySpec x509EncodedKeySpec = 
                new X509EncodedKeySpec(publicKey.getEncoded());
            FileOutputStream fos = 
                new FileOutputStream("public.key");
            fos.write(x509EncodedKeySpec.getEncoded());
            fos.close();
        } catch (FileNotFoundException ex) {
            // Handle exceptions
        } catch (IOException ex) {
            // Handle exceptions
        }
    }

    public static PublicKey getPublicKey() {
        try {
            File publicKeyFile = new File("public.key");
            FileInputStream fis = 
                new FileInputStream("public.key");
            byte[] encodedPublicKey = 
                new byte[(int) publicKeyFile.length()];
            fis.read(encodedPublicKey);
            fis.close();
            X509EncodedKeySpec publicKeySpec = 
                new X509EncodedKeySpec(encodedPublicKey);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = 
                keyFactory.generatePublic(publicKeySpec);
            return publicKey;
        } catch (FileNotFoundException ex) {
            // Handle exceptions
        } catch (IOException | NoSuchAlgorithmException | 
                 InvalidKeySpecException ex) {
            // Handle exceptions
        } 
        return null;
    }
```

标准的加密算法名称可以在[`docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html`](https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html)找到。对称算法的性能比较可以在[`www.javamex.com/tutorials/cryptography/ciphers.shtml`](http://www.javamex.com/tutorials/cryptography/ciphers.shtml)找到。

# 创建密钥库

密钥库存储了加密密钥和证书，并经常与服务器和客户端一起使用。密钥库通常是一个文件，但也可以是硬件设备。Java 支持以下类型的密钥库条目：

+   **PrivateKey**：这用于非对称加密

+   **证书**：这包含公钥

+   **SecretKey**：这用于对称加密

Java 8 支持五种不同类型的密钥库：JKS、JCEKS、PKCS12、PKCS11 和 DKS：

+   **JKS**：这是通常具有扩展名`jks`的**Java 密钥库**（**JKS**）。

+   **JCEKS**：这是**Java 密码扩展密钥库**（**JCE**）。它可以存储所有三种密钥库实体类型，为密钥提供更强的保护，并使用`jceks`扩展名。

+   **PKCS12**：与 JKS 和 JCEKS 相比，此密钥库可以与其他语言一起使用。它可以存储所有三种密钥库实体类型，并使用`p12`或`pfx`的扩展名。

+   **PKCS11**：这是一种硬件密钥库类型。

+   DKS：这是保存其他密钥库的**域密钥库**（**DKS**）。

Java 中的默认密钥库类型是 JKS。可以使用`keytool`命令行工具或 Java 代码创建和维护密钥库。我们将首先演示`keytool`。

## 使用 keytool 创建和维护密钥库

keytool 是一个用于创建密钥库的命令行程序。其完整的使用文档可在[`docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html`](https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html)找到。有几个 GUI 工具用于维护密钥库，比 keytool 更容易使用。其中一个是 IKEYMAN，位于[`www-01.ibm.com/software/webservers/httpservers/doc/v1312/ibm/9atikeyu.htm`](http://www-01.ibm.com/software/webservers/httpservers/doc/v1312/ibm/9atikeyu.htm)。

要在 Windows 上使用 keytool，您需要配置 PATH 环境变量以定位其所在的目录。使用类似以下的命令：

```java
 C:\Some Directory>set path=C:\Program Files\Java\jdk1.8.0_25\bin;%path%

```

让我们使用 keytool 创建一个密钥库。在命令提示符下，输入以下命令。这将开始创建名为`keystore.jks`的文件中的密钥库的过程。别名是您可以用来引用密钥库的另一个名称：

```java
 C:\Some Directory>keytool -genkey -alias mykeystore -keystore keystore.jks

```

然后，将提示您输入以下几个信息。根据提示进行适当的回应。您输入的密码不会显示出来。在本章的示例中，我们使用了密码`password`：

```java
Enter keystore password:
Re-enter new password:
What is your first and last name?
 [Unknown]:  some name
What is the name of your organizational unit?
 [Unknown]:  development
What is the name of your organization?
 [Unknown]:  mycom.com
What is the name of your City or Locality?
 [Unknown]:  some city
What is the name of your State or Province?
 [Unknown]:  some state
What is the two-letter country code for this unit?
 [Unknown]:  jv

```

然后将提示您确认输入如下。如果值正确，请回复“是”：

```java
Is CN=some name, OU=development, O=mycom.com, L=some city, ST=some state, C=jv correct?
 [no]:  yes

```

您可以为密钥分配单独的密码，如下所示：

```java
Enter key password for <mykeystore>
 (RETURN if same as keystore password):

```

然后创建密钥库。可以使用`-list`参数显示密钥库的内容，如下所示。`-v`选项会产生详细输出：

```java
keytool -list -v -keystore keystore.jks -alias mykeystore

```

这将显示以下输出。需要输入密钥库密码以及别名：

```java
Enter keystore password:
Alias name: mykeystore
Creation date: Oct 22, 2015
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=some name, OU=development, O=mycom.com, L=some city, ST=some state, C=jv
Issuer: CN=some name, OU=development, O=mycom.com, L=some city, ST=some state, C=jv
Serial number: 39f2e11e
Valid from: Thu Oct 22 18:11:21 CDT 2015 until: Wed Jan 20 17:11:21 CST 2016
Certificate fingerprints:
 MD5:  64:44:64:27:85:99:01:22:49:FC:41:DA:F7:A8:4C:35
 SHA1: 48:57:3A:DB:1B:16:92:E6:CC:90:8B:D3:A7:A3:89:B3:9C:9B:7C:BB
 SHA256: B6:B2:22:A0:64:61:DB:53:33:04:78:77:38:AF:D2:A0:60:37:A6:CB:3F:
3C:47:CC:30:5F:02:86:8F:68:84:7D
 Signature algorithm name: SHA1withDSA
 Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: 07 D9 51 BE A7 48 23 34   5F 8E C6 F9 88 C0 36 CA  ..Q..H#4_.....6.
0010: 27 8E 04 22                                        '.."
]
]

```

## Keytool 命令行参数

输入密钥库的信息可能会很繁琐。简化此过程的一种方法是使用命令行参数。以下命令将创建先前的密钥库：

```java
keytool -genkeypair -alias mykeystore -keystore keystore.jks -keypass password -storepass password -dname "cn=some name, ou=development, o=mycom.com, l=some city, st=some state c=jv

```

您会注意到命令行末尾没有匹配的双引号。这不是必要的。命令行参数在之前列出的 keytool 网站上有文档记录。

此工具可以创建对称密钥和非对称密钥以及证书。以下一系列命令演示了其中几种类型的操作。我们将为一对非对称密钥创建一个密钥库。然后将导出一对证书，可用于服务器和客户端应用程序。

此命令将使用 RSA 算法创建`serverkeystore.jck`密钥库文件，密钥大小为 1,024 位，到期日为 365 天：

```java
keytool -genkeypair -alias server -keyalg RSA -keysize 1024 -storetype jceks -validity 365 -keypass password -keystore serverkeystore.jck -storepass password -dname "cn=localhost, ou=Department, o=MyComp Inc, l=Some City, st=JV c=US

```

此命令生成一个名为`clientkeystore.jck`的密钥库，供客户端应用程序使用：

```java
keytool -genkeypair -alias client -keyalg RSA -keysize 1024 -storetype jceks -validity 365 -keypass password -keystore clientkeystore.jck -storepass password -dname "cn=localhost, ou=Department, o=MyComp Inc, l=Some City, st=JV c=US

```

接下来创建客户端的证书文件，并放在`client.crt`文件中：

```java
keytool -export -alias client -storetype jceks -keystore clientkeystore.jck -storepass password -file client.crt

```

服务器的证书在此导出：

```java
keytool -export -alias server -storetype jceks -keystore serverkeystore.jck -storepass password -file server.crt

```

信任库是用于验证凭据的文件，而密钥库会生成凭据。凭据通常采用证书的形式。信任库通常保存来自受信任第三方的证书，以形成证书链。

以下命令创建`clienttruststore.jck`文件，这是客户端的信任库：

```java
keytool -importcert -alias server -file server.crt -keystore clienttruststore.jck -keypass password -storepass storepassword

```

此命令生成以下输出：

```java
Owner: CN=localhost, OU=Department, O=MyComp Inc, L=Some City, ST="JV c=US"
Issuer: CN=localhost, OU=Department, O=MyComp Inc, L=Some City, ST="JV c=US"
Serial number: 2d924315
Valid from: Tue Oct 20 19:26:00 CDT 2015 until: Wed Oct 19 19:26:00 CDT 2016
Certificate fingerprints:
 MD5:  9E:3D:0E:D7:02:7A:F5:23:95:1E:24:B0:55:A9:F7:95
 SHA1: 69:87:CE:EE:11:59:8F:40:A8:14:DA:D3:92:D0:3F:B6:A9:5A:7B:53
 SHA256: BF:C1:7B:6D:D0:39:67:2D:1C:68:27:79:31:AA:B8:70:2B:FD:1C:85:18:
EC:5B:D7:4A:48:03:FA:F1:B8:CD:4E
 Signature algorithm name: SHA256withRSA
 Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: D3 63 C9 60 6D 04 49 75   FB E8 F7 90 30 1D C6 C1  .c.`m.Iu....0...
0010: 10 DF 00 CF                                        ....
]
]

Trust this certificate? [no]:  yes
Certificate was added to keystore

```

使用此命令创建服务器的信任库：

```java
keytool -importcert -alias client -file client.crt -keystore servertruststore.jck -keypass password -storepass password

```

其输出如下：

```java
Owner: CN=localhost, OU=Department, O=MyComp Inc, L=Some City, ST="JV c=US"
Issuer: CN=localhost, OU=Department, O=MyComp Inc, L=Some City, ST="JV c=US"
Serial number: 5d5f3c40
Valid from: Tue Oct 20 19:27:31 CDT 2015 until: Wed Oct 19 19:27:31 CDT 2016
Certificate fingerprints:
 MD5:  0E:FE:B3:EB:1B:D2:AD:32:9C:BC:FB:43:40:85:C1:A7
 SHA1: 90:14:1E:17:DF:51:79:0B:1E:A3:EC:38:6B:BA:A6:F4:6F:BF:B6:D2
 SHA256: 7B:3E:D8:2C:04:ED:E5:52:AE:B4:00:A8:63:A1:13:A7:E1:8E:59:63:E8:
86:38:D8:09:55:EA:3A:7C:F7:EC:4B
 Signature algorithm name: SHA256withRSA
 Version: 3

Extensions:

#1: ObjectId: 2.5.29.14 Criticality=false
SubjectKeyIdentifier [
KeyIdentifier [
0000: D9 53 34 3B C0 11 F8 75   0F 18 4E 18 23 A2 47 FE  .S4;...u..N.#.G.
0010: E6 F5 C1 AF                                        ....
]
]

Trust this certificate? [no]:  yes
Certificate was added to keystore

```

我们现在将演示如何在 Java 中执行类似的操作。

## 使用 Java 创建和维护密钥库

密钥库、它们的密钥和证书可以直接使用 Java 代码创建。在本节中，我们将演示如何创建一个包含秘密密钥的密钥库。我们将在 *对称加密客户端/服务器* 部分使用这个类。

`SymmetricKeyStoreCreation` 类声明如下。`SymmetricKeyStoreCreation` 方法创建一个密钥库，而 `main` 方法生成并存储秘密密钥：

```java
public class SymmetricKeyStoreCreation {

    private static KeyStore createKeyStore(String fileName, 
            String pw) {
        ...
    }

    public static void main(String[] args) {
        ...
    }
}
```

接下来描述了 `createKeyStore` 方法。它传递密钥库的文件名和密码。创建了一个 `KeyStore` 实例，指定了一个 JCEKS 密钥库。如果密钥库已经存在，它将返回该密钥库：

```java
    private static KeyStore createKeyStore(String fileName, 
            String password) {
        try {
            File file = new File(fileName);

            final KeyStore keyStore = 
                KeyStore.getInstance("JCEKS");
            if (file.exists()) {
                keyStore.load(new FileInputStream(file), 
                    password.toCharArray());
            } else {
                keyStore.load(null, null);
                keyStore.store(new FileOutputStream(fileName), 
                    password.toCharArray());
            }
            return keyStore;
        } catch (KeyStoreException | IOException | 
                NoSuchAlgorithmException | 
                CertificateException ex) {
            // Handle exceptions
        }
        return null;
    }
```

在 `main` 方法中，使用 AES 算法创建了一个 `KeyGenerator` 实例。`generateKey` 方法将创建 `SecretKey` 实例，如下所示：

```java
    public static void main(String[] args) {
        try {
            final String keyStoreFile = "secretkeystore.jks";
            KeyStore keyStore = createKeyStore(keyStoreFile, 
                "keystorepassword");
            KeyGenerator keyGenerator = 
                KeyGenerator.getInstance("AES");
            SecretKey secretKey = keyGenerator.generateKey();
            ...
        } catch (Exception ex) {
            // Handle exceptions
        }
    }
```

`KeyStore.SecretKeyEntry` 类表示密钥库中的条目。我们需要这个类和 `KeyStore.PasswordProtection` 类的实例，它表示密码，来存储秘密密钥：

```java
            KeyStore.SecretKeyEntry keyStoreEntry
                    = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.PasswordProtection keyPassword = 
                new  KeyStore.PasswordProtection(
                        "keypassword".toCharArray());
```

`setEntry` 方法使用字符串别名、密钥库条目对象和密码来存储条目，如下所示：

```java
            keyStore.setEntry("secretKey", keyStoreEntry, 
                keyPassword);
```

然后将此条目写入密钥库：

```java
            keyStore.store(new FileOutputStream(keyStoreFile),
                    "keystorepassword".toCharArray());
```

其他密钥库操作可以使用 Java 实现。

# 对称加密客户端/服务器

本节演示了如何在客户端/服务器应用程序中使用对称加密/解密。以下示例实现了一个简单的回显客户端/服务器，使我们能够专注于基本过程，而不会偏离特定的客户端/服务器问题。服务器使用 `SymmetricEchoServer` 类实现，客户端使用 `SymmetricEchoClient` 类。

客户端将加密消息发送到服务器。服务器将解密消息并以纯文本形式发送回来。如果需要，响应可以很容易地加密。这种单向加密足以说明基本过程。

在运行本章讨论的应用程序时，在 Windows 中，您可能会遇到以下对话框。选择 **允许访问** 按钮以允许应用程序运行：

![对称加密客户端/服务器](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_08_01.jpg)

我们还将使用对称加密技术中开发的 `SymmetricKeyStoreCreation` 类。

## 对称服务器应用程序

接下来声明对称服务器。它拥有 `main`、`decrypt` 和 `getSecretKey` 方法。`decrypt` 方法从客户端接收加密消息并解密。`getSecretKey` 方法将从对称加密技术中创建的密钥库中提取秘密密钥。`main` 方法包含用于与客户端通信的基本套接字和流：

```java
public class SymmetricEchoServer {
    private static Cipher cipher;

    public static String decrypt(String encryptedText, 
        SecretKey secretKey) {
        ...
    }

    private static SecretKey getSecretKey() {
        ...
    }

    public static void main(String[] args) {
        ...
    }
}
```

`decrypt` 方法与对称加密技术中开发的方法相同，因此这里不再重复。接下来描述了 `getSecretKey` 方法。在对称加密技术中创建的 `secretkeystore.jks` 文件保存了秘密密钥。此方法使用了与 `SymmetricKeyStoreCreation` 类的 `main` 方法中使用的许多相同的类。使用 `KeyStore.PasswordProtection` 类的实例从密钥库中提取秘密密钥。密钥库密码 `keystorepassword` 被硬编码到应用程序中。这不是最佳实践，但它简化了示例：

```java
    private static SecretKey getSecretKey() {
        SecretKey keyFound = null;
        try {
            File file = new File("secretkeystore.jks");
            final KeyStore keyStore = 
                KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream(file),
                    "keystorepassword".toCharArray());
            KeyStore.PasswordProtection keyPassword = 
                new KeyStore.PasswordProtection(
                        "keypassword".toCharArray());
            KeyStore.Entry entry = 
                keyStore.getEntry("secretKey", keyPassword);
            keyFound = 
                ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        } catch (KeyStoreException | IOException | 
                NoSuchAlgorithmException | 
                CertificateException ex) {
            // Handle exceptions
        } catch (UnrecoverableEntryException ex) {
            // Handle exceptions;
        } 
        return keyFound;
    }
```

`main` 方法与在第一章中开发的服务器非常相似，*网络编程入门*。主要区别在于 while 循环内。来自客户端的输入与秘密密钥一起传递给 `decrypt` 方法，如下所示。然后显示解密后的文本并返回给客户端：

```java
            String decryptedText = decrypt(inputLine, 
                getSecretKey());
```

`main` 方法如下：

```java
    public static void main(String[] args) {
        System.out.println("Simple Echo Server");
        try (ServerSocket serverSocket = new ServerSocket(6000)) {
            System.out.println("Waiting for connection.....");

            Socket clientSocket = serverSocket.accept();
            System.out.println("Connected to client");

            try (BufferedReader br = new BufferedReader(
                new InputStreamReader(
                    clientSocket.getInputStream()));
                    PrintWriter out = new PrintWriter(
                        clientSocket.getOutputStream(), true)) {
                String inputLine;
                while ((inputLine = br.readLine()) != null) {
                    String decryptedText = 
                        decrypt(inputLine, getSecretKey());
                    System.out.println("Client request: " + 
                        decryptedText);
                    out.println(decryptedText;
                }

            } catch (IOException ex) {
                // Handle exceptions
            } catch (Exception ex) {
                // Handle exceptions
            }
        } catch (IOException ex) {
            // Handle exceptions
        }
        System.out.println("Simple Echo Server Terminating");
    }
```

现在，让我们来看一下客户端应用程序。

## 对称客户端应用程序

接下来描述客户端应用程序，它与第一章中开发的客户端应用程序非常相似。它使用与服务器相同的`getSecretKey`方法。使用对称加密技术中解释的`encrypt`方法对用户消息进行加密。这两种方法都不在此处重复：

```java
public class SymmetricEchoClient {
    private static Cipher cipher;

    public static String encrypt(String plainText, 
            SecretKey secretKey) {
        ...
    }

        ...
    }

    public static void main(String args[]) {
        ...
    } 
}
```

`main`方法与第一章中的 while 循环版本不同。以下语句加密用户消息：

```java
            String encryptedText = encrypt(inputLine, 
                getSecretKey());
```

`main`方法如下：

```java
    public static void main(String args[]) {
        System.out.println("Simple Echo Client");

        try (Socket clientSocket
                = new Socket(InetAddress.getLocalHost(), 6000);
                PrintWriter out = new PrintWriter(
                        clientSocket.getOutputStream(), true);
                BufferedReader br = new BufferedReader(
                        new InputStreamReader(
                                clientSocket.getInputStream()))) {
            System.out.println("Connected to server");
            Scanner scanner = new Scanner(System.in);

            while (true) {
                System.out.print("Enter text: ");
                String inputLine = scanner.nextLine();
                if ("quit".equalsIgnoreCase(inputLine)) {
                    break;
                }
                String encryptedText = 
                    encrypt(inputLine, getSecretKey());
                System.out.println(
                    "Encrypted Text After Encryption: "
                    + encryptedText);
                out.println(encryptedText);

                String response = br.readLine();
                System.out.println(
                    "Server response: " + response);
            }
        } catch (IOException ex) {
            // Handle exceptions
        } catch (Exception ex) {
            // Handle exceptions
        }
    }
```

我们现在准备看客户端和服务器如何交互。

## 对称客户端/服务器正在运行

应用程序的行为方式与第一章中的方式相同。唯一的区别是发送到服务器的消息是加密的。除了在客户端显示加密文本之外，此加密在应用程序的输出中是不可见的。可能的交互如下。首先显示服务器输出：

简单回显服务器

等待连接.....

已连接到客户端

客户端请求：第一条消息

客户端请求：第二条消息

简单回显服务器终止

以下是客户端应用程序的输出：

简单回显客户端

已连接到服务器

输入文本：第一条消息

加密后的文本加密后：drkvP3bhnfMXrZluFiqKb0RgjoDqFIJMCo97YqqgNuM=

服务器响应：drkvP3bhnfMXrZluFiqKb0RgjoDqFIJMCo97YqqgNuM=

输入文本：第二条消息

加密后的文本加密后：fp9g+AqsVqZpxKMVNx8IkNdDcr9IGHb/qv0qrFinmYs=

服务器响应：fp9g+AqsVqZpxKMVNx8IkNdDcr9IGHb/qv0qrFinmYs=

输入文本：退出

现在，我们将使用非对称密钥复制此功能。

# 非对称加密客户端/服务器

在支持客户端和服务器应用程序时，使用了非对称加密技术开发的`AsymmetricKeyUtility`类。我们将使用它的`encrypt`和`decrypt`方法。客户端和服务器应用程序的结构与之前的部分相似。客户端将向服务器发送加密消息，服务器将解密后以纯文本形式回复。

## 非对称服务器应用程序

如下所述，`AsymmetricEchoServer`类用于服务器。它的唯一方法是`main`方法。创建了一个服务器套接字，它在`accept`方法处阻塞，等待客户端请求：

```java
public class AsymmetricEchoServer {

    public static void main(String[] args) {
        System.out.println("Simple Echo Server");
        try (ServerSocket serverSocket = new ServerSocket(6000)) {
            System.out.println("Waiting for connection.....");
            Socket clientSocket = serverSocket.accept();
            System.out.println("Connected to client");
            ...

        } catch (IOException | NoSuchAlgorithmException | 
                 NoSuchPaddingException ex) {
            // Handle exceptions
        }
        System.out.println("Simple Echo Server Terminating");
    }
}
```

接受客户端连接 IO 后，建立 IO 流，并实例化一个大小为`171`的`inputLine`字节数组。这是正在发送的消息的大小，使用此值将避免各种异常：

```java
            try (DataInputStream in = new DataInputStream(
                    clientSocket.getInputStream());
                    PrintWriter out = new PrintWriter(
                         clientSocket.getOutputStream(), true);) {
                byte[] inputLine = new byte[171];
                ...
                }
            } catch (IOException ex) {
                // Handle exceptions
            } catch (Exception ex) {
                // Handle exceptions
            }
```

要执行解密，我们需要一个私钥。这是使用`getPrivateKey`方法获取的：

```java
                PrivateKey privateKey = 
                    AsymmetricKeyUtility.getPrivateKey();
```

while 循环将从客户端读取加密消息。使用消息和私钥调用`decrypt`方法。然后显示解密的消息并发送回客户端。如果消息是`quit`，则服务器终止：

```java
                while (true) {
                    int length = in.read(inputLine);
                    String buffer = AsymmetricKeyUtility.decrypt(
                        privateKey, inputLine);
                    System.out.println(
                        "Client request: " + buffer);

                    if ("quit".equalsIgnoreCase(buffer)) {
                        break;
                    }
                    out.println(buffer);
```

现在，让我们检查客户端应用程序。

## 非对称客户端应用程序

客户端应用程序位于`AsymmetricEchoClient`类中，如下所示。它还只有一个`main`方法。一旦建立了服务器连接，就会建立 IO 流：

```java
public class AsymmetricEchoClient {

    public static void main(String args[]) {
        System.out.println("Simple Echo Client");

        try (Socket clientSocket
                = new Socket(InetAddress.getLocalHost(), 6000);
                DataOutputStream out = new DataOutputStream(
                        clientSocket.getOutputStream());
                BufferedReader br = new BufferedReader(
                        new InputStreamReader(
                                clientSocket.getInputStream()));
                DataInputStream in = new DataInputStream(
                        clientSocket.getInputStream())) {
            System.out.println("Connected to server");
            ...
            }
        } catch (IOException ex) {
            // Handle exceptions
        } catch (Exception ex) {
            // Handle exceptions
        }
    }
}
```

使用`Scanner`类获取用户输入。使用公钥加密用户消息，并使用`AsymmetricKeyUtility`类的`getPublicKey`方法获取公钥：

```java
            Scanner scanner = new Scanner(System.in);
            PublicKey publicKey = 
                AsymmetricKeyUtility.getPublicKey();
```

在下面的 while 循环中，提示用户输入消息，然后使用`encrypt`方法对消息进行加密。然后将加密的消息发送到服务器。如果消息是`quit`，则程序终止：

```java
            while (true) {
                System.out.print("Enter text: ");
                String inputLine = scanner.nextLine();

                byte[] encodedData = 
                    AsymmetricKeyUtility.encrypt(
                        publicKey, inputLine);
                System.out.println(encodedData);

                out.write(encodedData);
                if ("quit".equalsIgnoreCase(inputLine)) {
                    break;
                }
                String message = br.readLine();
                System.out.println("Server response: " + message);
```

现在，我们可以将这些应用程序一起使用。

## 非对称客户端/服务器操作

启动服务器，然后启动客户端。客户端将提示一系列消息。以下显示了一种可能的交互输出。首先显示服务器端：

**简单回显服务器**

**等待连接.....**

**连接到客户端**

**客户端请求：第一条消息**

**客户端请求：第二条消息**

**客户端请求：退出**

**简单回显服务器终止**

以下显示了客户端的交互：

**简单回显客户端**

**连接到服务器**

**输入文本：第一条消息**

**B@6bc168e5**

**服务器响应：第一条消息**

**输入文本：第二条消息**

**[B@7b3300e5**

**服务器响应：第二条消息**

**输入文本：退出**

**[B@2e5c649**

# TLS/SSL

TLS/SSL 是用于保护互联网上许多服务器的一组协议。SSL 是 TLS 的后继者。然而，它们并不总是可以互换使用。SSL 使用**消息认证码**（**MAC**）算法，而 TLS 使用**用于消息认证码的哈希**（**HMAC**）算法。

SSL 通常与许多其他协议一起使用，包括**文件传输协议**（**FTP**）、Telnet、**网络新闻传输协议**（**NNTP**）、**轻量级目录访问协议**（**LDAP**）和**交互式消息访问协议**（**IMAP**）。

TLS/SSL 在提供这些功能方面确实会带来性能损失。然而，随着互联网速度的提高，这种损失通常并不显著。

当使用 HTTPS 协议时，用户会知道，因为该协议通常出现在浏览器的地址栏中。甚至在您可能意想不到的地方也会使用，比如在以下 Google URL 中：

![TLS/SSL

我们不会深入讨论 SSL 协议的工作原理。然而，可以在[`www.javacodegeeks.com/2013/04/understanding-transport-layer-security-secure-socket-layer.html`](http://www.javacodegeeks.com/2013/04/understanding-transport-layer-security-secure-socket-layer.html)找到对该协议的简要讨论。在本节中，我们将说明如何创建和使用 SSL 服务器以及支持该协议的 Java 类。

为了简化应用程序，客户端向服务器发送一条消息，然后服务器显示它。不会向客户端发送响应。客户端使用 SSL 连接到服务器并与之通信。使用 SSL 将消息返回给客户端留作读者的练习。

## SSL 服务器

服务器实现在以下`SSLServer`类中。所有代码都在`main`方法中找到。我们将使用`keystore.jks`密钥库来访问在对称加密技术中创建的秘密密钥。为了提供对密钥库的访问，使用`Provider`实例来指定密钥库及其密码。在代码中硬编码密码并不是一个好主意，但为了简化这个例子，我们使用了它：

```java
public class SSLServer {

    public static void main(String[] args) throws Exception {
        System.out.println("SSL Server Started");
        Security.addProvider(new Provider());
        System.setProperty("javax.net.ssl.keyStore", 
            "keystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", 
            "password");
        ...

    }

}
```

`SSLServerSocket`类的一个实例用于在客户端和服务器之间建立通信。使用`SSLServerSocketFactory`类的`getDefault`方法创建此实例。与以前的服务器套接字类似，`accept`方法会阻塞，直到建立客户端连接：

```java
        SSLServerSocketFactory sslServerSocketfactory =
            (SSLServerSocketFactory) 
            SSLServerSocketFactory.getDefault();
        SSLServerSocket sslServerSocket = (SSLServerSocket) 
                sslServerSocketfactory.createServerSocket(5000);
        System.out.println("Waiting for a connection");
        SSLSocket sslSocket = 
            (SSLSocket) sslServerSocket.accept();
        System.out.println("Connection established");
```

然后从套接字的输出流创建了一个`BufferedReader`实例：

```java
        PrintWriter pw = 
            new PrintWriter(sslSocket.getOutputStream(), true);
        BufferedReader br = new BufferedReader(
            new InputStreamReader(sslSocket.getInputStream()));
```

以下 while 循环读取客户端请求并显示它。如果消息是`退出`，则服务器终止：

```java
        String inputLine;
        while ((inputLine = br.readLine()) != null) {
            pw.println(inputLine);
            if ("quit".equalsIgnoreCase(inputLine)) {
                break;
            }
            System.out.println("Receiving: " + inputLine);
        }
```

SSL 套接字会自动处理加密和解密。

### 注意

在 Mac 上执行时，服务器可能会抛出异常。可以通过创建 PKCS12 密钥库并使用`-Djavax.net.ssl.keyStoreType=pkcs12 VM`选项来避免这种情况。

## SSL 客户端

`SSLClient`类实现了客户端应用程序，如下所示。它基本上使用与服务器相同的过程。while 循环以与以前的客户端应用程序相同的方式处理用户输入：

```java
public class SSLClient {

    public static void main(String[] args) throws Exception {
        System.out.println("SSL Client Started");
        Security.addProvider(new Provider());
        System.setProperty("javax.net.ssl.trustStore", 
            "keystore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", 
            "password");

        SSLSocketFactory sslsocketfactory = (SSLSocketFactory) 
            SSLSocketFactory.getDefault();
        SSLSocket sslSocket = (SSLSocket) 
            sslsocketfactory.createSocket("localhost", 5000);
        System.out.println(
            "Connection to SSL Server Established");

        PrintWriter pw = 
            new PrintWriter(sslSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(
            new InputStreamReader(sslSocket.getInputStream()));

        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.print("Enter a message: ");
            String message = scanner.nextLine();
            pw.println(message);
            System.out.println("Sending: " + in.readLine());
            if ("quit".equalsIgnoreCase(message)) {
                break;
            }
        }
        pw.close();
        in.close();
        sslSocket.close();
    }
}
```

让我们看看它们是如何交互的。

## TLS/SSL 客户端/服务器操作

启动服务器，然后启动客户端。在以下输出中，向服务器发送了三条消息，然后显示：

**SSL 服务器已启动**

**等待连接**

**连接已建立**

**接收：第一条消息**

**接收：第二条消息**

客户端输入如下所示：

**SSL 客户端已启动**

**已建立与 SSL 服务器的连接**

**输入消息：第一条消息**

**发送：第一条消息**

**输入消息：第二条消息**

**发送：第二条消息**

**输入消息：退出**

**发送：退出**

`SSLServerSocket`类提供了一种简单的实现 SSL 启用服务器的方法。

# 安全哈希函数

安全哈希函数将在给定某种文档时生成一个称为哈希值的大数字。这个文档可以是几乎任何类型。我们将在我们的示例中使用简单的字符串。

该函数是单向哈希函数，这意味着在给定哈希值时，实际上不可能重新创建文档。当与非对称密钥一起使用时，它允许传输文档，并保证文档未被更改。

文档的发送方将使用安全哈希函数为文档生成哈希值。发送方将使用他们的私钥加密此哈希值。然后将文档和密钥组合并发送给接收方。文档未加密。

在接收文档后，接收方将使用发送方的公钥解密哈希值。然后接收方将使用相同的安全哈希函数对文档进行哈希值计算。如果此哈希值与解密的哈希值匹配，则接收方保证文档未被修改。

意图不是加密文档。虽然可能，但当不重要隐藏文档免受第三方查看，只需提供文档未被修改的保证时，这种方法是有用的。

Java 支持以下哈希算法：

+   **MD5**：默认大小为 64 字节

+   **SHA1**：默认大小为 64 字节

我们将在我们的示例中使用 SHA 哈希函数。这一系列函数是由**国家安全局**（**NSA**）开发的。这个哈希函数有三个版本：SHA-0，SHA-1 和 SHA-2。SHA-2 是更安全的算法，并使用可变的摘要大小：SHA-224，SHA-256，SHA-384 和 SHA-512。

`MessageDigest`类处理任意大小的数据，生成固定大小的哈希值。这个类没有公共构造函数。`getInstance`方法在给定算法名称时返回类的实例。有效名称可以在[`docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest`](http://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#MessageDigest)找到。在这个例子中，我们使用`SHA-256`：

```java
    MessageDigest messageDigest =
        MessageDigest.getInstance("SHA-256");
    messageDigest.update(message.getBytes());
```

完整的示例，改编自[`www.mkyong.com/java/java-sha-hashing-example/`](http://www.mkyong.com/java/java-sha-hashing-example/)，如下所示。`displayHashValue`方法提取单个哈希值字节并将其转换为可打印格式。

```java
public class SHAHashingExample {

    public static void main(String[] args) throws Exception {
        SHAHashingExample example = new SHAHashingExample();
        String message = "This is a simple text message";
        byte hashValue[] = example.getHashValue(message);
        example.displayHashValue(hashValue);
    }

    public void displayHashValue(byte hashValue[]) {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < hashValue.length; i++) {
            builder.append(Integer.toString((hashValue[i] & 0xff) 
                + 0x100, 16).substring(1));
        }
        System.out.println("Hash Value: " + builder.toString());
    }

    public byte[] getHashValue(String message) {
        try {
            MessageDigest messageDigest = 
                MessageDigest.getInstance("SHA-256");
            messageDigest.update(message.getBytes());
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException ex) {
            // Handle exceptions
        }
        return null;
    }
}
```

执行程序。这将产生以下输出：

**哈希值：83c660972991049c25e6cad7a5600fc4d7c062c097b9a75c1c4f13238375c26c**

在 Java 中实现的安全哈希函数的更详细的介绍可以在[`howtodoinjava.com/2013/07/22/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/`](http://howtodoinjava.com/2013/07/22/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/)找到。

# 摘要

在本章中，我们介绍了几种 Java 应用程序之间安全通信的方法。我们从安全相关术语的简要介绍开始，然后进行了更详细的讨论。

今天有两种常见的加密/解密方法。第一种是对称密钥加密，它使用一个在应用程序之间共享的单个密钥。这种方法要求密钥以安全的方式在应用程序之间传输。

第二种方法使用非对称加密。这种技术使用私钥和公钥。使用其中一个密钥加密的消息可以用另一个密钥解密。通常，公钥是使用来自受信任来源的证书进行分发的。私钥的持有者需要确保它没有被其他人访问。公钥可以自由地与需要它的任何人分享。

加密密钥通常存储在允许程序访问密钥的密钥库中。密钥库是使用 keytool 应用程序创建和维护的。我们演示了在我们的几个应用程序中创建和使用密钥库。此外，我们使用对称密钥和非对称密钥对来支持回显客户端/服务器应用程序。

创建安全客户端和服务器的更常见方法是使用`SSLServerSocket`类。这个类基于密钥库中的秘密密钥执行数据的自动加密和解密。我们演示了这个类如何在服务器和客户端应用程序中使用。

我们还研究了安全哈希函数的使用。这种技术允许未加密的数据被传输，并保证它没有被修改。非对称密钥对用于加密哈希值。我们提供了这个过程的一个简单示例。

在下一章中，我们将调查影响分布式应用程序之间交互的各种因素。


# 第九章：网络互操作性

网络互操作性指的是不同实现技术的系统可靠准确地交换信息的能力。这意味着底层硬件、操作系统和实现语言等因素可能在平台之间有所不同，但它们不会对这些系统进行通信的能力产生不利影响。

有几个因素可能会影响互操作性。这些因素从低级问题，如原始数据类型使用的字节顺序，到更高级的技术，如大部分隐藏其实现细节的 Web 服务。在本章中，我们将探讨许多这些因素。

我们首先讨论支持原始数据类型的字节顺序。这对于数据传输是至关重要的。不同的字节顺序会导致信息解释方式的显著差异。

接下来，我们将讨论 Java 应用程序如何与用不同语言编写的应用程序进行交互。这些可能是基于 JVM 的语言或与 Java 截然不同的语言。

基本的网络通信构造是套接字。这个实体通常在 TCP/IP 环境中运行。我们将演示 Java 套接字如何与用不同语言（特别是 C#）编写的套接字进行交互。

最重要的互操作性支持存在于以 Web 服务为代表的通信标准形式中。这些应用程序支持使用标准化中间件在不同系统之间进行通信。这些中间件实现大部分通信细节。

我们将调查以下互操作性主题：

+   Java 如何处理字节顺序

+   与其他语言进行接口

+   通过套接字通信

+   使用中间件实现互操作性

因此，让我们从讨论字节顺序及其对互操作性的影响开始。

# Java 中的字节顺序

有两种字节顺序：**大端序**和**小端序**。这些术语指的是多字节数量在内存中存储的顺序。为了说明这一点，考虑整数在内存中的存储方式。由于整数由 4 个字节组成，这些字节被分配给内存的 4 字节区域。然而，这些字节可以以不同的方式存储。大端序将最重要的字节放在最前面，而小端序将最不重要的字节放在最前面。

考虑以下整数的声明和初始化：

```java
        int number = 0x01234567;
```

在下面的示例中，假设整数已分配到地址`1000`，使用大端序显示内存的四个字节：

| 地址 | 字节 |
| --- | --- |
| 1000 | 01 |
| 1001 | 23 |
| 1002 | 45 |
| 1003 | 67 |

下表显示了使用小端序存储整数的方式：

| 地址 | 字节 |
| --- | --- |
| 1000 | 67 |
| 1001 | 45 |
| 1002 | 23 |
| 1003 | 01 |

机器的字节顺序有以下几种方式：

+   基于 Intel 的处理器使用小端序

+   ARM 处理器可能使用小端序或大端序

+   Motorola 68K 处理器使用大端序

+   Motorola PowerPC 使用大端序

+   Sun SPARK 处理器使用大端序

发送数据，如 ASCII 字符串，不是问题，因为这些字节是按顺序存储的。对于其他数据类型，如浮点数和长整型，可能会有问题。

如果我们需要知道当前机器支持哪种表示形式，`java.nio`包中的`ByteOder`类可以确定当前的字节顺序。以下语句将显示当前平台的字节序：

```java
        System.out.println(ByteOrder.nativeOrder());
```

对于 Windows 平台，它将显示如下内容：

**LITTLE_ENDIAN**

`DataOutputStream`类的方法自动使用大端序。`ByteBuffer`类也默认使用大端序。然而，如下所示，顺序可以被指定：

```java
        ByteBuffer buffer = ByteBuffer.allocate(4096);
        System.out.println(buffer.order());
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        System.out.println(buffer.order());
```

这将显示如下内容：

**BIG_ENDIAN**

**LITTLE_ENDIAN**

一旦建立，其他方法，比如`slice`方法，不会改变使用的字节顺序，如下所示：

```java
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        ByteBuffer slice = buffer.slice();
        System.out.println(buffer.order());
```

输出将如下所示：

**LITTLE_ENDIAN**

字节序通常会在机器上自动处理。然而，当我们在使用不同字节序的机器之间传输数据时，可能会出现问题。传输的字节可能会在目的地以错误的顺序。

网络通常使用大端序，也称为**网络字节顺序**。通过套接字发送的任何数据都应该使用大端序。在 Java 应用程序之间发送信息时，字节序通常不是一个问题。然而，当与非 Java 技术交互时，字节序更为重要。

# 与其他语言进行接口

有时，有必要访问用不同语言编写的库。虽然这不是一个纯粹的网络问题，但 Java 以多种方式提供支持。直接与其他语言进行接口不是通过网络进行的，而是在同一台机器上进行的。我们将简要地检查一些这些接口问题。

如果我们使用另一个 Java 库，那么我们只需要加载类。如果我们需要与非 Java 语言进行接口，那么我们可以使用**Java 本地接口**（**JNI**）API 或其他库。然而，如果这种语言是基于 JVM 的语言，那么这个过程会更容易。

## 与基于 JVM 的语言进行接口

**Java 虚拟机**（**JVM**）执行 Java 字节码。然而，不仅有 Java 使用 JVM。其他语言包括以下几种：

+   **Nashorn**：这使用 JavaScript

+   **Clojure**：这是一种 Lisp 方言

+   **Groovy**：这是一种脚本语言

+   **Scala**：这结合了面向对象和函数式编程方法

+   **JRuby**：这是 Ruby 的 Java 实现

+   **Jthon**：这是 Python 的 Java 实现

+   **Jacl**：这是 Tcl 的 Java 实现

+   **TuProlog**：这是 Prolog 的基于 Java 的实现

更完整的基于 JVM 的语言列表可以在[`en.wikipedia.org/wiki/List_of_JVM_languages`](https://en.wikipedia.org/wiki/List_of_JVM_languages)找到。使用相同的 JVM 基础将有助于共享代码和库。通常，不仅可以使用在不同基于 JVM 的语言中开发的库，还可以从不同语言中开发的类中派生。

许多语言已经移植到 JVM，因为使用 JVM 比为不同平台创建多个编译器或解释器更容易。例如，Ruby 和 Python 有 JVM 实现的原因。这些语言可以利用 JVM 的可移植性和其**即时编译**（**JIT**）过程。除此之外，JVM 还有一个大型的经过充分测试的代码库可供利用。

Nashorn 是构建在 JVM 之上并在 Java 8 中添加的 JavaScript 引擎。这允许 JavaScript 代码被轻松地集成到 Java 应用程序中。以下代码序列说明了这个过程。首先获得 JavaScript 引擎的一个实例，然后执行 JavaScript 代码：

```java
    try {
        ScriptEngine engine = 
            new ScriptEngineManager().getEngineByName("nashorn");
        engine.eval("print('Executing JavaScript code');");
    } catch (ScriptException ex) {
        // Handle exceptions
    }
```

这个序列的输出如下：

**执行 JavaScript 代码**

更复杂的 JavaScript 处理是可能的。关于这项技术的更多细节可以在[`docs.oracle.com/javase/8/docs/technotes/guides/scripting/nashorn/`](https://docs.oracle.com/javase/8/docs/technotes/guides/scripting/nashorn/)找到。

## 与非 JVM 语言进行接口

访问不同语言中的代码的常见技术是通过 JNI API。这个 API 提供了访问 C/C++代码的方法。这种方法有很好的文档，这里不会进行演示。然而，可以在[`www.ibm.com/developerworks/java/tutorials/j-jni/j-jni.html`](http://www.ibm.com/developerworks/java/tutorials/j-jni/j-jni.html)找到这个 API 的很好介绍。

可以从 Java 访问.NET 代码。一种技术使用 JNI 访问 C#。如何访问 C++、托管 C++和 C#代码的示例可在[`www.codeproject.com/Articles/13093/C-method-calls-within-a-Java-program`](http://www.codeproject.com/Articles/13093/C-method-calls-within-a-Java-program)找到。

# 通过简单的套接字进行通信

使用套接字可以在不同语言编写的应用程序之间传输信息。套接字概念并不是 Java 独有的，已经在许多语言中实现。由于套接字在 TCP/IP 级别工作，它们可以在不费吹灰之力的情况下进行通信。

主要的互操作性考虑涉及传输的数据。当数据的内部表示在两种不同的语言之间有显着差异时，可能会发生不兼容性。这可能是由于数据类型在内部的表示中使用大端或小端，以及特定数据类型是否存在于另一种语言中。例如，在 C 中没有明确的布尔数据类型。它是用整数表示的。

在本节中，我们将在 Java 中开发一个服务器，在 C#中开发一个客户端。为了演示使用套接字，在这两个应用程序之间传输一个字符串。我们将发现，即使是传输简单的数据类型，比如字符串，也可能比看起来更困难。

## Java 服务器

服务器在`JavaSocket`类中声明，如下所示。它看起来与本书中开发的以前版本的回显服务器非常相似。创建服务器套接字，然后阻塞，直到`accept`方法返回与客户端连接的套接字：

```java
public class JavaSocket {

    public static void main(String[] args) {
        System.out.println("Server Started");
        try (ServerSocket serverSocket = new ServerSocket(5000)) {
            Socket socket = serverSocket.accept();
            System.out.println("Client connection completed");
            ...
            socket.close();
        } catch (IOException ex) {
            // Handle exceptions
        }
        System.out.println("Server Terminated");
    }
}
```

`Scanner`类用于读取从客户端发送的消息。`PrintWriter`实例用于回复客户端：

```java
            Scanner scanner = 
                new Scanner(socket.getInputStream());
            PrintWriter pw = new PrintWriter(
                socket.getOutputStream(), true);
```

`nextLine`方法检索消息，显示并发送回客户端：

```java
            String message = scanner.nextLine();
            System.out.println("Server received: " + message);
            pw.println(message);
            System.out.println("Server sent: " + message);
```

服务器将终止。

现在，让我们来看看 C#应用程序。

## C#客户端

`CSharpClient`类，如下所示，实现了客户端。C#在形式和语法上类似于 Java，尽管类库通常不同。我们不会提供代码的详细解释，但我们将介绍应用程序的重要特性。

`using`语句对应于 Java 中的导入语句。与 Java 类似，要执行的第一个方法是`Main`方法。C#通常使用不同的缩进样式和命名约定：

```java
using System;
using System.Net;
using System.Net.Sockets;

namespace CSharpSocket
{
    class CSharpClient
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("Client Started");
            ...
        }
    }
}
```

`IPEndPoint`变量表示 Internet 地址，`Socket`类，正如你可能期望的那样，表示套接字。`Connect`方法连接到服务器：

```java
            IPEndPoint serverAddress = 
               new IPEndPoint(IPAddress.Parse("127.0.0.1"), 5000);
            Socket clientSocket = 
                new Socket(AddressFamily.InterNetwork, 
                    SocketType.Stream, ProtocolType.Tcp);
            clientSocket.Connect(serverAddress);
```

`Console`类的`Write`方法在命令窗口中显示信息。在这里，用户被提示输入要发送到服务器的消息。`ReadLine`方法读取用户输入：

```java
            Console.Write("Enter message: ");
            String message = Console.ReadLine();
```

`Send`方法将数据传输到服务器。但是，它需要将数据放入字节缓冲区，如下所示。消息和附加的回车/换行字符被编码并插入到缓冲区中。需要附加字符以便服务器可以正确读取字符串并知道字符串何时终止：

```java
            byte[] messageBuffer;
            messageBuffer = System.Text.Encoding.ASCII.GetBytes(
               message + "\n");
            clientSocket.Send(messageBuffer);
```

`Receive`方法读取服务器的响应。与`Send`方法类似，它需要一个字节缓冲区。这个缓冲区的大小为 32 字节。这限制了消息的大小，但我们将讨论如何克服这个限制：

```java
            byte[] receiveBuffer = new byte[32];
            clientSocket.Receive(receiveBuffer);
```

接收缓冲区被转换为字符串并显示。开始和结束括号用于清楚地界定缓冲区：

```java
            String recievedMessage = 
               System.Text.Encoding.ASCII.GetString(
                   receiveBuffer);
            Console.WriteLine("Client received: [" + 
               recievedMessage + "]");
```

套接字关闭，应用程序终止：

```java
            clientSocket.Close();
            Console.WriteLine("Client Terminated");
```

## 客户端/服务器操作

启动服务器，然后启动客户端。客户端用户将被提示输入消息。输入消息。消息将被发送，并在客户端窗口中显示响应。

服务器输出显示在这里：

**服务器已启动**

**客户端连接完成**

**服务器收到：消息**

**服务器发送：消息**

**服务器终止**

客户端界面如下：

**客户端已启动**

**输入消息：The message**

**客户端收到：[The message**

**]**

**客户端终止**

**按任意键继续. . .**

您会注意到收到的消息比预期的要大。这是因为客户端的接收字节缓冲区长度为 32 字节。这个实现使用了固定大小的缓冲区。由于来自服务器的响应大小可能并不总是已知的，因此缓冲区需要足够大以容纳响应。32 的大小用于限制服务器的输出。

可以通过多种方式克服这个限制。一种方法是在字符串末尾附加一个特殊字符，然后使用此标记构造响应。另一种方法是首先发送响应的长度，然后是响应。接收缓冲区可以根据响应的长度进行分配。

发送字符串对于传输格式化信息很有用。例如，发送的消息可以是 XML 或 JSON 文档。这将有助于传输更复杂的内容。

# 通过中间件实现互操作性

在过去的 20 年里，网络技术已经有了很大的发展。低级套接字支持为大多数这些技术提供了基础。然而，它们通过多层软件隐藏在用户之下。这些层被称为**中间件**。

通过中间件（如 JMI、SOAP 和 JAX-WS 等）实现了互操作性。Java EE 版主要旨在支持这些中间件类型的技术。Java EE 从**servlets**开始，这是一个用于支持网页的 Java 应用程序。它已经发展到包括**Java 服务器页面**（**JSP**），最终到**Faclets**，这两者都隐藏了底层的 Servlets。

这些技术涉及为用户提供服务，无论是在浏览器上的人还是其他应用程序。用户不一定知道服务是如何实现的。通信是通过多种不同的标准实现的，并且数据经常封装在语言中立的 XML 文档中。因此，服务器和客户端可以用不同的语言编写，并在不同的执行环境中运行，促进了互操作性。

虽然有许多可用的技术，但通常使用两种常见的方法：RESTful Web 服务和基于 SOAP 的 Web 服务。**表述状态转移 Web 服务**（**RESTful Web 服务**）使用 HTTP 和标准命令（`PUT`、`POST`、`GET`、`DELETE`）来支持 Web 页面和其他资源的分发。其目的是简化这些类型的服务的创建方式。客户端和服务器之间的交互是无状态的。也就是说，先前处理的内容不会影响当前请求的处理方式。

**基于 SOAP 的 Web 服务**使用**简单对象访问协议**（**SOAP**）来交换结构化信息。它使用应用层协议，如 HTTP 和 SMTP，并使用 XML 进行通信。我们将专注于 JAX-RS。

**用于 RESTful Web 服务的 Java API**（**JAX-RS**）是支持 RESTful 服务开发的 API。它使用一系列注解将资源映射到 Java 实现。为了演示这项技术的工作原理，我们将使用 NetBeans 创建一个简单的 RESTful 应用程序。

## 创建 RESTful 服务

我们将首先创建服务器，然后创建一个简单的基于控制台的应用程序来访问服务器。我们将使用 NetBeans IDE 8.0.2 来开发此服务。NetBeans 可以从[`netbeans.org/downloads/`](https://netbeans.org/downloads/)下载。选择 Java EE 版本。

安装 NetBeans 后，启动它，然后从**文件** | **新建项目...**菜单项创建一个新项目。这将弹出**新建项目**对话框，如下所示。选择**Java Web**类别和**Web 应用程序**项目。然后，选择**下一步**：

![创建 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_01.jpg)

给项目命名。在下图中，我们使用了`SimpleRestfulService`作为其名称。选择一个适当的位置保存项目，然后选择**下一步**：

![创建 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_02.jpg)

在**服务器和设置**步骤中，选择 GlassFish 服务器和 Java EE7 Web。GlassFish 是我们将用于托管服务的 Web 服务器。**上下文路径**字段将成为传递给服务器的 URL 的一部分。再次点击**下一步**：

![创建 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_03.jpg)

我们可以从三种设计模式中选择一种来创建我们的 RESTful 服务。在本例中，选择第一种**简单根资源**，然后点击**下一步**：

![创建 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_04.jpg)

在**指定资源类**步骤中，填写对话框，如下所示。资源包是 Java 类将放置的位置。路径用于向用户标识资源。类名字段将是支持资源的 Java 类的名称。完成后，点击**完成**：

![创建 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_05.jpg)

然后 IDE 将生成文件，包括`ApplicationConfig.java`和`SimpleRestfulService.java`文件。`ApplicationConfig.java`文件用于配置服务。我们主要关注的是`SimpleRestfulService.java`文件。

在`SimpleRestfulService`类中有`getHtml`方法，如下所示。它的目的是生成对`GET`命令的响应。第一个注释指定了当使用`HTTP GET`命令时要调用的方法。第二个注释指定了该方法的预期输出是 HTML 文本。IDE 生成的返回语句已被简单的 HTML 响应替换：

```java
    @GET
    @Produces("text/html")
    public String getHtml() {
        return 
            "<html><body><h1>Hello, World!!</body></h1></html>";
    }
```

当使用`GET`命令请求服务时，将返回 HTML 文本。所有中间步骤，包括套接字的使用，都被隐藏，简化了开发过程。

## 测试 RESTful 服务

我们将开发一个客户端应用程序来访问此资源。但是，我们可以使用内置设施测试资源。要测试服务，请在**项目资源管理器**窗口中右键单击项目名称，然后选择**测试 RESTful Web 服务**菜单项。这将弹出以下窗口。点击**确定**：

![测试 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_06.jpg)

在 Windows 上可能会收到安全警报。如果发生这种情况，请选择**允许访问**按钮：

![测试 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_07.jpg)

默认浏览器将显示测试页面，如下所示。选择**packt**节点：

![测试 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_08.jpg)

然后资源将显示在右侧，如下所示。这使我们可以选择测试方法。由于默认选择了`GET`命令，因此点击**测试**按钮：

![测试 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_09.jpg)

然后将`GET`命令发送到服务器，并显示响应，如下所示。

![测试 RESTful 服务](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_10.jpg)

可以使用 JAX_RS 执行更复杂的处理。但是，这说明了基本方法。

## 创建 RESTful 客户端

RESTful 服务可以被写成各种语言的任意数量的应用程序调用。在这里，我们将创建一个简单的 Java 客户端来访问此服务。

创建一个新项目，并从**Web 服务**类别中选择**RESTful Java 客户端**选项，如下所示。然后点击**下一步**：

![创建 RESTful 客户端](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_11.jpg)

**名称和位置**步骤对话框将显示如下截图所示。我们需要选择 RESTful 资源。我们可以通过单击**浏览...**按钮来执行此操作：

![创建 RESTful 客户端](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_12.jpg)

**可用的 REST 资源**对话框将显示如下。展开我们的 RESTful 项目并选择资源，如下截图所示，然后单击**确定**：

![创建 RESTful 客户端](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_13.jpg)

完成的对话框应如下所示。单击**完成**：

![创建 RESTful 客户端](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/lrn-net-prog-java/img/B04915_09_14.jpg)

然后生成`RestfulClient`类。我们对`getHtml`方法感兴趣，如下所示。这将从服务返回 HTML 文本：

```java
    public String getHtml() throws ClientErrorException {
        WebTarget resource = webTarget;
        return resource.
            request(javax.ws.rs.core.MediaType.TEXT_HTML).
            get(String.class);
    }
```

要测试应用程序，请添加以下`main`方法，调用`getHtml`方法：

```java
    public static void main(String[] args) {
        RestfulClient restfulClient = new RestfulClient();
        System.out.println(restfulClient.getHtml());
    }
```

确保 GlassFish 服务器正在运行，并执行程序。输出将如下所示：

**<html><body><h1>简单的 Restful 示例</body></h1></html>**

虽然我们通常不会在控制台中显示 HTML 文本，但这说明了我们从 RESTful 服务获取信息的过程。

# 摘要

在本章中，我们探讨了许多影响网络互操作性的因素。在低级别上，字节顺序变得重要。我们了解到系统使用大端或小端字节顺序。顺序可以由 Java 应用程序确定和控制。网络通信在传输数据时通常使用大端。

如果我们需要与其他语言通信，我们发现基于 JVM 的语言更容易使用，因为它们共享相同的字节码基础。如果我们需要与其他语言一起工作，那么通常使用 JNI。

套接字不是 Java 独有的概念。它通常用于 TCP/IP 环境，这意味着用一种语言编写的套接字可以轻松地与用另一种语言编写的套接字进行通信。我们使用 Java 服务器和 C#客户端演示了这种能力。

我们还探讨了中间件如何通过抽象化大部分低级通信细节来支持互操作性。使用诸如 Web 服务之类的概念，我们了解到低级套接字交互的细节被隐藏起来。我们使用 JAX-RS 进行了演示，它支持 RESTful 方法，其中 HTTP 命令（如 GET 和 POST）被映射到特定的 Java 功能。

网络互操作性是企业级应用程序中的重要考虑因素，企业的功能是通过各种技术进行分布的。通过使用标准中间件协议和产品，可以实现这种互操作性。
