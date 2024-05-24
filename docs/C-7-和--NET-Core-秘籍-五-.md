# C#7 和 .NET Core 秘籍（五）

> 原文：[`zh.annas-archive.org/md5/FFE2E66D9C939D110BF0079B0B5B3BA8`](https://zh.annas-archive.org/md5/FFE2E66D9C939D110BF0079B0B5B3BA8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：在 Visual Studio 中编写安全代码和调试

在本章中，我们将看一些例子，作为开发人员在调试代码时更高效的方式。我们还将看看如何编写安全的代码。编写安全的代码可能是一个挑战，但请考虑以下内容：如果您的代码安全的一部分涉及确保密码安全存储，为什么要在项目之间一遍又一遍地编写代码？只需编写一次代码，然后在创建的每个新项目中实施它。我们将要看的概念如下：

+   正确加密和存储密码

+   在代码中使用 SecureString

+   保护 App.config/web.config 的敏感部分

+   防止 SQL 注入攻击

+   使用 IntelliTrace、诊断工具和历史调试

+   设置条件断点

+   使用 PerfTips 识别代码中的瓶颈

# 介绍

许多开发人员经常忽视的一点是编写安全的代码。开发期限和其他与项目相关的压力会导致开发人员将交付代码置于正确方式之上。你们中的许多人可能不同意我，但相信我，我已经听到“我们没有预算”这样的借口太多次了。这通常是在开发预算已由其他利益相关者确定且未经开发人员咨询时发生的。

考虑这样一种情况，顾问告诉开发人员他们已经向客户出售了一个系统。现在需要开发该系统。此外，开发人员被告知他们有*x*小时来完成开发。给开发人员提供了一份概述需求的文件，并允许开发人员开始，并在规定的时间内完成开发。

这种情况是许多开发人员面临的现实。你可能认为这种情况不可能存在，或者你正在阅读这篇文章，并将这种情况视为你公司目前的工作流程。无论情况如何，这是今天软件开发中发生的事情。

那么，开发人员如何应对项目自杀（我将这些项目称为这样，因为像这样处理的项目很少成功）？首先要创建可重用的代码。考虑一下你经常重复的流程是否值得编写可重用的 DLL。你知道你可以创建 Visual Studio 模板吗？如果你有一个标准的项目结构，可以从中创建一个模板，并在每个新项目中重用它，从而加快交付速度并减少错误。

项目模板的一些考虑因素是数据库层、安全层、常见验证代码（此数据表是否包含任何数据？）、常见扩展方法等等。

# 正确加密和存储密码

我经常看到的一件事是密码存储不当。仅仅因为密码存储在服务器上的数据库中，并不意味着它是安全的。那么，密码存储不当是什么样子呢？

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_15_01.png)

存储不当的安全密码不再安全。上一张截图中的密码是实际用户密码。在登录屏幕上输入第一个密码`^tj_Y4$g1!8LkD`将使用户访问系统。密码应该安全地存储在数据库中。实际上，您需要使用盐加密密码。您应该能够加密用户的密码，但永远不要解密它。

那么，你如何解密密码以匹配用户在登录屏幕上输入的密码？嗯，你不会。你总是对用户在登录屏幕上输入的密码进行哈希处理。如果它与存储在数据库中的他们真实密码的哈希匹配，你就允许他们访问系统。

# 做好准备

本食谱中的 SQL 表仅用于说明，不是由食谱中的代码编写的。可以在伴随本书源代码的“_ 数据库脚本”文件夹中找到数据库。

# 如何做…

1.  最简单的方法是创建一个控制台应用程序，然后通过右键单击解决方案，选择“添加”，然后从上下文菜单中选择“新建项目”来添加一个新的类库。

1.  从“添加新项目”对话框屏幕中，从已安装的模板中选择“类库”，并将您的类命名为`Chapter15`。

1.  您的新类库将添加到解决方案中，并具有默认名称`Class1.cs`，我们将其重命名为`Recipes.cs`以正确区分代码。但是，如果您觉得更合理，可以将类重命名为任何您喜欢的名称。

1.  要重命名您的类，只需在“解决方案资源管理器”中单击类名，然后从上下文菜单中选择“重命名”。

1.  Visual Studio 将要求您确认对项目中代码元素 Class1 的所有引用的重命名。只需单击“是”。

1.  以下类将添加到您的`Chapter15`库项目中：

```cs
        namespace Chapter15 
        { 
          public static class Recipes 
          { 

          } 
        }

```

1.  在您的类中添加以下`using`语句：

```cs
        using System.Security.Cryptography;

```

1.  接下来，您需要向类中添加两个属性。这些属性将存储盐和哈希值。通常，您将这些值与用户名一起写入数据库，但是，为了本示例的目的，我们将它们简单地添加到静态属性中。还要向类中添加两个方法，分别称为`RegisterUser()`和`ValidateLogin()`。这两个方法都以`username`和`password`变量作为参数：

```cs
        public static class Recipes 
        { 
          public static string saltValue { get; set; } 
          public static string hashValue { get; set; } 

          public static void RegisterUser(string password, string 
            username) 
          { 

          } 

          public static void ValidateLogin(string password, 
            string username) 
          {                   

          } 
        }

```

1.  从`RegisterUser()`方法开始，我们做了一些事情。列出方法中的步骤：

1\. 我们使用`RNGCryptoServiceProvider`生成一个真正随机的、密码学强的盐值。

2\. 将盐添加到密码中，并使用`SHA256`对加盐的密码进行哈希。

在密码之前或之后添加盐都无所谓。只需记住每次都要保持一致。

3\. 将盐值和哈希值与用户名一起存储在数据库中。

为了减少代码量，我实际上没有添加代码将哈希和盐值写入数据库。我只是将它们添加到之前创建的属性中。在实际情况下，您应该始终将这些值写入数据库。

这是在应用程序中处理用户密码的一种非常安全的方式：

```cs
        public static void RegisterUser(string password, string  username) 
        { 
          // Create a truly random salt using RNGCryptoServiceProvider. 
          RNGCryptoServiceProvider csprng = new RNGCryptoServiceProvider(); 
          byte[] salt = new byte[32]; 
          csprng.GetBytes(salt); 

          // Get the salt value 
          saltValue = Convert.ToBase64String(salt); 
          // Salt the password 
          byte[] saltedPassword = Encoding.UTF8.GetBytes(
            saltValue + password); 

          // Hash the salted password using SHA256 
          SHA256Managed hashstring = new SHA256Managed(); 
          byte[] hash = hashstring.ComputeHash(saltedPassword); 

          // Save both the salt and the hash in the user's database record. 
          saltValue = Convert.ToBase64String(salt); 
          hashValue = Convert.ToBase64String(hash);             
        }

```

1.  我们需要创建的下一个方法是`ValidateLogin()`方法。在这里，我们首先获取用户名并验证。如果用户输入的用户名不正确，请不要告诉他们。这会提醒试图破坏系统的人，他们输入了错误的用户名，并且一旦他们收到错误的密码通知，他们就知道用户名是正确的。此方法中的步骤如下：

1.  从数据库中获取输入的用户名的盐和哈希值。

1.  使用从数据库中读取的盐对用户在登录屏幕上输入的密码进行加盐。

1.  使用用户注册时相同的哈希算法对加盐的密码进行哈希。

1.  将从数据库中读取的哈希值与方法中生成的哈希值进行比较。如果两个哈希值匹配，则密码被正确输入并且用户被验证。

请注意，我们从未从数据库中解密密码。如果您的代码解密用户密码并匹配输入的密码，您需要重新考虑并重写密码逻辑。系统永远不应该能够解密用户密码。

```cs
        public static void ValidateLogin(string password, string username) 
        {             
          // Read the user's salt value from the database 
          string saltValueFromDB = saltValue; 

          // Read the user's hash value from the database 
          string hashValueFromDB = hashValue; 

          byte[] saltedPassword = Encoding.UTF8.GetBytes(
            saltValueFromDB + password); 

          // Hash the salted password using SHA256 
          SHA256Managed hashstring = new SHA256Managed(); 
          byte[] hash = hashstring.ComputeHash(saltedPassword); 

          string hashToCompare = Convert.ToBase64String(hash); 

          if (hashValueFromDB.Equals(hashToCompare)) 
            Console.WriteLine("User Validated.");             
          else 
            Console.WriteLine("Login credentials incorrect. User not 
              validated.");             
        }

```

1.  要测试代码，请在`CodeSamples`项目中添加对`Chapter15`类的引用。

1.  因为我们创建了一个静态类，您可以将新的`using static`添加到您的`Program.cs`文件中：

```cs
        using static Chapter15.Recipes;

```

1.  通过调用`RegisterUser()`方法并传递`username`和`password`变量来测试代码。之后，调用`ValidateLogin()`方法并查看密码是否与哈希值匹配。这在真实的生产系统中显然不会同时发生：

```cs
        string username = "dirk.strauss"; 
        string password = "^tj_Y4$g1!8LkD"; 
        RegisterUser(password, username); 

        ValidateLogin(password, username); 
        Console.ReadLine();

```

1.  当您调试代码时，您将看到用户已被验证：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_007.png)

1.  最后，稍微修改代码，并将`password`变量设置为其他内容。这将模仿用户输入错误的密码：

```cs
        string username = "dirk.strauss"; 
        string password = "^tj_Y4$g1!8LkD"; 
        RegisterUser(password, username); 

        password = "WrongPassword"; 
        ValidateLogin(password, username); 
        Console.ReadLine();

```

1.  当您调试应用程序时，您会发现用户未经过验证：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_008.png)

# 它是如何工作的...

在代码中我们从未解密密码。事实上，密码从未存储在任何地方。我们总是使用密码的哈希值。以下是从这个示例中得出的重要要点：

+   永远不要使用`Random`类来生成您的盐。始终使用`RNGCryptoServiceProvider`类。

+   永远不要在代码中重复使用相同的盐。因此，不要创建一个包含您的盐的常量，并将其用于为系统中的所有密码加盐。

+   如果密码不匹配，永远不要告诉用户密码不正确。同样，永远不要告诉用户他们输入了错误的用户名。这可以防止发现其中一个登录凭据正确后，有人试图破坏系统。相反，如果用户名或密码输入不正确，请通知用户他们的登录凭据不正确。这可能意味着用户名或密码（或两者）输入不正确。

+   您无法从数据库中存储的哈希或盐中获取密码。因此，如果数据库遭到破坏，其中存储的密码数据不会受到威胁。用户密码的加密是一个单向操作，意味着它永远无法被解密。同样重要的是，即使源代码被人恶意窃取，您也无法使用该代码来解密数据库中的加密数据。

+   将上述方法与强密码策略结合起来（因为即使在 2016 年，仍然有用户认为使用`'l3tm31n'`作为密码就足够了），您将得到一个非常好的密码加密例程。

当我们查看用户访问表时，存储用户凭据的正确方式应该是这样的：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_009.png)

盐和哈希存储在用户名旁边，并且是安全的，因为它们无法被解密以暴露实际密码。

如果您在互联网上注册服务，并且他们通过电子邮件或短信向您发送确认并以纯文本显示您的密码，那么您应该认真考虑关闭您的帐户。如果系统可以读取您的密码并以纯文本形式发送给您，其他人也可以。永远不要在所有登录中使用相同的密码。

# 在代码中使用 SecureString

保护应用程序免受恶意攻击并不是一件容易的事。这是在编写安全代码和最小化错误（黑客通常利用的）之间不断斗争，以及黑客编写越来越复杂的方法来破坏系统和网络。我个人认为高等学府需要教授 IT 学生两件事：

+   如何使用和集成流行的 ERP 系统

+   适当的软件安全原则

事实上，我认为安全编程 101 不应该只是给定 IT 课程中的一个模块或主题，而应该是一个完整的课程。它需要以应有的严肃和尊重对待，并且最好由一个真正可以黑客系统或网络的人来教授。

白帽黑客教授学生如何破坏系统，利用易受攻击的代码，并渗透网络，将对未来软件开发人员的编程方式产生重大影响。开发人员需要知道在进行防御性编程时不应该做什么。有可能其中一些学生最终会成为黑帽黑客，但无论他们是否参加了关于黑客安全编程的课程，他们都会这样做。

# 准备就绪

代码可能在某些地方看起来有点奇怪。这是因为`SecureString`正在使用非托管内存存储敏感信息。请放心，`SecureString`在.NET Framework 中得到了很好的支持和使用，可以从创建连接到数据库时使用的`SqlCredential`对象的实例化中看出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_010.png)

# 如何做...

1.  首先，向解决方案添加一个新的 Windows 表单项目。

1.  将项目命名为`winformSecure`并点击“确定”按钮。

1.  在工具箱中，搜索文本框控件并将其添加到您的表单中。

1.  最后，向您的表单添加一个按钮控件。您可以调整此表单的大小，使其看起来更像登录表单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_014.png)

1.  选择 Windows 表单上的文本框控件，在属性面板中打开并点击事件按钮（看起来像闪电）。在键组中，双击 KeyPress 事件以在代码后台创建处理程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_015.png)

为您创建的代码是文本框控件的 KeyPress 事件处理程序。每当用户在键盘上按键时，这将触发。

```cs
        private void textBox1_KeyPress(object sender,  KeyPressEventArgs e) 
        { 

        }

```

1.  回到属性面板，展开行为组，并将 UseSystemPasswordChar 的值更改为`True`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_016.png)

1.  在代码后台，添加以下`using`语句：

```cs
        using System.Runtime.InteropServices;

```

1.  将`SecureString`变量作为全局变量添加到您的 Windows 表单中：

```cs
        SecureString secure = new SecureString();

```

1.  然后，在`KeyPress`事件中，每次用户按键时将`KeyChar`值附加到`SecureString`变量中。您可能希望添加代码来忽略某些按键，但这超出了本教程的范围：

```cs
        private void textBox1_KeyPress(object sender,  KeyPressEventArgs e) 
        { 
          secure.AppendChar(e.KeyChar); 
        }

```

1.  然后，在登录按钮的事件处理程序中，添加以下代码以从`SecureString`对象中读取值。在这里，我们正在处理非托管内存和非托管代码：

```cs
        private void btnLogin_Click(object sender, EventArgs e) 
        { 
          IntPtr unmanagedPtr = IntPtr.Zero; 

          try 
          { 
            if (secure == null) 
            throw new ArgumentNullException("Password not defined");        
            unmanagedPtr = Marshal.SecureStringToGlobalAllocUnicode(
              secure);
            MessageBox.Show($"SecureString password to validate is 
                            {Marshal.PtrToStringUni(unmanagedPtr)}"); 
          } 
          catch(Exception ex) 
          { 
            MessageBox.Show(ex.Message); 
          } 
          finally 
          { 
            Marshal.ZeroFreeGlobalAllocUnicode(unmanagedPtr); 
            secure.Dispose(); 
          } 
        }

```

1.  运行您的 Windows 表单应用程序并输入密码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_017.png)

1.  然后点击登录按钮。然后您将看到您输入的密码显示在消息框中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_018.png)

# 它是如何工作的...

对许多开发人员来说，使用`System.String`存储密码等敏感信息几乎成了一种习惯。这种方法的问题在于`System.String`是不可变的。这意味着`System.String`在内存中创建的对象无法更改。如果修改变量，内存中将创建一个新对象。您也无法确定`System.String`创建的对象在垃圾回收期间何时从内存中删除。相反，使用`SecureString`对象，您将加密敏感信息，并在不再需要该对象时将其从内存中删除。`SecureString`在非托管内存中加密和解密您的敏感数据。

现在，我需要明确一件事。`SecureString`绝不是绝对安全的。如果您的系统中存在一个旨在破坏`SecureString`操作的病毒，使用它并没有太大帮助（无论如何，请务必使用适当的防病毒软件）。在代码执行过程中，您的密码（或敏感信息）的字符串表示可能是可见的。其次，如果黑客以某种方式找到了检查您的堆或记录您的按键的方法，密码可能是可见的。然而，使用`SecureString`可以使黑客的这个窗口机会变得更小。机会窗口变小是因为攻击向量（黑客的入口点）减少了，从而减少了攻击面（黑客的所有攻击点的总和）。

底线是：`SecureString`是有其存在的理由的。作为一个关心安全的软件开发人员，您应该使用`SecureString`。

# 保护 App.config/web.config 的敏感部分

作为开发人员，你无疑会处理诸如密码之类的敏感信息。在开发过程中如何处理这些信息非常重要。在过去，我曾收到客户的实时数据库副本用于测试。这确实对你的客户构成了非常真实的安全风险。

通常，我们会将设置保存在`web.config`文件中（在使用 Web 应用程序时）。但是，在这个例子中，我将演示一个使用`App.config`文件的控制台应用程序。相同的逻辑也可以应用于`web.config`文件。

# 准备工作

创建控制台应用程序是演示这个方法的最快方式。然而，如果你想使用 Web 应用程序（并保护`web.config`文件）进行跟随，你也可以这样做。

# 如何做...

1.  在控制台应用程序中，找到`App.config`文件。这个文件包含了敏感数据。

1.  如果你打开`App.config`文件，你会看到，在`appSettings`标签中，添加了一个名为`Secret`的键。这些信息可能本来就不应该在`App.config`中。问题在于它可能被提交到你的源代码控制中。想象一下在 GitHub 上？

```cs
        <?xml version="1.0" encoding="utf-8"?> 
        <configuration> 
          <startup>  
            <supportedRuntime version="v4.0" sku=".NETFramework,
             Version=v4.6.1"/> 
          </startup> 
          <appSettings> 
            <add key="name" value="Dirk"/> 
            <add key="lastname" value="Strauss"/>  
            <add key="Secret" value="letMeIn"/> 
          </appSettings> 
        </configuration>

```

1.  为了克服这个漏洞，我们需要将敏感数据从`App.config`文件中移出到另一个文件中。为此，我们指定一个包含我们想要从`App.config`文件中移除的敏感数据的文件路径。

```cs
        <appSettings file="C:\temp\secret\secret.config">:

```

你可能会想为什么不简单地加密这些信息。嗯，这是肯定的。这个值以明文形式存在的原因只是为了演示一个概念。在现实世界的情况下，你可能会加密这个值。然而，你不希望这些敏感信息以任何形式存在于服务器的代码库中，即使它被加密了。要保险起见，将其移出你的解决方案。

1.  当你添加了安全文件的路径后，删除包含敏感信息的键：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_020.png)

1.  导航到你在`App.config`文件属性中指定的路径。创建你的`secret.config`文件并打开它进行编辑：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_021.png)

1.  在这个文件中，重复`appSettings`部分并添加`Secret`键。现在发生的是，当你的控制台应用程序运行时，它会读取你解决方案中的`appSettings`部分，并找到对秘密文件的引用。然后它会寻找秘密文件，并将其与你解决方案中的`App.config`合并：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_022.png)

1.  为了看到这个合并是如何工作的，添加一个引用到你的控制台应用程序。

1.  搜索并添加`System.Configuration`到你的引用中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_024.png)

1.  当你添加了引用后，你的解决方案引用将列出 System.Configuration。

1.  在你的`Program.cs`文件顶部，添加以下`using`语句：

```cs
        using System.Configuration;

```

1.  添加以下代码来从你的`App.config`文件中读取`Secret`键设置。只是这一次，它将读取合并后的文件，由你的`App.config`和`secret.config`文件组成：

```cs
        string sSecret =  ConfigurationManager.AppSettings["Secret"]; 
        Console.WriteLine(sSecret); 
        Console.ReadLine();

```

1.  运行你的控制台应用程序，你会看到敏感数据已经从`secret.config`文件中读取，并在运行时与`App.config`文件合并：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_026.png)

# 它是如何工作的...

我需要在这里指出的是，这种技术也适用于`web.config`文件。如果你需要从配置文件中删除敏感信息，将其移动到另一个文件中，这样就不会被包含在你的源代码控制检入或部署中。

# 防止 SQL 注入攻击

SQL 注入攻击是一个非常真实的问题。有太多的应用程序仍然使自己容易受到这种攻击。如果你开发 Web 应用程序或网站，你应该对不良的数据库操作保持警惕。易受攻击的内联 SQL 会使数据库容易受到 SQL 注入攻击。SQL 注入攻击是指攻击者通过 Web 表单输入框修改 SQL 语句，以产生与最初意图不同的结果。这通常是在 Web 应用程序应该访问数据库以验证用户登录的表单上尝试的。通过不对用户输入进行消毒，你会使你的数据容易受到这种攻击的利用。

减轻 SQL 注入攻击的可接受解决方案是创建一个带参数的存储过程，并从代码中调用它。

# 准备工作

在继续本示例之前，你需要在你的 SQL Server 中创建`CookbookDB`数据库。你可以在附带源代码的`_database scripts`文件夹中找到脚本。

# 如何做...

1.  在这个示例中，我使用的是 SQL Server 2012。如果你使用的是较旧版本的 SQL Server，概念是一样的。在创建了`CookbookDB`数据库之后，你会看到`Tables`文件夹下有一个名为`UserDisplayData`的表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_027.png)

1.  `UserDisplayData`表只是用来说明使用带参数的存储过程进行查询的概念。在生产数据库中，它不会有任何真正的好处，因为它只返回一个屏幕名称：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_028.png)

1.  我们需要创建一个存储过程来选择这个表中特定 ID（用户 ID）的数据。点击`Programmability`节点以展开它：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_029.png)

1.  接下来，右键单击`Stored Procedures`节点，从上下文菜单中选择`New Stored Procedure...`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_030.png)

1.  SQL Server 会为你创建以下存储过程模板。这个模板包括一个你可以对特定存储过程进行注释的部分，以及一个你可能需要添加参数的部分，显然还有一个你需要添加实际 SQL 语句的部分：

```cs
        SET ANSI_NULLS ON 
        GO 
        SET QUOTED_IDENTIFIER ON 
        GO 
        -- ============================================= 
        -- Author:          <Author,,Name> 
        -- Create date:      <Create Date,,> 
        -- Description:      <Description,,> 
        -- ============================================= 
        CREATE PROCEDURE <Procedure_Name, sysname, ProcedureName>  
            -- Add the parameters for the stored procedure here 
            <@Param1, sysname, @p1> <Datatype_For_Param1, , int> =                  <Default_Value_For_Param1, , 0>,  
            <@Param2, sysname, @p2> <Datatype_For_Param2, , int> =              <Default_Value_For_Param2, , 0> 
        AS 
        BEGIN 
        -- SET NOCOUNT ON added to prevent extra result sets      from 
        -- interfering with SELECT statements. 
        SET NOCOUNT ON; 

        -- Insert statements for procedure here 
        SELECT <@Param1, sysname, @p1>, <@Param2, sysname, @p2> 
        END 
        GO

```

1.  给存储过程取一个合适的名字，描述存储过程的动作或意图：

```cs
        CREATE PROCEDURE cb_ReadCurrentUserDisplayData

```

有很多人在他们的存储过程中加入前缀，我就是其中之一。我喜欢把我的存储过程分组。因此，我以*[prefix]_[tablename_or_module]_[stored_procedure_action]*的格式命名我的存储过程。话虽如此，我通常避免使用`sp_`作为存储过程的前缀。关于为什么这样做是一个坏主意，互联网上有很多不同的观点。一般认为，在性能方面，使用`sp_`作为存储过程前缀会有影响，因为它被用作主数据库中的存储过程前缀。对于这个示例，我只是简单地给存储过程取了一个简单的名字。

1.  为这个存储过程定义一个参数。通过这样做，你告诉数据库，当调用这个存储过程时，它将传递一个整数类型的值，存储在一个名为`@userID`的参数中：

```cs
        @userID INT

```

1.  现在定义要由该存储过程使用的 SQL 语句。我们将只执行一个简单的`SELECT`语句：

```cs
        SELECT 
          Firstname, Lastname, Displayname 
        FROM 
          dbo.UserDisplayData 
        WHERE 
          ID = @userID

```

您会注意到我的`SELECT`语句包含特定的列名，而不是`SELECT * FROM`。使用`SELECT *`被认为是不良实践。通常情况下，您不希望从表中返回所有列值。如果您需要所有列值，最好明确列出列名，而不是获取所有列。使用`SELECT *`会返回不必要的列，并增加服务器的开销。这在更大的事情中确实会有所不同，特别是当数据库开始有很多流量时。不得不为大表的列名输入而感到期待是绝对不会发生的事情。但是，您可以使用以下技巧来使您轻松地将列名添加到您的 SQL `SELECT`语句中。您可以右键单击数据库表，然后选择`Script Table As`来创建多个 SQL 语句之一。其次，您可以展开`Table`节点并展开要为其编写语句的表。然后，您将看到一个名为`Columns`的节点。将`Columns`节点拖放到查询编辑器中。这将为您在查询编辑器中插入所有列名。

1.  当您完成向存储过程添加代码后，它将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_031.png)

1.  要创建存储过程，您需要单击“执行”按钮。确保在单击“执行”按钮时选择了正确的数据库：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_15_18.jpg)

1.  然后存储过程将在 SQL Server 的`Stored Procedures`节点下创建：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_033.png)

1.  我们现在已经完成了这项任务的一半。是时候构建我们将在应用程序中使用来查询数据库的代码了。我们将直接将此代码添加到控制台应用程序的`Program.cs`文件中。虽然这段代码不被认为是最佳实践（硬编码服务器凭据），但它仅仅用来说明从 C#调用参数化存储过程的概念。

1.  首先，在您的控制台应用程序顶部添加以下`using`语句：

```cs
        using System.Data.SqlClient;

```

1.  然后添加变量以包含我们登录服务器所需的凭据：

```cs
        int intUserID = 1; 
        int cmdTimeout = 15; 
        string server = "DIRK"; 
        string db = "CookbookDB"; 
        string uid = "dirk"; 
        string password = "uR^GP2ABG19@!R";

```

1.  我们现在使用`SecureString`来存储密码，并将其添加到`SqlCredential`对象中：

```cs
        SecureString secpw = new SecureString(); 
        if (password.Length > 0) 
        { 
          foreach (var c in password.ToCharArray()) secpw.AppendChar(c); 
        } 
        secpw.MakeReadOnly(); 

        string dbConn = $"Data Source={server};Initial Catalog={db};"; 
        SqlCredential cred = new SqlCredential(uid, secpw);

```

有关`SecureString`的更多信息，请参阅本章的*在代码中使用 SecureString*配方。

1.  我们现在在`using`语句中创建一个`SqlConnection`对象。这确保了当`using`语句移出范围时，SQL 连接将被关闭：

```cs
        using (SqlConnection conn = new SqlConnection(dbConn,  cred)) 
        {                 
          try 
          { 

          } 
          catch (Exception ex) 
          { 
            Console.WriteLine(ex.Message); 
          } 
        } 
        Console.ReadLine();

```

1.  在`try`内，添加以下代码以打开连接字符串并创建一个`SqlCommand`对象，该对象将打开的连接和存储过程的名称作为参数。您可以使用创建实际 SQL 参数的快捷方法来传递给存储过程：

```cs
        cmd.Parameters.Add("userID", SqlDbType.Int).Value = intUserID;

```

因为我只是向存储过程传递了一个整数类型的参数，所以我没有为这个参数定义长度：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_034.png)

然而，如果您需要定义`VarChar(MAX)`类型的参数，您需要通过添加`-1`来定义参数类型的大小。例如，假设您需要在数据库中存储学生的文章；则代码将如下所示：

```cs
        cmd.Parameters.Add("essay", SqlDbType.VarChar, -1).Value = 
          essayValue;

```

1.  在将参数及其值添加到`SqlCommand`对象后，我们指定超时值，执行`SqlDataReader`并将其加载到`DataTable`中。然后将该值输出到控制台应用程序：

```cs
        conn.Open(); 
        SqlCommand cmd = new SqlCommand("cb_ReadCurrentUserDisplayData", 
          conn); 
        cmd.CommandType = CommandType.StoredProcedure; 
        cmd.Parameters.Add("userID", SqlDbType.Int).Value = intUserID; 
        cmd.CommandTimeout = cmdTimeout; 
        var returnData = cmd.ExecuteReader(); 
        var dtData = new DataTable(); 
        dtData.Load(returnData); 

        if (dtData.Rows.Count != 0) 
          Console.WriteLine(dtData.Rows[0]["Displayname"]);

```

1.  在将所有代码添加到控制台应用程序后，正确的完成代码将如下所示：

```cs
        int intUserID = 1; 
        int cmdTimeout = 15; 
        string server = "DIRK"; 
        string db = "CookbookDB"; 
        string uid = "dirk"; 
        string password = "uR^GP2ABG19@!R"; 
        SecureString secpw = new SecureString(); 
        if (password.Length > 0) 
        { 
          foreach (var c in password.ToCharArray())
            secpw.AppendChar(c); 
        } 
        secpw.MakeReadOnly(); 

        string dbConn = $"Data Source={server};Initial Catalog={db};"; 

        SqlCredential cred = new SqlCredential(uid, secpw); 
        using (SqlConnection conn = new SqlConnection(dbConn, cred)) 
        {                 
          try 
          { 
            conn.Open(); 
            SqlCommand cmd = new SqlCommand(
              "cb_ReadCurrentUserDisplayData", conn); 
            cmd.CommandType = CommandType.StoredProcedure; 
            cmd.Parameters.Add("userID", SqlDbType.Int).Value = intUserID; 
            cmd.CommandTimeout = cmdTimeout; 
            var returnData = cmd.ExecuteReader(); 
            var dtData = new DataTable(); 
            dtData.Load(returnData); 
            if (dtData.Rows.Count != 0) 
              Console.WriteLine(dtData.Rows[0]["Displayname"]);  
          } 
          catch (Exception ex) 
          { 
            Console.WriteLine(ex.Message); 
          } 
        } 
        Console.ReadLine();

```

1.  运行您的控制台应用程序，您将看到显示名称输出到屏幕上：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_035.png)

# 它是如何工作的...

通过创建参数化的 SQL 查询，编译器在运行 SQL 语句之前正确地替换参数。这将防止恶意数据改变您的 SQL 语句以获得恶意结果。这是因为`SqlCommand`对象不会直接将参数值插入语句中。

总之，使用参数化存储过程意味着不再有“小鲍比表”。

# 使用 IntelliTrace、诊断工具和历史调试

老式的臭虫已经成为软件开发人员和工程师 140 多年来的祸根。是的，你没看错。事实上，正是托马斯·爱迪生在 19 世纪 70 年代末创造了“臭虫”这个词。它出现在他的许多笔记中，例如他描述白炽灯仍然有许多“臭虫”的笔记中。

他为调试自己的发明所付出的努力是相当传奇的。考虑到一个已经年过六旬的人每周工作 112 小时的真正勇气和决心。他和他的七人团队（人们普遍错误地认为只有六个人，因为第七个成员没有出现在团队照片中）在为期 5 周的工作中几乎没有睡眠，因此被称为失眠小队。

如今，由于技术的进步，软件开发人员在使用调试工具（包括 Visual Studio 内外）时有着广泛的选择。那么，调试真的很重要吗？当然很重要。这是我们作为软件开发人员所做的一部分。如果我们不调试，嗯，这里有一些例子：

+   2004 年，英国的**电子数据系统**（**EDS**）子支持系统向近 200 万人过度支付，同时向近 100 万人支付不足，并导致数十亿美元的未收取子支持费。EDS 与其依赖的另一个系统之间的不兼容性导致纳税人损失，并对许多单身父母的生活产生负面影响。

+   2012 年发布的苹果地图就足够说明问题了。虽然对许多人来说令人困惑，但当我在陌生的城市或地区时，我仍然发现自己使用谷歌地图进行导航。

+   Therac-25 放射治疗机使用电子来瞄准患者的肿瘤。不幸的是，软件中的竞争条件导致该机器向几名患者输送致命的过量辐射。

在互联网上可以找到许多影响数百万人生活的软件错误的例子。我们不仅仅谈论一般的错误。有时，我们面临看似不可逾越的问题。知道如何使用一些可用的工具是稳定应用程序和完全无法使用的应用程序之间的区别。

# 准备工作

请注意，IntelliTrace 仅在 Visual Studio 的企业版中可用。请参阅[`www.visualstudio.com/vs/compare/`](https://www.visualstudio.com/vs/compare/)链接，了解 Visual Studio 各个版本之间的比较。IntelliTrace 并不是 Visual Studio 中的新功能。它已经随着时间的推移（自 Visual Studio 2010 以来）发展成为我们今天所拥有的功能。

# 如何做到...

1.  首先，转到“工具”，“选项”。

1.  展开 IntelliTrace 节点，单击“常规”。确保已选中“启用 IntelliTrace”。还要确保选择了 IntelliTrace 事件和调用信息选项。单击“确定”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_037.png)

1.  在`Recipes.cs`文件中，您可能需要添加以下`using`语句：

```cs
        using System.Diagnostics; 
        using System.Reflection; 
        using System.IO;

```

1.  在`Recipes`类中添加一个名为`ErrorInception()`的方法。还要添加代码来读取基本路径，并假设有一个名为`log`的文件夹。不要在硬盘上创建这个文件夹。我们希望抛出一个异常。最后，添加另一个名为`LogException()`的方法，什么也不做：

```cs
        public static void ErrorInception() 
        { 
          string basepath = Path.GetDirectoryName(
            Assembly.GetEntryAssembly().Location); 
          var full = Path.Combine(basepath, "log"); 
        } 

        private static void LogException(string message) 
        { 

        }

```

1.  在确定完整路径后，将以下代码添加到您的`ErrorInception()`方法中。在这里，我们尝试打开日志文件。这就是异常将发生的地方：

```cs
        try 
        { 
          for (int i = 0; i <= 3; i++) 
          { 
            // do work 
            File.Open($"{full}log.txt", FileMode.Append); 
          } 
        } 
        catch (Exception ex) 
        { 
          StackTrace st = new StackTrace(); 
          StackFrame sf = st.GetFrame(0); 
          MethodBase currentMethodName = sf.GetMethod(); 
          ex.Data.Add("Date", DateTime.Now); 
          LogException(ex.Message); 
        }

```

1.  当您添加了所有代码后，您的代码应该看起来像这样：

```cs
        public static void ErrorInception() 
        { 
          string basepath = Path.GetDirectoryName(
            Assembly.GetEntryAssembly().Location); 
          var full = Path.Combine(basepath, "log"); 

          try 
          { 
            for (int i = 0; i <= 3; i++) 
            { 
              // do work 
              File.Open($"{full}log.txt", FileMode.Append); 
            } 
          } 
          catch (Exception ex) 
          { 
            StackTrace st = new StackTrace(); 
            StackFrame sf = st.GetFrame(0); 
            MethodBase currentMethodName = sf.GetMethod(); 
            ex.Data.Add("Date", DateTime.Now); 
            LogException(ex.Message); 
          } 
        } 

        private static void LogException(string message) 
        { 

        }

```

1.  在`Program.cs`文件中，调用`ErrorInception()`方法。在那之后，进行`Console.ReadLine()`，这样我们的控制台应用程序将在那里暂停。不要在代码的任何地方添加断点：

```cs
        ErrorInception(); 
        Console.ReadLine();

```

1.  开始调试您的应用程序。异常被抛出，应用程序继续运行，这在更复杂的应用程序中经常发生。在这一点上，您期望日志文件被附加上应用程序的虚构数据，但什么也没有发生。就在这时，您停止应用程序，并开始在代码中随意添加断点。我说随意，因为您可能不知道错误的确切位置。如果您的代码文件包含几千行代码，这一点尤其正确。现在有了 IntelliTrace 和历史调试，您只需点击“全部中断”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_038.png)

1.  您的应用程序现在基本上暂停了。如果您没有看到诊断工具窗口，请按住*Ctrl* + *Alt* + *F2*。

1.  Visual Studio 现在显示诊断工具窗口。立即，您可以看到在事件部分的红色菱形图标指示了问题。在底部的事件选项卡中，您可以点击异常：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_040.png)

1.  这样做会扩展异常详细信息，您可以看到日志文件未找到。然而，Visual Studio 通过历史调试更进一步：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_041.png)

1.  您将在异常详细信息底部看到一个名为“激活历史调试”的链接。点击此链接。这允许您在代码编辑器中看到导致此异常的实际代码行。它还允许您查看本地窗口、调用堆栈和其他窗口中应用程序状态的历史记录。现在您可以在代码编辑器中看到导致异常的具体代码行。在本地窗口中，您还可以看到应用程序用于查找日志文件的路径。这种调试体验非常强大，可以让开发人员直接找到错误的源头。这将提高生产力并改善代码：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_042.png)

# 它是如何工作的...

那么这里的要点是什么？如果您只记住一件事，请记住这一点。一旦您的系统的用户因为错误而失去了对该系统能力和潜力的信心，那种信心几乎不可能重新获得。即使您从错误和其他问题中复活了您的系统，制作出了一个无瑕疵的产品，您的用户也不会轻易改变主意。这是因为在他们的心目中，系统是有错误的。

我曾经接手过一部分由一位即将离开公司的资深开发人员开发的系统。她有一个出色的规格说明和一个向客户展示的精美原型。唯一的问题是，她在系统的第一阶段实施后不久就离开了公司。当出现错误时，客户自然会要求她的帮助。

告诉客户，负责与客户建立关系的开发人员已经离开公司，并不能增强信心。在这个特定项目中，只有一个开发人员参与是第一个错误。

其次，第二阶段即将由我来开发，我也是唯一被分配给这个客户的开发人员。这必须在修复第一阶段的错误的同时完成。所以，我在开发系统的新功能的同时修复错误。幸运的是，这一次我有一个名叫罗里·谢尔顿的出色项目经理作为我的搭档。我们一起被抛入深渊，罗里在管理客户期望方面做得非常出色，同时对客户完全透明地表明我们面临的挑战。

不幸的是，用户已经对提供的系统感到幻灭，并不信任这个软件。这种信任从未完全恢复。如果我们在 2007 年就有 IntelliTrace 和历史调试，我肯定能够追踪到对我来说陌生的代码库中的问题。

始终调试你的软件。当你找不到更多的错误时，再次调试。然后把系统交给我妈妈（爱你妈妈）。作为系统的开发者，你知道应该点击哪些按钮，输入哪些数据，以及事情需要以什么顺序发生。我妈妈不知道，我可以向你保证，一个对系统不熟悉的用户比你煮一杯新鲜咖啡还要快地破坏它。

Visual Studio 为开发人员提供了非常强大和功能丰富的调试工具。好好利用它们。

# 设置条件断点

条件断点是调试时的另一个隐藏宝石。这允许你指定一个或多个条件。当满足其中一个条件时，代码将在断点处停止。使用条件断点非常简单。

# 准备工作

你不需要特别准备任何东西来使用这个方法。

# 如何做...

1.  在你的`Program.cs`文件中添加以下代码。我们只是创建了一个整数列表并循环遍历该列表：

```cs
        List<int> myList = new List<int>() { 1, 4, 6, 9, 11 }; 
        foreach(int num in myList) 
        { 
          Console.WriteLine(num); 
        } 
        Console.ReadLine();

```

1.  接下来，在循环内的`Console.WriteLine(num)`代码上设置一个断点：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_043.png)

1.  右键单击断点，然后从上下文菜单中选择条件...：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_044.png)

1.  现在你会看到 Visual Studio 打开了一个断点设置窗口。在这里，我们指定断点只有在`num`的值为`9`时才会被触发。你可以添加多个条件并指定不同的条件。条件逻辑非常灵活：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_045.png)

1.  调试你的控制台应用程序。你会看到当断点被触发时，`num`的值是`9`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_046.png)

# 它的工作原理...

条件在每次循环中都会被评估。当条件为真时，断点将被触发。在这个示例中，条件断点的真正好处有点失去了，因为这是一个非常小的列表。不过请考虑一下。你正在绑定一个数据网格。网格上的项目根据项目的状态给定特定的图标。你的网格包含数百个项目，因为这是一个分层网格。你确定了绑定到网格的项目的主要 ID。然后将此主要 ID 传递给其他代码逻辑来确定状态，从而确定显示的图标。

通过数百个循环按下*F10*进行调试并不高效。使用条件断点，你可以指定主要 ID 的值，并且只有在循环达到该值时才会中断。然后你可以直接找到显示不正确的项目。

# 使用 PerfTips 来识别代码中的瓶颈

PerfTips 绝对是我最喜欢的 Visual Studio 功能之一。解释它们的作用并不能充分展现它们的价值。你必须亲眼看到它们的效果。

# 准备工作

不要将 PerfTips 与 CodeLens 混淆。它是 Visual Studio 中与 CodeLens 分开的一个选项。

# 如何做...

1.  PerfTips 默认是启用的。但是以防你没有看到任何 PerfTips，转到工具 | 选项，并展开调试节点。在常规下，到设置页面的底部，你会看到一个名为在调试时显示经过时间 PerfTip 的选项。确保选中此选项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_047.png)

1.  我们将创建一些模拟长时间运行任务的简单方法。为此，我们将让线程休眠几秒钟。在`Recipes.cs`文件中添加以下代码：

```cs
        public static void RunFastTask() 
        { 
          RunLongerTask(); 
        } 

        private static void RunLongerTask() 
        { 
          Thread.Sleep(3000); 
          BottleNeck(); 
        } 

        private static void BottleNeck() 
        { 
          Thread.Sleep(8000); 
        }

```

1.  在你的控制台应用程序中，调用静态方法`RunFastTask()`并在这行代码上设置一个断点：

```cs
        RunFastTask(); 
        Thread.Sleep(1000);

```

1.  开始调试你的控制台应用程序。你的断点将停在`RunFastTask()`方法上。按*F10*跳过这个方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_048.png)

1.  您会注意到 11 秒后，下一行将被突出显示，并显示 PerfTip。PerfTip 显示了上一行代码执行所花费的时间。因此，现在位于`Thread.Sleep`上的调试器显示`RunFastTask()`方法花费了 11 秒才完成。该任务显然并不是很快：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_049.png)

1.  进入`RunFastTask()`方法后，您可以设置更多断点，并逐个跳过它们，以找到导致最长延迟的方法。正如您所看到的，PerfTips 可以让开发人员快速轻松地识别代码中的瓶颈。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/image_15_050.png)

# 工作原理...

市场上有许多工具可以做到这一点，甚至更多，允许开发人员查看各种代码指标。然而，PerfTips 可以让您在正常调试任务中逐步查看代码时即时查看问题。在我看来，这是一个必不可少的调试工具。


# 第十五章：在 Azure Service Fabric 上创建微服务

本章涉及微服务和**Azure Service Fabric**的激动人心的世界。在本章中，我们将介绍以下内容：

+   下载和安装 Service Fabric

+   使用无状态 actor 服务创建 Service Fabric 应用程序

+   使用 Service Fabric Explorer

# 介绍

传统上，开发人员以单片方式编写应用程序。这意味着一个单一的可执行文件通过类等组件进行分解。单片应用程序需要大量的测试，由于单片应用程序的庞大，部署是繁琐的。即使您可能有多个开发团队，他们都需要对整个应用程序有扎实的了解。

微服务是一种旨在解决单片应用程序和传统应用程序开发方式所带来问题的技术。使用微服务，您可以将应用程序分解为可以独立运行的较小部分（服务），而不依赖于任何其他服务。这些较小的服务可以是无状态或有状态的，并且在功能规模上也更小，使它们更容易开发、测试和部署。您还可以独立对每个微服务进行版本控制。如果一个微服务的负载比其他微服务更大，您可以仅扩展该服务以满足其所承受的需求。对于单片应用程序，您必须尝试扩展整个应用程序以满足应用程序中的单个组件的需求。

例如，考虑一个流行的在线网络商店的运作方式。它可能包括购物车、购物者个人资料、订单管理、后端登录、库存管理、结算、退货等等。传统上，创建一个单一的 Web 应用程序来提供所有这些服务。使用微服务，您可以将每个服务隔离为独立的、自包含的功能和代码库。您还可以专门组建一个开发团队来处理网络商店的某一部分。如果这个团队负责库存管理微服务，他们将处理它的各个方面。例如，这意味着从编写代码和增强功能到测试和部署的所有工作。

微服务的另一个优点是，它可以轻松隔离您可能遇到的任何故障。最后，您还可以使用任何您想要的技术（C＃，Java 和 VB.NET）创建微服务，因为它们是与语言无关的。

Azure Service Fabric 允许您轻松扩展微服务，并增加应用程序的可用性，因为它实现了故障转移。当微服务与 Service Fabric 一起使用时，微服务变得非常强大。将 Azure Service Fabric 视为您的微服务所在的**平台即服务**（**PaaS**）解决方案。我们将微服务所在的集合称为 Service Fabric 集群。每个微服务都位于一个虚拟机上，这在 Service Fabric 集群中被称为节点。此 Service Fabric 集群可以存在于云中或本地机器上。如果由于任何原因节点不可用，Service Fabric 集群将自动将微服务重新分配到其他节点，以确保应用程序保持可用。

最后，关于有状态和无状态微服务之间的区别。您可以将微服务创建为无状态或有状态。当微服务依赖外部数据存储来持久化数据时，它具有无状态性质。这意味着微服务不会在内部维护其状态。另一方面，有状态微服务通过在其所在的服务器上本地存储来维护自己的状态。可以想象，有状态微服务非常适合金融交易。如果某个节点因某种原因关闭，当故障转移发生时，该交易的状态将被持久化，并在新节点上继续进行。

# 下载和安装 Service Fabric

在创建和测试 Service Fabric 应用程序之前，您需要在 PC 上安装和设置本地 Service Fabric 集群。本地 Service Fabric 集群是一个完全功能的集群，就像在实际环境中一样。

# 准备就绪

我们将从 Azure 网站下载并安装**Microsoft Azure Service Fabric SDK**。这将允许您在本地开发机器上创建本地 Service Fabric 集群。有关更多信息，请参阅[`docs.microsoft.com/en-us/azure/service-fabric/service-fabric-get-started`](https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-get-started)。

Service Fabric 工具现在是 Visual Studio 2017 中 Azure 开发和管理工作负载的一部分。在安装 Visual Studio 2017 时启用此工作负载。您还需要启用 ASP.NET 和 Web 开发工作负载：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_01.png)

请注意，如果您不再拥有 Visual Studio 的原始安装程序，并且在安装过程中没有启用 Azure 开发和管理工作负载，您仍然可以启用它。下载您拥有的 Visual Studio 2017 版本的 Web 平台安装程序并单击它。这将启动安装程序，但将允许您修改现有的 Visual Studio 2017 安装。您还可以从 Visual Studio 2017 的“新项目”对话框屏幕中运行安装程序。如果您折叠已安装的模板，您将看到一个允许您打开 Visual Studio 安装程序的部分。

除此之外，您还可以使用上述链接中的 Web 平台安装程序安装 Microsoft Azure Service Fabric SDK。它将读取安装 Microsoft Azure Service Fabric SDK。为了获得最佳的安装体验，建议使用 Internet Explorer 或 Edge 浏览器启动 Web 平台安装程序。

# 如何操作...

1.  从 Microsoft Azure 网站下载 Microsoft Azure Service Fabric SDK，并通过 Service Fabric 学习路径访问其他资源，例如文档，从[`azure.microsoft.com/en-us/documentation/learning-paths/service-fabric/`](https://azure.microsoft.com/en-us/documentation/learning-paths/service-fabric/)。单击 WPI 启动程序后，您应该看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_02.png)

1.  在安装开始之前，您需要接受许可条款。

1.  然后，Web 平台安装程序开始下载 Microsoft Azure Service Fabric Runtime。允许此过程完成。

1.  下载完成后，安装过程将开始：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_03.png)

1.  安装完成后，将安装以下产品，这也可以从以下屏幕截图中看出：

+   Microsoft Visual C++ 2012 SP1 可再发行包

+   Microsoft Azure Service Fabric Runtime

+   Microsoft Azure Service Fabric SDK

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_04.png)

您的安装可能与屏幕截图不同，具体取决于您特定的预安装组件。

1.  下一个任务是以管理员身份打开 PowerShell。在 Windows 10 开始菜单中，键入单词 `PowerShell`，搜索将立即返回桌面应用程序作为结果。右键单击桌面应用程序，然后从上下文菜单中选择以管理员身份运行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_05.png)

1.  一旦 Windows PowerShell 打开，运行 `Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Scope CurrentUser` 命令。原因是 Service Fabric 使用 PowerShell 脚本来创建本地开发集群。它也用于部署 Visual Studio 开发的应用程序。运行此命令可以防止 Windows 阻止这些脚本：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_06.png)

1.  接下来，创建本地 Service Fabric 集群。输入 `& "$ENV:ProgramFiles\Microsoft SDKs\Service Fabric\ClusterSetup\DevClusterSetup.ps1"` 命令。

这将创建所需的本地集群来托管 Service Fabric 应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_07.png)

B06434_17_07

1.  集群创建后，PowerShell 将启动服务：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_08.png)

1.  该过程可能需要几分钟。请确保让它完成：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_09.png)

1.  一旦命名服务准备就绪，您可以关闭 PowerShell：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_10.png)

1.  要查看创建的集群，可以在本地机器上导航到 `http://localhost:19080/Explorer`。

这将为您提供集群的健康和状态的快照。它还将显示集群中运行的任何应用程序：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_11.png)

# 工作原理...

正如您所看到的，Service Fabric 集群对于在 Visual Studio 中创建和运行应用程序至关重要。这将允许我们在将应用程序发布到云之前直接在本地机器上测试应用程序。正如前面提到的，这不是 Service Fabric 集群的简化版本。它与您在其中安装 Service Fabric 应用程序的任何一台机器上安装的版本完全相同。

# 使用无状态 Actor 服务创建 Service Fabric 应用程序

作为本章介绍的一部分，我们看了有状态和无状态微服务之间的区别。然后，可用的 Service Fabric 应用程序模板进一步分为**可靠服务**（有状态/无状态）和**可靠 Actor**。何时使用哪一个将取决于您的应用程序的具体业务需求。

简单来说，如果您想创建一个应该向您的应用程序的许多用户公开的服务，可靠的服务可能是一个很好的选择。想象一下，一个服务公开了最新的汇率，可以被许多用户或应用程序同时使用。

再次回顾本章的介绍，我们使用了在线网店和购物车的例子。对于每个购买商品的客户，可靠 Actor 可能是一个很好的选择，因此您可以有一个购物车 Actor。Service Fabric 框架中的可靠 Actor 基于虚拟 Actor 模式。请查看 [`research.microsoft.com/en-us/projects/orleans/`](http://research.microsoft.com/en-us/projects/orleans/) 上关于虚拟 Actor 模式的文章。

为了向您展示使用无状态 Actor 服务创建微服务有多容易，我们将使用 Visual Studio 将服务发布到 Service Fabric 集群，并从控制台（客户端）应用程序调用该服务作为示例。

# 做好准备

要完成此步骤，您必须确保已在本地机器上安装了 Service Fabric 集群。您还需要确保已安装了 Visual Studio 2017 中的 Azure 开发和管理工作负载。在安装 Visual Studio 2017 时启用此工作负载。如果您没有在 Visual Studio 2017 的安装中安装该工作负载，可以通过单击 Visual Studio 2017 的 Web 平台安装程序并维护安装来执行此操作。

# 如何做...

1.  在 Visual Studio 中，通过转到“文件”|“新建”|“项目”来创建一个新项目。

1.  从 Visual C#节点展开节点，直到看到 Cloud 节点。当您点击它时，您会看到 Visual Studio 现在列出了一个新的 Service Fabric 应用程序模板。选择 Service Fabric 应用程序模板，将其命名为`sfApp`，然后单击“确定”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_12.png)

1.  接下来，从弹出的服务模板窗口中选择 Actor Service。我们只是称之为`UtilitiesActor`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_13-2.png)

1.  创建解决方案后，您会注意到它由三个项目组成：

+   `sfApp`

+   `UtilitiesActor`

+   `UtilitiesActor.Interfaces`

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_14.png)

1.  我们将首先修改`UtilitiesActor.Interfaces`项目中的`IUtilitiesActor`接口。该接口将简单要求`UtilitiesActor`实现一个名为`ValidateEmailAsync`的方法，该方法以电子邮件地址作为参数，并返回一个布尔值，指示它是否是有效的电子邮件地址：

```cs
        namespace UtilitiesActor.Interfaces 
        { 
          public interface IUtilitiesActor : IActor 
          { 
            Task<bool> ValidateEmailAsync(string emailToValidate); 
          } 
        }

```

1.  接下来，打开您的`UtilitiesActor`项目，并查看`UtilitiesActor.cs`类。查找大约在第 22 行左右的内部类定义`internal class UtilitiesActor：Actor，IUtilitiesActor`。`IUtilitiesActor`接口名称将被下划线标记，因为它没有实现接口成员`ValidateEmailAsync()`。

1.  使用*Ctrl* + *.*（句号），实现接口。删除所有其他不必要的默认代码（如果有）。

1.  为您插入的实现接口代码应如下所示。目前，它只包含`NotImplementedException`。我们将在这里实现验证电子邮件地址的代码：

```cs
        namespace UtilitiesActor 
        { 
          internal class UtilitiesActor : StatelessActor, IUtilitiesActor 
          { 
            public UtilitiesActor(ActorService actorService, 
              ActorId actorId) : base(actorService, actorId)
            {
            }
            public async Task<bool> ValidateEmailAsync(string 
              emailToValidate) 
            { 
              throw new NotImplementedException(); 
            }         
          } 
        }

```

1.  我们将使用正则表达式来验证通过参数传递给此方法的电子邮件地址。正则表达式非常强大。然而，在我多年的编程生涯中，我从未编写过自己的表达式。这些可以在互联网上轻松找到，并且您可以为自己的项目创建一个实用程序类（或扩展方法类）以重用。您可以利用经常使用的正则表达式和其他代码。

最后，您会注意到`ActorEventSource`代码。这只是为了创建**Windows 事件跟踪**（**ETW**）事件，以帮助您从 Visual Studio 的诊断事件窗口中查看应用程序中发生的情况。要打开诊断事件窗口，请转到“视图”，选择“其他窗口”，然后单击“诊断事件”：

```cs
        public async Task<bool> ValidateEmailAsync(string emailToValidate)
        {
          ActorEventSource.Current.ActorMessage(this, "Email Validation");
          return await Task.FromResult(Regex.IsMatch(emailToValidate, 
          @"A(?:[a-z0-9!#$%&'*+/=?^_&grave;{|}~-]+(?:.[
          a-z0-9!#$%&'*+/=?^_&grave;{|}~-]+) *@(?:a-z0-9?.)+a-z0-9?)
          Z", RegexOptions.IgnoreCase));
        }

```

1.  确保添加对`System.Text.RegularExpressions`命名空间的引用。如果没有引用，您将无法使用正则表达式。如果在代码中添加了正则表达式而没有添加引用，Visual Studio 将在`Regex`方法下显示红色波浪线。

1.  使用*Ctrl* + *.*（句号），将`using`语句添加到您的项目。这将使正则表达式命名空间生效。

1.  现在我们已经创建了接口，并添加了该接口的实现，现在是时候添加一个客户端应用程序进行测试了。右键单击解决方案，然后添加一个新项目。

1.  最简单的方法是添加一个简单的控制台应用程序。将您的客户端应用程序命名为`sfApp.Client`，然后单击“确定”按钮。

1.  将控制台应用程序添加到解决方案后，您的解决方案应如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_15.png)

1.  现在，您需要向客户端应用程序添加引用。右键单击`sfApp.Client`项目中的`References`节点，然后从上下文菜单中选择添加引用。

1.  首先要做的是向`UtilitiesActor.Interfaces`项目添加引用。

1.  您还需要添加对几个 Service Fabric **动态链接库**（**DLLs**）的引用。当您创建 Service Fabric 应用程序时，它应该已经在项目文件夹结构中添加了一个名为`packages`的文件夹。浏览到此文件夹，并从中添加所需的 Service Fabric DLL。添加所需的 DLL 后，您的项目应如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_16.png)

1.  在您的控制台应用程序的`Program.cs`文件中，您需要将以下代码添加到`Main`方法中：

```cs
        namespace sfApp.Client 
        { 
          class Program 
          { 
            static void Main(string[] args)
            {
              var actProxy = ActorProxy.Create<IUtilitiesActor>
                (ActorId.CreateRandom(), "fabric:/sfApp");
              WriteLine("Utilities Actor {0} - Valid Email?:{1}", 
              actProxy.GetActorId(), actProxy.ValidateEmailAsync(
              "validemail@gmail.com").Result);
              WriteLine("Utilities Actor {0} - Valid Email?:{1}", 
              actProxy.GetActorId(), actProxy.ValidateEmailAsync(
              "invalid@email@gmail.com").Result);
              ReadLine();
            } 
          }   
        }

```

确保将以下`using`语句添加到您的控制台应用程序中：

```cs
        using Microsoft.ServiceFabric.Actors;
        using Microsoft.ServiceFabric.Actors.Client;
        using UtilitiesActor.Interfaces;
        using static System.Console;

```

我们所做的就是为我们的 actor 创建一个代理，并将电子邮件验证的输出写入控制台窗口。您的客户端应用程序现在已经准备就绪。

# 它是如何工作的...

然而，在运行客户端应用程序之前，我们需要先发布我们的服务。在解决方案资源管理器中，右键单击`sfApp`服务，然后从上下文菜单中单击“发布...”：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_17.png)

现在将显示发布 Service Fabric 应用程序窗口。单击连接端点文本框旁边的“选择...”按钮。选择本地集群作为您的连接端点，然后单击“确定”。将目标配置文件和应用程序参数文件更改为`Local.1Node.xml`。完成后，单击“发布”按钮：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_18.png)

如果您导航到`http://localhost:19080/Explorer`，您会注意到您创建的服务已发布到本地的 Service Fabric 集群：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_19.png)

现在您已经准备好运行您的客户端应用程序。右键单击`sfApp.Client`项目，然后从上下文菜单中选择“调试”和“启动新实例”。控制台应用程序调用`validate`方法来检查电子邮件地址，并将结果显示在控制台窗口中。结果如预期的那样：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_20.png)

如果在尝试运行控制台应用程序时收到`System.BadImageFormatException`，请检查控制台应用程序的目标平台。您可能已经将控制台应用程序编译为 Any CPU，而解决方案中的其他项目则以 x64 为目标。从配置管理器中修改这一点，并使控制台应用程序也以 x64 为目标。

但是，在创建 actor ID 时，我们可以更具体。在先前的代码清单中，我们使用`CreateRandom()`方法生成了一个`ActorId`。现在我们可以给它一个特定的名称。修改您的代理代码，创建一个新的`ActorId`实例，并给它任何字符串值。在下面的代码清单中，我只是称呼我的为`Utilities`：

```cs
var actProxy = ActorProxy.Create<IUtilitiesActor>(new ActorId("Utilities"), "fabric:/sfApp");

```

`ActorId`方法可以接受`Guid`、`long`或`string`类型的参数。

当您再次调试您的客户端应用程序时，您会注意到`Utilities Actor`现在有一个逻辑名称（与创建新的`ActorId`实例时传递的字符串值相同的名称）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_21.png)

在将您的 Service Fabric 应用程序本地发布之前，这是测试应用程序的完美解决方案。创建小型、独立的微服务允许开发人员在测试、调试和部署高效和健壮的代码方面获得许多好处，您的应用程序可以利用这些好处来确保最大的可用性。

# 使用 Service Fabric Explorer

还有另一个工具可以用来可视化 Service Fabric 集群。这是一个独立的工具，您可以通过导航到本地安装路径`%Program Files%\Microsoft SDKs\Service Fabric\Tools\ServiceFabricExplorer`并单击`ServiceFabricExplorer.exe`来找到。运行应用程序时，它将自动连接到您的本地 Service Fabric 集群。它可以显示有关集群上的应用程序、集群节点、应用程序和节点的健康状态以及集群中应用程序的任何负载的丰富信息。

# 准备工作

您必须已经在本地计算机上完成了 Service Fabric 的安装，才能使 Service Fabric Explorer 正常工作。如果尚未完成，请按照本章中的*下载和安装 Service Fabric*配方进行操作。

# 如何做...

1.  当您启动 Service Fabric Explorer 时，将出现以下窗口：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_22.png)

1.  请注意，左侧的树形视图显示了应用程序视图和节点视图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_23-1.png)

1.  右侧窗格将显示有关本地集群的信息。这使您可以轻松地查看本地服务集群的整体健康状况：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_24-1.png)

1.  当您扩展应用程序视图时，您会注意到我们的`sfApp`服务已经发布。进一步扩展它，您会看到`sfApp`服务已经发布在 Node_3 上。扩展节点视图和 Node_3，以查看该节点上的服务活动：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_25.png)

1.  为了说明微服务的可扩展性，右键单击 Node_3，并从上下文菜单中选择在节点上激活/停用和停用（删除数据）。然后，单击窗口顶部的刷新按钮以刷新节点和应用程序。

1.  如果您现在继续扩展应用程序视图并再次查看服务，您会注意到 Service Fabric 集群注意到 Node_3 已被禁用。然后自动将服务推送到一个新的健康节点（在本例中为 Node_2）：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_26.png)

1.  Service Fabric Explorer 右侧面板中的本地集群节点视图还报告 Node_3 已禁用。单击节点视图以查看此信息：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_27.png)

# 工作原理...

Service Fabric Explorer 将允许您查看所选节点的信息，并且您将能够深入了解有关 Service Fabric 集群应用程序的丰富信息。这只是管理员除了浏览器中可用的 Service Fabric Explorer 之外可以使用的另一个实用程序。

有一些激烈的辩论关于开发人员应该如何处理微服务架构。有人认为，当开发人员的目标是应用程序的微服务架构时，需要从单体优先的角度来处理。也就是说，首先编写大型单体应用程序，因为这个过程是熟悉的开发方法。在完成后，计划并将单体应用程序划分为更小的微服务。这里的论点是，创建单体应用程序时，上市时间更快。更快的上市时间意味着更快的投资回报。

另一方面的论点是，从单体开始恰恰是错误的方法。在设计阶段开始考虑如何将应用程序划分为部分才是正确的时间。然而，必须承认，开发团队可能需要了解他们需要构建的系统。另一个让步是，也许最好在创建现有单体的第二个版本时采用微服务方法。单体应用程序根据定义，所有部分都紧密耦合在一起。将这些部分分解为更小的微服务需要多少时间？

无论您决定采取哪种方法，都必须在仔细考虑涉及所有利益相关者的所有事实之后做出决定。不幸的是，没有公式或硬性规则可以帮助您做出决定。关于应用程序架构（单体与微服务）的决定将因项目而异。


# 第十六章：Azure 和无服务器计算

现在，我敢打赌，有些人来到这一章，问道：“无服务器计算到底是什么意思？”名字很令人困惑，我同意。对我来说毫无意义，但当你理解这个概念时，它有点意义。在这一章中，我们将看看无服务器计算这个术语的含义。我们还将看一下：

+   创建 Azure 函数

+   使用 DocRaptor 提供打印功能

+   使用 AWS 和 S3

+   使用 AWS 和 S3 创建 C# lambda 函数

# 介绍

无服务器并不意味着没有服务器，而是你（或应用程序）不知道用于为应用程序提供某些功能的服务器是哪个。因此，无服务器描述了一个依赖于云中的某些第三方应用程序或服务来为应用程序提供一些逻辑或功能的应用程序。

让我们以学生研究门户的例子来说明。学生研究某个主题并在门户中创建相关的文档。然后他们可以加载打印信用到他们的个人资料中，并打印他们需要的保存的文档。在打印一页后，打印信用将从他们的个人资料中扣除。

虽然这是一个非常简单的例子，但我用它来说明无服务器计算的概念。我们可以将应用程序分成各种组件。具体如下：

1.  登录认证

1.  购买打印信用

1.  更新剩余的打印信用

1.  打印文档

这里可能需要其他未提及的组件，但这不是现实世界。我们只是创建这个假设的应用程序来说明无服务器计算的概念。

当已经有第三方服务提供登录认证时，为什么还要在您的应用程序中编写代码来提供登录认证呢？同样，当有提供打印文档的服务时，为什么还要编写代码来打印文档呢？任何特定的功能，比如购买和加载学生打印信用，都可以使用 Azure 函数来创建。无服务器计算的主题是广泛的，而且还处于起步阶段。还有很多东西要学习和体验。让我们迈出第一步，探索这对开发人员有什么好处。

# 创建 Azure 函数

为什么选择 Azure Functions？想象一下，您有一个应用程序需要提供一些特定的功能，但当对函数的调用率增加时，它仍然会扩展。这就是 Azure Functions 提供的好处所在。使用 Azure Functions，您只支付函数在特定时间点所需的计算，而且它立即可用。

要开始，请访问[`azure.microsoft.com/en-us/services/functions`](https://azure.microsoft.com/en-us/services/functions)并创建一个免费账户。

因为在运行 Azure Functions 时，您只支付实际使用的计算时间，所以您的代码尽可能优化是至关重要的。如果您重构 Azure Function 代码并获得了 40%的代码执行改进，那么您直接节省了 40%的月度费用。您重构和改进代码的越多，您就能节省更多的钱。

# 准备工作

您需要设置一个 Azure 账户。如果您还没有账户，可以免费设置一个。从 Azure 门户，在左侧菜单中，点击“新建”开始：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_01.jpg)

在搜索框中，输入“函数应用程序”并点击“Enter”按钮。第一个结果应该是函数应用程序。选择它。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_02.jpg)

当您选择函数应用程序时，您将看到右侧弹出此屏幕。描述完美地描述了 Azure Functions 的功能。在此表单底部点击“创建”按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_03.jpg)

现在您看到一个表单，允许您为函数命名并选择资源组和其他设置。完成后，点击“创建”按钮。 

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_04.jpg)

# 如何做...

1.  Azure 创建新的函数应用程序后，您将能够创建 Azure 函数。我们要做的就是创建一个 Azure 函数，每当 GitHub 存储库上发生某些事情时就会触发。单击创建自定义函数链接。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_05.jpg)

根据 Microsoft Azure 网站，编写 Azure Functions 时支持以下内容：JavaScript、C#、F#以及 Python、PHP、Bash、Batch 和 PowerShell 等脚本选项。

1.  现在您将看到可以在几个模板之间进行选择。从语言选择中选择 C#，从场景选择中选择 API 和 Webhooks，然后选择 GitHubWebHook-CSharp 模板。Azure 现在会要求您为函数命名。我将我的命名为`GithubAzureFunctionWebHook`。单击创建按钮创建函数。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_06.jpg)

1.  创建函数后，您将看到在线代码编辑器中为您添加了一些默认代码。

```cs
        using System.Net;

        public static async Task<HttpResponseMessage> Run
                              (HttpRequestMessage req, TraceWriter log)
        {
          log.Info("C# HTTP trigger function processed a request.");

          // Get request body
          dynamic data = await req.Content.ReadAsAsync<object>();

          // Extract github comment from request body
          string gitHubComment = data?.comment?.body;

          return req.CreateResponse(HttpStatusCode.OK, "From Github:" +
                                    gitHubComment);
        }

```

1.  在`return`语句之前，添加以下代码行：`log.Info($"来自 GitHub 的消息：{gitHubComment}");`。这样我们就可以看到从 GitHub 发送的内容。

1.  您的代码现在应如下所示。请注意，有两个链接可让您获取函数 URL 和 GitHub 秘钥。单击这些链接，然后将每个值复制到记事本中。单击保存并运行按钮。

您的 Azure 函数 URL 应类似于：`https://funccredits.azurewebsites.net/api/GithubAzureFunctionWebHook`

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_07.jpg)

1.  转到 GitHub 网站[`github.com/`](https://github.com/)。如果您没有帐户，请创建一个并创建一个存储库（GitHub 对开源项目免费）。转到您创建的存储库，然后单击设置选项卡。在左侧，您将看到一个名为 Webhooks 的链接。单击该链接。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_08.jpg)

1.  现在您将看到右侧有一个名为添加 webhook 的按钮。单击该按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_09.jpg)

1.  将之前复制的 Azure Function URL 添加到 Payload URL 字段。将内容类型更改为 application/json，并将之前复制的 GitHub 秘钥添加到秘钥字段。选择 Send me everything，然后单击添加 webhook 按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_10.jpg)

# 工作原理...

在您的 GitHub 存储库中，打开一个文件并向其添加评论。单击此提交上的评论按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_11.jpg)

返回到 Azure Function 并查看日志窗口。此窗口直接位于代码窗口下方。您将看到我们在 GitHub 中发布的评论出现在 Azure Function 的日志输出中。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_12.jpg)

如果日志窗口中没有显示任何内容，请确保您已单击 Azure Function 的运行按钮。如果一切都失败了，请单击测试窗口底部的运行按钮。

虽然这只是一个非常简单的例子，但 Azure Functions 的实用性应该变得明显。您还会注意到函数具有`.csx`扩展名。重要的是要注意，无论您选择使用哪种编程语言编写代码，Azure Functions 都共享一些核心概念和组件。归根结底，函数是这里的主要概念。您还有一个包含 JSON 配置数据的`function.json`文件。您可以通过单击右侧的查看文件链接来查看此文件和其他文件。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_13.jpg)

单击`function.json`文件，您将看到 JSON 文件的内容。将`disabled`属性更改为`true`将有效地阻止函数在调用时执行。您还会注意到`bindings`属性。在这里，您可以配置您的 web hook。所有这些设置都可以在 Azure Function 的集成和其他部分中设置。

```cs
        {
          "bindings": [
            {
              "type": "httpTrigger",
              "direction": "in",
              "webHookType": "github",
              "name": "req"
            },
            {
              "type": "http",
              "direction": "out",
              "name": "res"
            }
          ],
          "disabled": false
        }

```

Azure Functions 和向开发人员提供的好处是一个令人兴奋的概念。这是您编程技能中的一个领域，肯定会让您忙碌很多小时，因为您将探索更复杂和复杂的任务。

# 使用 DocRaptor 提供打印功能

从 Web 应用程序中打印一直是棘手的。如今，由于提供打印功能的众多第三方控件的可用性，这变得更加容易。然而，现实情况是，我遇到过许多项目，在开发时使用了第三方控件来提供打印功能。当时，第三方控件很好，确实满足了他们的需求。

使应用程序具有这种功能意味着购买这些第三方控件的公司很少继续续订他们的许可证。然而，几年后，这将导致 Web 应用程序包含旧的和过时的打印技术。虽然这没有什么问题，但它确实有一些缺点。

开发人员通常被困在维护老化的代码库中，这些代码库被锁定在这个第三方控件中。一旦需求发生变化，你会发现开发人员不得不使代码在第三方控件的限制内工作。或者，他们需要向管理层提出建议，建议更新第三方控件到最新版本。这意味着在打印模块中需要的小改动，结果比任何人的预算都要昂贵。

现实世界：我曾经在一家公司工作，这家公司会让顾问为客户报价某个应用功能的更改。一旦报价得到接受，就交给开发人员在规定的时间和预算内使其工作。这导致开发人员不得不修改代码以使其工作，并满足预算和截止日期，因为缺乏适当的项目管理技能。替换第三方控件几乎是不可能的，因为预算已经在没有开发人员参与的情况下确定了。

我同意有一些开发人员在维护老化的代码库中提供和维护功能方面做得非常好。我也非常喜欢第三方控件和它们提供的功能。开发人员可以选择一些大型的供应商。但问题是：当你只需要打印发票时，为什么要购买一套第三方控件？按照这种逻辑，在许多情况下（包括本例），无服务器更有意义。

# 准备工作

这个示例将介绍一个名为 DocRaptor 的服务。这项服务并不是免费的，但考虑一下在您的 Web 应用程序中编写和维护提供打印功能的代码的成本。考虑购买第三方控件以提供相同的功能的成本。最终取决于作为开发人员的您选择什么才是最合理的。

创建一个基本的 Web 应用程序，然后转到工具，NuGet 包管理器，包管理器控制台。在控制台中键入以下命令以安装 DocRaptor NuGet 包。

```cs
Install-Package DocRaptor

```

安装了 DocRaptor 后，您可以访问他们的网页（[`docraptor.com/`](http://docraptor.com/)）阅读一些 API 文档，或者您也可以访问 GitHub 页面（[`github.com/DocRaptor/docraptor-csharp`](https://github.com/DocRaptor/docraptor-csharp)）获取更多信息。

最好查看本书附带的源代码，以便复制本示例的代码。

# 如何做到这一点...

1.  添加一个包含发票详细信息的 aspx 网页。我只是从 DocRaptor 网站的示例中简单地提取并稍作修改。将此页面命名为`InvoicePrint.aspx`。

我已经在名为`invoice.css`的样式表中包含了 CSS。一定要从本书附带的源代码中获取这个。

有几种方法可以处理这段代码。这并不一定是创建 Web 页面的唯一方法。如果您使用.NET Core MVC，您的方法可能会有所不同。但是，如果您这样做，请记住，这段代码只是为了说明这里的概念。

```cs
    <%@ Page Language="C#" AutoEventWireup="true" CodeBehind="InvoicePrint.aspx.cs" Inherits="Serverless.InvoicePrint" %>

    <!DOCTYPE html>

    <html >
      <head runat="server">
         <title>Invoice</title>
         <meta http-equiv="content-type" content="text/html;
          charset=utf-8"/>
        <link href="css/invoice.css" rel="stylesheet" />
        <script type="text/javascript">
          function ToggleErrorDisplay()
          {
            if ($("#errorDetails").is(":visible")) {
              $("#errorDetails").hide();
            } else {
              $("#errorDetails").show();
            }
          }

          function TogglePrintResult() {
            if ($("#printDetails").is(":visible")) {
              $("#printDetails").hide();
            } else {
              $("#printDetails").show();
            }
          }
        </script>
      </head>
      <body>
        <form runat="server">
          <div id="container"> 
            <div id="main">
              <div id="header">
                <div id="header_info black">The Software Company
                  <span class="black">|</span> (072)-412-5920 
                  <span class="black">|</span> software.com</div>
              </div>
              <h1 class="black" id="quote_name">Invoice INV00015</h1>
              <div id="client" style="float: right">
                <div id="client_header">client:</div>
                <p class="address black">
                  Mr. Wyle E. Coyote
                </p>
              </div>
              <table id="phase_details">
                <thead>
                  <tr>
                    <th class="title">Stock Code</th>
                    <th class="description">Item Description</th>
                    <th class="price">price</th>
                  </tr>
                </thead>
                <tr class="first black">
                  <td>BCR902I45</td>
                  <td>Acme Company Roadrunner Catch'em Kit</td>
                  <td class="price">
                    <div class="price_container">$300</div>
                  </td>
                </tr>
                <tr>
                  <td></td>
                  <td>Booster Skates</td>
                  <td class="price">
                    <div class="price_container">$200</div>
                  </td>
                </tr>
                <tr>
                  <td></td>
                  <td>Emergency Parachute</td>
                  <td class="price">
                     <div class="price_container">$100</div>
                  </td>
                </tr>
                <tr class="last">
                  <td></td>
                  <td></td>
                  <td></td>
                </tr>
                <tr class="first black">
                  <td>BFT547J78</td>
                  <td>Very Sneaky Trick Seed Kit</td>
                  <td class="price">
                    <div class="price_container">$800</div>
                  </td>
                </tr>
                <tr>
                  <td></td>
                  <td>Giant Magnet and Lead Roadrunner Seeds</td>
                  <td class="price">
                    <div class="price_container">$500</div>
                  </td>
                </tr>
                <tr>
                  <td></td>
                  <td>Rollerblades</td>
                  <td class="price">
                    <div class="price_container">$300</div>
                  </td>
                </tr>
                <tr class="last">
                  <td></td>
                  <td></td>
                  <td></td>
                </tr>
              </table>
            </div>
            <div id="total_price">
              <h2>TOTAL: <span class="price black">$1100</span></h2>
            </div>
            <div id="print_link">
              <asp:LinkButton ID="lnkPrintInvoice" runat="server"
                Text="Print this invoice" OnClick="lnkPrintInvoice_Click">
              </asp:LinkButton> 
            </div>
            <div id="errorDetails">
              <asp:Label ID="lblErrorDetails" runat="server">
              </asp:Label>
            </div>
            <div id="printDetails">
              <asp:Label ID="lblPrintDetails" runat="server">
              </asp:Label>
            </div>
          </div>
        </form>

      </body>
    </html>

```

1.  我还创建了一个名为`invoice.html`的发票页面的打印友好版本。

1.  下一步是为链接按钮创建一个单击事件。将以下代码添加到单击事件。您会注意到，我只是将生成 PDF 文档的路径硬编码为：`C:tempinvoiceDownloads`。如果您想要输出到不同的路径（或者获取相对于您所在服务器的路径），请确保更改此路径。

```cs
        Configuration.Default.Username = "YOUR_API_KEY_HERE";
        DocApi docraptor = new DocApi();

         Doc doc = new Doc(
           Test: true,
           Name: "docraptor-csharp.pdf",
           DocumentType: Doc.DocumentTypeEnum.Pdf,
           DocumentContent: GetInvoiceContent()
        );

        byte[] create_response = docraptor.CreateDoc(doc);
        File.WriteAllBytes(@"C:tempinvoiceDownloadsinvoice.pdf",
                           create_response);

```

1.  确保在您的网页中包含以下命名空间：

```cs
        using System;
        using System.Web.UI;
        using DocRaptor.Client;
        using DocRaptor.Model;
        using DocRaptor.Api;
        using System.IO;
        using System.Net;
        using System.Text;

```

1.  最后，获取名为`invoice.html`的打印友好页面的 HTML 内容。下面代码中的 URL 在您的机器上会有所不同，因为您的端口号可能不同。

```cs
        private string GetInvoiceContent()
        {
          WebRequest req = WebRequest.Create
                              ("http://localhost:37464/invoice.html");
          WebResponse resp = req.GetResponse();
          Stream st = resp.GetResponseStream();
          StreamReader sr = new StreamReader(st, Encoding.ASCII);
          return sr.ReadToEnd();
        }

```

# 它是如何工作的...

运行您的 Web 应用程序并查看在 Web 页面上显示的基本发票。确保您已将`InvoicePrint.aspx`页面设置为 Web 应用程序的起始页面。单击“打印此发票”链接。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_14.jpg)

您将看到发票已创建在您指定的输出路径中。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_15.jpg)

单击 PDF 文档以打开发票。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_16.jpg)

DocRaptor 为开发人员创建 Web 解决方案提供了一个非常有用的服务。如果您需要从您的应用程序创建 PDF 或 Excel 文档，DocRaptor 可以使您的团队受益。本例中使用的测试文档可免费使用，不会从您的月配额中扣除（如果您是付费计划用户）。

从真正无服务器的意义上讲，DocRaptor 为您提供功能，而无需您编写大量额外的代码。它非常容易实现，也非常容易维护。前面的例子非常基本，但您可以传递给 DocRaptor 一个 URL，而不是`DocumentContent`，以打印您想要的页面。从开发人员的角度来看，他们不关心 DocRaptor 是如何做到的。它只是有效。这就是无服务器计算背后的理念。

开发人员可以轻松、毫不费力地在他们的应用程序中实现解决方案，并在记录时间内使用最少的代码为他们正在开发的应用程序增加了很多价值。随着需求的增加，实施的功能也可以轻松扩展。但是，专业计划会有超额费用。最后，创建几个 PDF 文档可能不会对服务器计算能力产生太大影响。然后考虑到 DocRaptor 被一些大公司使用，这些公司可能每个月生成数千份文档。所有这些文档生成请求都不是由使用 DocRaptor 的客户处理的，而是由 DocRaptor 服务器自己处理的。

然后，您可以开发一个轻量级、简化的 Web 应用程序，随着访问量的增加，不会对您的服务器造成巨大的需求。

# 使用 AWS 和 S3

没有看到 Amazon Web Services（AWS）这一章就不能算完整。AWS 的主题非常广泛。该平台提供了许多功能。开发人员可以在他们的应用程序中利用这一点，并在他们自己的部分上使用最少的代码提供丰富的功能。AWS 还有非常好的文档，开发人员可以快速查看以迅速掌握。S3 是亚马逊的简单存储服务，允许您在云中存储和检索数据。

我喜欢和我的孩子们一起玩 Minecraft。他们创造的一些东西令人难以置信，尤其是因为我的女儿（以 CupcakeSparkle 的身份玩耍）只有 7 岁，而我的儿子（以 Cheetah 的身份玩耍）只有 4 岁。我的女儿从 5 岁开始玩 Minecraft，可以想象，她已经创造了相当多令人难以置信的结构。Joseph Garrett 绝对是我孩子们最喜欢的 YouTuber，他以 Stampy Cat 的身份玩耍。他们经常（包括与 Squid Nugget 一起建造时间）看他的游戏视频。我们经常举行自己的建造时间比赛，而 Stampy Cat 和他美丽的世界则成为我的孩子们在 Minecraft 中所做的一切的灵感来源。

这是我女儿建造的 Stampy Cat 的图片。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_23.png)

这是我儿子建造的 Squid Nugget 的图片。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_24.png)

因此，我想创建一个地方来上传一些他们的 Minecraft 图片、截图和与我们的 Minecraft 冒险相关的其他文档。为此，我们将使用 S3。

# 准备工作

本章假设您已经注册了 AWS 账户并使用了免费套餐。有关免费套餐的更多详细信息，请转到[`aws.amazon.com/free/`](https://aws.amazon.com/free/)。不过，我想要强调的一个部分是：

<q>亚马逊网络服务（AWS）免费套餐旨在让您能够亲身体验 AWS 云服务。AWS 免费套餐包括在您注册 AWS 后的 12 个月内提供免费套餐的服务，以及在您的 12 个月 AWS 免费套餐期满后不会自动到期的其他服务提供。</q>

为了注册，您需要提供您的信用卡信息。免费套餐期满后（或者如果您的应用程序超出了使用限制），您将按照按使用量付费的服务费率收费。特别是关于 S3，免费套餐允许 5GB 的存储空间，20,000 个获取请求和 2,000 个放置请求。首先，您需要创建一个 S3 存储桶。从服务选择中，找到存储组，然后点击 S3。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_21.jpg)

创建您的第一个存储桶。我将其命名为`familyvaultdocs`并选择了 EU（法兰克福）地区。点击下一步，直到完成存储桶的创建。 

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_17.jpg)

创建存储桶后，您可以查看存储桶的权限。为简单起见，我已选择让所有人对对象访问和权限访问具有读取和写入权限。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_18.jpg)

最后，您还需要为您的应用程序创建访问密钥和秘密密钥。从服务中查找安全、身份和合规性组，然后点击 IAM（身份和访问管理）。添加一个访问类型为程序访问的用户。这将为您提供所需的访问密钥 ID 和秘密访问密钥。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_22.jpg)

创建了您的存储桶，用户权限设置为所有人，并创建了访问密钥，让我们写一些代码。

# 如何做...

1.  我们将创建一个控制台应用程序，将图片上传到之前创建的 S3 存储桶中。首先打开 NuGet 包管理器，并将 AWSSDK NuGet 包添加到您的控制台应用程序中。

您可能值得查看以下链接中的.NET 的 AWS SDK[`aws.amazon.com/sdk-for-net/`](https://aws.amazon.com/sdk-for-net/)。这有助于开发人员快速掌握 SDK。

1.  接下来，创建一个名为`StampysLovelyWorld`的类和一个名为`SaveStampy()`的方法。代码真的没有什么复杂的地方。创建一个指定存储桶区域的客户端对象，创建一个指定要上传的文件、存储桶名称和目录的`TransferUtilityUploadRequest`对象，最后，通过`TransferUtility`将文件上传到存储桶。

AWS 的`RegionEndpoint`枚举为 EU（法兰克福）是`EUCentral1`。请参考 AWS 区域和端点的以下链接[`docs.aws.amazon.com/general/latest/gr/rande.html.`](https://docs.aws.amazon.com/general/latest/gr/rande.html.)

实际上，我们可能会枚举文件夹的内容，甚至允许用户选择多个文件。这个类只是为了说明将文件上传到我们的存储桶的概念。正如您将看到的，这段代码真的很简单。

```cs
        internal static class StampysLovelyWorld
        { 
          public static void SaveStampy(string fileToSave,
                                        string bucket,
                                        string bucketDirectory,
                                        string bucketFilename)
          {
            IAmazonS3 client = AWSClientFactory.CreateAmazonS3Client
                                        (RegionEndpoint.EUCentral1);

            TransferUtility utility = new TransferUtility(client); 
            TransferUtilityUploadRequest request = new 
                                    TransferUtilityUploadRequest();

            request.BucketName = bucket + "/" + bucketDirectory;
            request.Key = bucketFilename; 
            request.FilePath = fileToSave; 
            utility.Upload(request); 
          }
        }

```

1.  在控制台应用程序的`static void Main`方法中，指定您之前创建的存储桶名称，要在存储桶中创建的文件夹以及您想要在 S3 文件夹中的文件名。将这些与文件的路径一起传递给`StampysLovelyWorld`类中的`SaveStampy()`方法。

```cs
        static void Main(string[] args)
        {
          string uploadFile = "C:UsersdirkPicturesSaved 
                               PicturesStampyCat.png";
          string S3Bucket = "familyvaultdocs"; 
          string S3Folder = "MinecraftPictures";
          string uploadedFilename = $"{DateTime.Now.ToString("yyyymmdd")}
                                      - StampyCat.png";
          StampysLovelyWorld.SaveStampy(uploadFile, S3Bucket, S3Folder,
                                        uploadedFilename);
          WriteLine("uploaded");
          ReadLine();
        }

```

1.  我们需要做的最后一件事是将访问密钥和秘密密钥添加到我们控制台应用程序的 App.config 文件中。只需添加一个`<appSettings>`部分，并添加此处列出的密钥。您显然会使用之前在 IAM 中生成的访问密钥和秘密密钥。

```cs
        <?xml version="1.0" encoding="utf-8" ?>
        <configuration>
          <appSettings>
            <add key="AWSProfileName" value="profile1"/>
            <add key="AWSAccessKey" value="AKIAJ6Q2Q77IHJX7STWA"/>
            <add key="AWSSecretKey" value="uFBN6xtuWCSf9zR9WzQKrh1vk
                                           zU2PEuosTTy5qhc"/>
          </appSettings>
          <startup>
            <supportedRuntime version="v4.0" sku=".NETFramework,
                Version=v4.6.2" />
          </startup>
        </configuration>

```

1.  运行您的控制台应用程序。文件上传后，您的控制台应用程序将在输出中显示上传的文本。

# 它是如何工作的...

返回到 AWS 中的`familyvaultdocs`存储桶，并单击欧盟（法兰克福）区域旁边的刷新图标。您将看到您在代码中指定的`MinecraftPictures`文件夹。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_19.jpg)

单击文件夹，您将看到列出的内容。我之前上传了`SquidNugget.png`图像，但我们在代码示例中上传的`StampyCat.png`图像已经根据代码中指定的日期前缀。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_20.jpg)

代码运行并且文件几乎立即被添加。诚然，这些文件并不是很大，但这表明了在 AWS 中添加简单存储服务并将其与.NET 应用程序集成是多么容易。

# 使用 AWS 创建 C# Lambda 函数

2016 年 12 月 1 日，亚马逊宣布 C#现在是 AWS Lambda 支持的语言。因此，这实际上是最新的消息，开发人员可以尝试在.NET 应用程序中使用 AWS Lambda。AWS Lambda 允许您将代码部署到 AWS，而无需担心代码运行的机器，甚至无需担心需求增加时这些机器的扩展。您的代码将正常工作。这对移动开发人员来说非常棒。直到 12 月，AWS Lambda 只支持 Node.js、Pythos 和 Java。让我们看看如何在 Visual Studio 2017 中使用 C#创建 Lambda 函数。

# 准备工作

您需要确保已下载并安装了 Visual Studio 2017 的 AWS Toolkit 预览版。在撰写本文时，工具包可以在以下链接找到：[`aws.amazon.com/blogs/developer/preview-of-the-aws-toolkit-for-visual-studio-2017/`](https://aws.amazon.com/blogs/developer/preview-of-the-aws-toolkit-for-visual-studio-2017/)。

如果您使用的是较早版本的 Visual Studio，请从此链接下载 AWS Toolkit：[`aws.amazon.com/visualstudio/`](https://aws.amazon.com/visualstudio/)。该工具包支持 Visual Studio 2015，并允许您下载 Visual Studio 2010-2012 和 Visual Studio 2008 的旧版本。下载并安装工具包后，您就可以创建您的第一个 AWS Lambda 函数了。

# 如何操作...

1.  启动 Visual Studio 并创建一个新项目。在 Visual C#模板下，您将看到一个名为 AWS Lambda 的新类型。单击 AWS Lambda 项目(.NET Core)模板。没错，这些是.NET Core 应用程序。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_25.jpg)

1.  下一个屏幕将允许我们选择一个蓝图。对于我们的目的，我们将选择一个简单的 S3 函数蓝图，用于响应 S3 事件通知。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_26.jpg)

1.  函数已创建，您的 Visual Studio 中的解决方案资源管理器将如下所示。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_27.jpg)

1.  添加到`Function.cs`文件的代码只是一个具有名为`FunctionHandler()`的方法的类。您还会注意到类顶部的程序集属性如下：`[assembly: LambdaSerializerAttribute(typeof(Amazon.Lambda.Serialization.Json.JsonSerializer))]`。这是必需的，并注册了使用`Newtonsoft.Json`创建我们的类型化类的 Lambda JSON 序列化程序。由于这段代码只是起作用，我不会花太多时间来解释它。

```cs
        public async Task<string> FunctionHandler(S3Event evnt,
                                                ILambdaContext context)
        {
          var s3Event = evnt.Records?[0].S3;
          if(s3Event == null)
          {
            return null;
          }

          try
          {
            var response = await this.S3Client.GetObjectMetadataAsync
                           (s3Event.Bucket.Name, s3Event.Object.Key);
            return response.Headers.ContentType;
          }
          catch(Exception e)
          {
            context.Logger.LogLine($"Error getting object
              {s3Event.Object.Key} from bucket {s3Event.Bucket.Name}.
              Make sure they exist and your bucket is in the same
              region as this function.");
            context.Logger.LogLine(e.Message);
            context.Logger.LogLine(e.StackTrace);
            throw;
          }
        }

```

1.  现在，您可以直接从 Visual Studio 中发布函数到 AWS。右键单击您创建的项目，从上下文菜单中选择发布到 AWS Lambda....

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_28.jpg)

1.  现在，您需要完成部署向导。为您的函数命名，如果您没有选择帐户配置文件，请添加一个。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_29.jpg)

对于您的 AWS Lambda 函数，请确保选择与上一篇文章中创建的 S3 存储桶相同的区域。

1.  添加账户配置文件非常简单。这是您在 IAM 中配置的帐户。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_30.jpg)

1.  单击“下一步”将允许您选择为 S3 和我们的函数提供访问权限的 IAM 角色名称。这是在**IAM**（身份和访问管理）中配置的。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_31.jpg)

1.  单击“上传”将函数上传到 AWS。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_32.jpg)

1.  请注意，在这一步可能会遇到几个权限问题。您可能会遇到以下内容：

```cs
Error creating Lambda function: User: arn:aws:iam::932141661806:user/S3Lambda is not authorized to perform: lambda:CreateFunction on resource: arn:aws:lambda:eu-central-1:932141661806:function:S3LambdaFunction

```

实际上，在尝试将函数上传到 AWS 时，您可能会收到几个此类错误。AWS 中的身份和访问管理区域在这里是您的朋友。您应该查看您正在使用的用户（在本例中是 S3Lambda）并审查分配给用户的权限。在这里，错误通知我们，用户 S3Lambda 没有权限在 AWS 上为 S3LambdaFunction 资源创建函数。修改您的权限，然后尝试重新上传。

# 工作原理...

将函数上传到 AWS 后，在 Visual Studio 中单击“查看”菜单，然后选择 AWS 资源管理器。展开 AWS Lambda 节点将显示我们之前上传的函数。如果在展开节点时看到错误，可能需要为您的用户提供 ListFunctions 权限。展开 AWS 身份和访问管理节点还将显示您配置的用户、组和角色。您可以通过选择一个示例请求并单击“调用”按钮在 Visual Studio 中轻松测试 AWS Lambda 函数。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_33.jpg)

然而，我们想要做的是将存储文件的 S3 连接到我们的函数以发送事件。单击“事件源”选项卡，然后单击“添加”按钮。选择 Amazon S3 作为源类型，并选择我们在上一篇文章中创建的`familyvaultdocs`存储桶。完成后，单击“确定”按钮。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_34.jpg)

运行上一篇文章中的控制台应用程序以将新文件上传到我们的 S3 存储桶将触发我们的 Lambda 函数。我们可以通过查看函数视图中的日志部分来确认这一点。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_35.jpg)

您还可以从 AWS 资源管理器上传文件。展开 Amazon S3 节点，然后单击“上传文件”按钮到存储桶。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_36.jpg)

您的文件已上传，并且进度显示在底部的状态窗口中。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cs7-dncore-cb/img/B06434_17_37.jpg)

虽然这个例子并不太复杂（除了权限设置可能有点复杂），但它确实说明了 AWS Lambda 函数的概念。我们可以使用该函数在触发来自 S3 存储桶中的事件等简单事件时执行一系列操作。开始结合功能，您可以创建一个非常强大的无服务器模块，以支持和增强您的应用程序。

无论您使用 AWS、Azure 还是诸如 DocRaptor（或任何其他第三方服务），无服务器计算都将长存下去，C# Lambda 函数将以一种重大的方式改变开发的面貌。
