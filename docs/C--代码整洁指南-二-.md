# C# 代码整洁指南（二）

> 原文：[`zh.annas-archive.org/md5/0768F2F2E3C709CF4014BAB4C5A2161B`](https://zh.annas-archive.org/md5/0768F2F2E3C709CF4014BAB4C5A2161B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：编写干净的函数

干净的函数是小方法（它们有两个或更少的参数）并且避免重复。理想的方法没有参数，也不修改程序的状态。小方法不太容易出现异常，因此你将编写更加健壮的代码，从长远来看，你将有更少的错误需要修复。

函数式编程是一种将计算视为数学计算的软件编码方法。本章将教你将计算视为数学函数的评估的好处，以避免改变对象的状态。

大方法（也称为函数）阅读起来笨拙且容易出错，因此编写小方法有其优势。因此，我们将看看如何将大方法分解为小方法。在本章中，我们将介绍 C#中的函数式编程以及如何编写小而干净的方法。

构造函数和具有多个参数的方法可能会变得非常麻烦，因此我们需要寻找解决方法来处理和传递多个参数，以及如何避免使用超过两个参数。减少参数数量的主要原因是它们可能变得难以阅读，会让其他程序员感到烦恼，并且如果参数足够多的话会造成视觉压力。它们也可能表明该方法试图做太多的事情，或者你需要考虑重构你的代码。

在本章中，我们将涵盖以下主题：

+   理解函数式编程

+   保持方法小

+   避免重复

+   避免多个参数

通过本章的学习，你将具备以下技能：

+   描述函数式编程是什么

+   在 C#编程语言中提供现有的函数式编程示例

+   编写函数式的 C#代码

+   避免编写超过两个参数的方法

+   编写不可变的数据对象和结构

+   保持你的方法小

+   编写符合单一职责原则（SRP）的代码

让我们开始吧！

# 理解函数式编程

函数式编程与其他编程方法的唯一区别在于函数不修改数据或状态。在深度学习、机器学习和人工智能等场景中，当需要对相同的数据集执行不同的操作时，你将使用函数式编程。

.NET Framework 中的 LINQ 语法是函数式编程的一个例子。因此，如果你想知道函数式编程是什么样子，如果你以前使用过 LINQ，那么你已经接触过函数式编程，并且应该知道它是什么样子的。

由于函数式编程是一个深入的主题，关于这个主题存在许多书籍、课程和视频，所以我们在本章中只会简要涉及这个主题，通过查看纯函数和不可变数据。

纯函数只能对传入的数据进行操作。因此，该方法是可预测的，避免产生副作用。这对程序员有好处，因为这样的方法更容易推理和测试。

一旦初始化了一个不可变的数据对象或数据结构，其中包含的数据值将不会被修改。因为数据只是被设置而不是修改，你可以很容易地推断出数据是什么，它是如何设置的，以及任何操作的结果会是什么，给定了输入。不可变数据也更容易测试，因为你知道你的输入是什么，以及期望的输出是什么。这使得编写测试用例变得更容易，因为你不需要考虑那么多事情，比如对象状态。不可变对象和结构的好处在于它们是线程安全的。线程安全的对象和结构可以作为良好的数据传输对象（DTOs）在线程之间传递。

但是如果结构包含引用类型，它们仍然可以是可变的。解决这个问题的一种方法是使引用类型成为不可变的。C# 7.2 增加了对`readonly struct`和`ImmutableStruct`的支持。因此，即使我们的结构包含引用类型，我们现在也可以使用这些新的 C# 7.2 构造来使具有引用类型的结构成为不可变的。

现在，让我们来看一个纯函数的例子。对象属性的唯一设置方式是通过构造函数在构造时进行。这个类是一个`Player`类，其唯一工作是保存玩家的姓名和他们的最高分。提供了一个方法来更新玩家的最高分：

```cs
public class Player
{
    public string PlayerName { get; }
    public long HighScore { get; }

    public Player(string playerName, long highScore)
    {
        PlayerName = playerName;
        HighScore = highScore;
    }

    Public Player UpdateHighScore(long highScore)
    {
        return new Player(PlayerName, highScore);
    }

}
```

请注意，`UpdateHighScore`方法不会更新`HighScore`属性。相反，它通过传入已在类中设置的`PlayerName`变量和方法参数`highScore`来实例化并返回一个新的`Player`类。您现在已经看到了一个非常简单的示例，说明如何在不改变其状态的情况下编写软件。

函数式编程是一个非常庞大的主题，对于过程式和面向对象的程序员来说，它需要进行思维转变，这可能非常困难。由于这超出了本书的范围（深入探讨函数式编程的主题），我们鼓励您自行查阅 PacktPub 提供的函数式编程资源。

Packt 有一些非常好的书籍和视频，专门教授功能编程的顶级知识。您将在本章末尾的*进一步阅读*部分找到一些 Packt 功能编程资源的链接。

在我们继续之前，我们将看一些 LINQ 示例，因为 LINQ 是 C#中函数式编程的一个例子。有一个例子数据集会很有帮助。以下代码构建了一个供应商和产品列表。我们将首先编写`Product`结构：

```cs
public struct Product
{
    public string Vendor { get; }
    public string ProductName { get; }
    public Product(string vendor, string productName)
    {
        Vendor = vendor;
        ProductName = productName;
    }
}
```

现在我们有了结构体，我们将在`GetProducts()`方法中添加一些示例数据：

```cs
public static List<Product> GetProducts()
{
    return new List<Products>
    {
        new Product("Microsoft", "Microsoft Office"),
        new Product("Oracle", "Oracle Database"),
        new Product("IBM", "IBM DB2 Express"),
        new Product("IBM", "IBM DB2 Express"),
        new Product("Microsoft", "SQL Server 2017 Express"),
        new Product("Microsoft", "Visual Studio 2019 Community Edition"),
        new Product("Oracle", "Oracle JDeveloper"),
        new Product("Microsoft", "Azure"),
        new Product("Microsoft", "Azure"),
        new Product("Microsoft", "Azure Stack"),
        new Product("Google", "Google Cloud Platform"),
        new Product("Amazon", "Amazon Web Services")
    };
}
```

最后，我们可以开始在我们的列表上使用 LINQ。在前面的示例中，我们将获得一个按供应商名称排序的产品的不同列表，并打印出结果：

```cs
class Program
{
    static void Main(string[] args)
    {
        var vendors = (from p in GetProducts()
                        select p.Vendor)
                        .Distinct()
                        .OrderBy(x => x);
        foreach(var vendor in vendors)
            Console.WriteLine(vendor);
        Console.ReadKey();
    }
}
```

在这里，我们通过调用`GetProducts()`获取供应商列表，并仅选择`Vendor`列。然后，我们过滤列表，使其只包括一个供应商，通过调用`Distinct()`方法。然后，通过调用`OrderBy(x => x)`按字母顺序对供应商列表进行排序，其中`x`是供应商的名称。在获得排序后的不同供应商列表后，我们遍历列表并打印供应商的名称。最后，我们等待用户按任意键退出程序。

函数式编程的一个好处是，您的方法比其他类型的编程方法要小得多。接下来，我们将看一下为什么保持方法小巧是有益的，以及我们可以使用的技术，包括函数式编程。

# 保持方法的小巧

在编写干净和可读的代码时，保持方法小巧是很重要的。在 C#世界中，最好将方法保持在*10 行以下*。最佳长度不超过*4 行*。保持方法小巧的一个好方法是考虑是否应该捕获错误或将其传递到调用堆栈的更高层。通过防御性编程，您可能会变得过于防御，这可能会增加您发现自己编写的代码量。此外，捕获错误的方法将比不捕获错误的方法更长。

让我们考虑以下可能会抛出`ArgumentNullException`的代码：

```cs
        public UpdateView(MyEntities context, DataItem dataItem)
        {
            InitializeComponent();
            try
            {
                DataContext = this;
                _dataItem = dataItem;
                _context = context;
                nameTextBox.Text = _dataItem.Name;
                DescriptionTextBox.Text = _dataItem.Description;
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
                throw;
            }
        }
```

在上面的代码中，我们可以清楚地看到有两个位置可能会引发`ArgumentNullException`。可能引发`ArgumentNullException`的第一行代码是`nameTextBox.Text = _dataItem.Name;`；可能引发相同异常的第二行代码是`DescriptionTextBox.Text = _dataItem.Description;`。我们可以看到异常处理程序在发生异常时捕获异常，将其写入控制台，然后简单地将其抛回堆栈。

请注意，从人类阅读的角度来看，有*8 行*代码形成了`try/catch`块。

你可以通过编写自己的参数验证器，用一行文本完全替换`try/catch`异常处理。为了解释这一点，我们将提供一个例子。

让我们首先看一下`ArgumentValidator`类。这个类的目的是抛出一个带有包含空参数的方法名称的`ArgumentNullException`：

```cs
using System;
namespace CH04.Validators
{
    internal static class ArgumentValidator
    {
        public static void NotNull(
            string name, 
            [ValidatedNotNull] object value
        )
        {
            if (value == null)
                throw new ArgumentNullException(name);
        }
    }

    [AttributeUsage(
        AttributeTargets.All, 
        Inherited = false, 
        AllowMultiple = true)
    ]
    internal sealed class ValidatedNotNullAttribute : Attribute
    {
    }
}
```

现在我们有了我们的空验证类，我们可以对我们的方法中的空值参数执行新的验证方式。所以，让我们看一个简单的例子：

```cs
public ItemsUpdateView(
    Entities context, 
    ItemsView itemView
)
{
    InitializeComponent();
    ArgumentValidator.NotNull("ItemsUpdateView", itemView);
    // ### implementation omitted ###
}
```

正如你可以清楚地看到的，我们用一个一行代码替换了整个`try catch`块。当这个验证检测到空参数时，会抛出一个`ArgumentNullException`，阻止代码继续执行。这使得代码更容易阅读，也有助于调试。

现在，我们将看一下如何使用缩进格式化函数，使其易于阅读。

## 缩进代码

一个非常长的方法在任何时候都很难阅读和跟踪，特别是当你不得不多次滚动方法才能到达底部时。但是，如果方法没有正确格式化并且缩进级别不正确，那么这将是一个真正的噩梦。

如果你遇到任何格式不良的方法代码，那么作为专业程序员，在你做任何其他事情之前，要把代码整理好是你自己的责任。大括号之间的任何代码被称为**代码块**。代码块内的代码应该缩进一级。代码块内的代码块也应该缩进一级，如下面的例子所示：

```cs
public Student Find(List<Student> list, int id) 
{          
Student r = null;foreach (var i in list)          
{             
if (i.Id == id)                   
    r = i;          }          return r;     
}
```

上面的例子展示了糟糕的缩进和糟糕的循环编程。在这里，你可以看到正在搜索学生列表，以便找到并返回具有指定 ID 的学生，该 ID 作为参数传递。一些程序员感到恼火并降低了应用程序的性能，因为在上面的代码中，即使找到了学生，循环仍在继续。我们可以改进上面的代码的缩进和性能如下：

```cs
public Student Find(List<Student> list, int id) 
{          
    Student r = null;
    foreach (var i in list)          
    {             
        if (i.Id == id)                  
        {
            r = i; 
            break;         
        }      
    }
    return r;         
}
```

在上面的代码中，我们改进了格式，并确保代码正确缩进。我们在`for`循环中添加了`break`，以便在找到匹配项时终止`foreach`循环。

现在不仅代码更易读，而且性能也更好。想象一下，代码正在针对一个校园有 73,000 名学生的大学以及远程学习进行运行。考虑一下，如果学生与 ID 匹配是列表中的第一个，那么如果没有`break`语句，代码将不得不运行 72,999 次不必要的计算。你可以看到`break`语句对上面的代码性能有多大的影响。

我们将返回值保留在原始位置，因为编译器可能会抱怨并非所有代码路径都返回一个值。这也是我们添加`break`语句的原因。很明显，正确的缩进提高了代码的可读性，从而帮助程序员理解代码。这使程序员能够进行任何他们认为必要的更改。

# 避免重复

代码可以是**DRY**或**WET**。WET 代码代表**每次写**，是 DRY 的相反，DRY 代表**不要重复自己**。WET 代码的问题在于它是*bug*的完美候选者。假设您的测试团队或客户发现了一个 bug 并向您报告。您修复了 bug 并传递了它，但它会在您的计算机程序中遇到该代码的次数一样多次回来咬您。

现在，我们通过消除重复来 DRY 我们的 WET 代码。我们可以通过提取代码并将其放入方法中，然后以一种可访问所有需要它的计算机程序区域的方式将方法集中起来。

举个例子。假设您有一个费用项目集合，其中包含`Name`和`Amount`属性。现在，考虑通过`Name`获取费用项目的十进制`Amount`。

假设您需要这样做 100 次。为此，您可以编写以下代码：

```cs
var amount = ViewModel
    .ExpenseLines
    .Where(e => e.Name.Equals("Life Insurance"))
    .FirstOrDefault()
    .Amount;
```

没有理由您不能写相同的代码 100 次。但有一种方法可以只写一次，从而减少代码库的大小并提高您的生产力。让我们看看我们可以如何做到这一点：

```cs
public decimal GetValueByName(string name)
{
    return ViewModel
        .ExpenseLines
        .Where(e => e.Name.Equals(name))
        .FirstOrDefault()
        .Amount;
}
```

要从`ViewModel`中的`ExpenseLines`集合中提取所需的值，您只需将所需值的名称传递给`GetValueName(string name)`方法，如下面的代码所示：

```cs
var amount = GetValueByName("Life Insurance");
```

那一行代码非常易读，获取值的代码行包含在一个方法中。因此，如果出于任何原因（例如修复 bug）需要更改方法，您只需在一个地方修改代码。

编写良好的函数的下一个逻辑步骤是尽可能少地使用参数。在下一节中，我们将看看为什么我们不应该超过两个参数，以及如何处理参数，即使我们需要更多。

# 避免多参数

Niladic 方法是 C#中理想的方法类型。这种方法没有参数（也称为*参数*）。Monadic 方法只有一个参数。Dyadic 方法有两个参数。Triadic 方法有三个参数。具有三个以上参数的方法称为多参数方法。您应该尽量保持参数数量最少（最好少于三个）。

在 C#编程的理想世界中，您应尽力避免三参数和多参数方法。这不是因为它是糟糕的编程，而是因为它使您的代码更易于阅读和理解。具有大量参数的方法可能会给程序员带来视觉压力，并且也可能成为烦恼的根源。随着添加更多参数，IntelliSense 也可能变得难以阅读和理解。

让我们看一个更新用户帐户信息的多参数方法的不良示例：

```cs
public void UpdateUserInfo(int id, string username, string firstName, string lastName, string addressLine1, string addressLine2, string addressLine3, string addressLine3, string addressLine4, string city, string postcode, string region, string country, string homePhone, string workPhone, string mobilePhone, string personalEmail, string workEmail, string notes) 
{
    // ### implementation omitted ###
}
```

如`UpdateUserInfo`方法所示，代码难以阅读。我们如何修改该方法，使其从多参数方法转变为单参数方法？答案很简单 - 我们传入一个`UserInfo`对象。首先，在修改方法之前，让我们看一下我们的`UserInfo`类：

```cs
public class UserInfo
{
    public int Id { get;set; }
    public string Username { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string AddressLine1 { get; set; }
    public string AddressLine2 { get; set; }
    public string AddressLine3 { get; set; }
    public string AddressLine4 { get; set; }
    public string City { get; set; }
    public string Region { get; set; }
    public string Country { get; set; }
    public string HomePhone { get; set; }
    public string WorkPhone { get; set; }
    public string MobilePhone { get; set; }
    public string PersonalEmail { get; set; }
    public string WorkEmail { get; set; }
    public string Notes { get; set; }
}
```

现在我们有一个包含所有需要传递给`UpdateUserInfo`方法的信息的类。`UpdateUserInfo`方法现在可以从多参数方法转变为单参数方法，如下所示：

```cs
public void UpdateUserInfo(UserInfo userInfo)
{
    // ### implementation omitted ###
}
```

前面的代码看起来好多了吗？它更小，更易读。经验法则应该是少于三个参数，理想情况下是零。如果您的类遵守 SRP，则考虑实现*参数对象模式*，就像我们在这里所做的那样。

## 实施 SRP

您编写的所有对象和方法应该最多只有一个职责，而不再有其他。对象可以有多个方法，但这些方法在组合时应该都朝着它们所属的对象的单一目的工作。方法可以调用多个方法，每个方法都做不同的事情。但方法本身应该只做一件事。

一个了解和做得太多的方法被称为**上帝方法**。同样，一个了解和做得太多的对象被称为**上帝对象**。上帝对象和方法很难阅读、维护和调试。这样的对象和方法通常会多次重复相同的错误。擅长编程技艺的人会避免上帝对象和上帝方法。让我们看一个做了不止一件事的方法：

```cs
public void SrpBrokenMethod(string folder, string filename, string text, emailFrom, password, emailTo, subject, message, mediaType)
{
    var file = $"{folder}{filename}";
    File.WriteAllText(file, text);
    MailMessage message = new MailMessage();  
    SmtpClient smtp = new SmtpClient();  
    message.From = new MailAddress(emailFrom);  
    message.To.Add(new MailAddress(emailTo));  
    message.Subject = subject;  
    message.IsBodyHtml = true;  
    message.Body = message;  
    Attachment emailAttachment = new Attachment(file); 
    emailAttachment.ContentDisposition.Inline = false; 
    emailAttachment.ContentDisposition.DispositionType =        
        DispositionTypeNames.Attachment; 
    emailAttachment.ContentType.MediaType = mediaType;  
    emailAttachment.ContentType.Name = Path.GetFileName(filename); 
    message.Attachments.Add(emailAttachment);
    smtp.Port = 587;  
    smtp.Host = "smtp.gmail.com";
    smtp.EnableSsl = true;  
    smtp.UseDefaultCredentials = false;  
    smtp.Credentials = new NetworkCredential(emailFrom, password);  
    smtp.DeliveryMethod = SmtpDeliveryMethod.Network;  
    smtp.Send(message);
}
```

`SrpBrokenMethod`显然做了不止一件事，因此它违反了 SRP。我们现在将这个方法分解为多个只做一件事的较小方法。我们还将解决该方法的多参数性质的问题。

在我们开始将方法分解为只做一件事的较小方法之前，我们需要查看方法执行的所有操作。该方法首先将文本写入文件。然后创建电子邮件消息，分配附件，最后发送电子邮件。因此，我们需要以下方法：

+   将文本写入文件

+   创建电子邮件消息

+   添加电子邮件附件

+   发送电子邮件

查看当前方法，我们有四个参数传递给它来写入文本到文件：一个用于文件夹，一个用于文件名，一个用于文本，一个用于媒体类型。文件夹和文件名可以合并为一个名为`filename`的单个参数。如果`filename`和`folder`是在调用代码中分开使用的两个变量，则可以将它们作为单个插值字符串传递到方法中，例如`$"{folder}{filename}"`。

至于媒体类型，这可以在构造时私下设置在一个结构体内。我们可以使用该结构体来设置我们需要的属性，以便我们可以将该结构体作为单个参数传递进去。让我们看一下实现这一点的代码：

```cs
    public struct TextFileData
    {
        public string FileName { get; private set; }
        public string Text { get; private set; }
        public MimeType MimeType { get; }        

        public TextFileData(string filename, string text)
        {
            Text = text;
            MimeType = MimeType.TextPlain;
            FileName = $"{filename}-{GetFileTimestamp()}";
        }

        public void SaveTextFile()
        {
            File.WriteAllText(FileName, Text);
        }

        private static string GetFileTimestamp()
        {
            var year = DateTime.Now.Year;
            var month = DateTime.Now.Month;
            var day = DateTime.Now.Day;
            var hour = DateTime.Now.Hour;
            var minutes = DateTime.Now.Minute;
            var seconds = DateTime.Now.Second;
            var milliseconds = DateTime.Now.Millisecond;
            return $"{year}{month}{day}@{hour}{minutes}{seconds}{milliseconds}";
        }
    }
```

`TextFileData`构造函数通过调用`GetFileTimestamp()`方法并将其附加到`FileName`的末尾来确保`FileName`的值是唯一的。要保存文本文件，我们调用`SaveTextFile()`方法。请注意，`MimeType`在内部设置为`MimeType.TextPlain`。我们本可以简单地将`MimeType`硬编码为`MimeType = "text/plain";`，但使用`enum`的优势在于代码是可重用的，而且您不必记住特定`MimeType`的文本或在互联网上查找它的好处。现在，我们将编写`enum`并为`enum`值添加描述：

```cs
[Flags]
public enum MimeType
{
    [Description("text/plain")]
    TextPlain
}
```

好吧，我们有了我们的`enum`，但现在我们需要一种方法来提取描述，以便可以轻松地分配给一个变量。因此，我们将创建一个扩展类，它将使我们能够获取`enum`的描述。这使我们能够设置`MimeType`，如下所示：

```cs
MimeType = MimeType.TextPlain;
```

没有扩展方法，`MimeType`的值将为`0`。但是通过扩展方法，`MimeType`的值为`"text/plain"`。现在您可以在其他项目中重用这个扩展，并根据需要构建它。

我们将编写的下一个类是`Smtp`类，其职责是通过`Smtp`协议发送电子邮件：

```cs
    public class Smtp
    {
        private readonly SmtpClient _smtp;

        public Smtp(Credential credential)
        {
            _smtp = new SmtpClient
            {
                Port = 587,
                Host = "smtp.gmail.com",
                EnableSsl = true,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(
                 credential.EmailAddress, credential.Password),
                DeliveryMethod = SmtpDeliveryMethod.Network
            };
        }

        public void SendMessage(MailMessage mailMessage)
        {
            _smtp.Send(mailMessage);
        }
    }
```

`Smtp`类有一个构造函数，它接受一个`Credential`类型的参数。这个凭据用于登录到电子邮件服务器。服务器在构造函数中配置。当调用`SendMessage(MailMessage mailMessage)`方法时，消息被发送。

让我们编写一个`DemoWorker`类，将工作分成不同的方法：

```cs
    public class DemoWorker
    {
        TextFileData _textFileData;

        public void DoWork()        
        {
            SaveTextFile();
            SendEmail();
        }

        public void SendEmail()
        {
            Smtp smtp = new Smtp(new Credential("fakegmail@gmail.com", 
             "fakeP@55w0rd"));
            smtp.SendMessage(GetMailMessage());
        }

        private MailMessage GetMailMessage()
        {
            var msg = new MailMessage();
            msg.From = new MailAddress("fakegmail@gmail.com");
            msg.To.Add(new MailAddress("fakehotmail@hotmail.com"));
            msg.Subject = "Some subject";
            msg.IsBodyHtml = true;
            msg.Body = "Hello World!";
            msg.Attachments.Add(GetAttachment());
            return msg;
        }

        private Attachment GetAttachment()
        {
            var attachment = new Attachment(_textFileData.FileName);
            attachment.ContentDisposition.Inline = false;
            attachment.ContentDisposition.DispositionType = 
             DispositionTypeNames.Attachment;
            attachment.ContentType.MediaType = 
             MimeType.TextPlain.Description();
            attachment.ContentType.Name = 
             Path.GetFileName(_textFileData.FileName);
            return attachment;
        }

        private void SaveTextFile()
        {
            _textFileData = new TextFileData(
                $"{Environment.SpecialFolder.MyDocuments}attachment", 
                "Here is some demo text!"
            );
            _textFileData.SaveTextFile();
        }
    }
```

`DemoWorker`类展示了发送电子邮件消息的更清晰版本。负责保存附件并通过电子邮件作为附件发送的主要方法称为`DoWork()`。这个方法只包含两行代码。第一行调用`SaveTextFile()`方法，而第二行调用`SendEmail()`方法。

`SaveTextFile()`方法创建一个新的`TextFileData`结构，并传入文件名和一些文本。然后调用`TextFileData`结构中的`SaveTextFile()`方法，负责将文本保存到指定的文件中。

`SendEmail()`方法创建一个新的`Smtp`类。`Smtp`类有一个`Credential`参数，而`Credential`类有两个字符串参数用于电子邮件地址和密码。电子邮件和密码用于登录 SMTP 服务器。一旦 SMTP 服务器被创建，就会调用`SendMessage(MailMessage mailMessage)`方法。

这个方法需要传入一个`MailMessage`对象。因此，我们有一个名为`GetMailMethod()`的方法，它构建一个`MailMessage`对象，然后将其传递给`SendMessage(MailMessage mailMessage)`方法。`GetMailMethod()`通过调用`GetAttachment()`方法向`MailMessage`添加附件。

从这些修改中可以看出，我们的代码现在更加简洁和易读。这是良好质量的代码的关键，它必须易于阅读和理解。这就是为什么你的方法应该尽可能小而干净，参数尽可能少的原因。

你的方法是否违反了 SRP？如果是，你应该考虑将方法分解为尽可能多的方法来承担责任。这就结束了关于编写清晰函数的章节。现在是时候总结你所学到的知识并测试你的知识了。

# 总结

在本章中，您已经看到函数式编程如何通过不修改状态来提高代码的安全性，这可能会导致错误，特别是在多线程应用程序中。通过保持方法小而有意义的名称，以及不超过两个参数，您已经看到您的代码有多么清晰和易于阅读。您还看到了我们如何消除代码中的重复部分以及这样做的好处。易于阅读的代码比难以阅读和解释的代码更容易维护和扩展！

我们现在将继续并看一下异常处理的主题。在下一章中，您将学习如何适当地使用异常处理，编写自己的自定义 C#异常以提供有意义的信息，并编写避免引发`NullPointerExceptions`的代码。

# 问题

1.  你如何称呼一个没有参数的方法？

1.  你如何称呼一个有一个参数的方法？

1.  你如何称呼一个有两个参数的方法？

1.  你如何称呼一个有三个参数的方法？

1.  你如何称呼一个有超过三个参数的方法？

1.  应该避免哪两种方法类型，为什么？

1.  用通俗的语言来说，什么是函数式编程？

1.  函数式编程有哪些优点？

1.  函数式编程的一个缺点是什么？

1.  什么是 WET 代码，为什么应该避免？

1.  什么是 DRY 代码，为什么应该使用它？

1.  你如何去除 WET 代码中的重复部分？

1.  为什么方法应该尽可能小？

1.  如何在不实现`try/catch`块的情况下实现验证？

# 进一步阅读

以下是一些额外资源，让您可以深入了解 C#函数式编程的领域：

+   *Functional C#* by Wisnu Anggoro: [`www.packtpub.com/application-development/functional-c`](https://www.packtpub.com/application-development/functional-c)。这本书致力于 C#函数式编程，如果您想了解更多，这是一个很好的起点。

+   《C#中的函数式编程》由 Jovan Poppavic（微软）编写：[`www.codeproject.com/Articles/375166/Functional-programming-in-Csharp`](https://www.codeproject.com/Articles/375166/Functional-programming-in-Csharp)。这是一篇关于函数式 C#编程的深度文章。它包含了图表，并且有 5 星的评分。


# 第五章：异常处理

在上一章中，我们看了函数。尽管程序员尽力编写健壮的代码，但函数最终会产生异常。这可能是由于许多原因，例如缺少文件或文件夹，空值或空值，无法写入位置，或者用户被拒绝访问。因此，在本章中，您将学习使用异常处理产生清晰的 C#代码的适当方法。首先，我们将从算术`OverflowExceptions`的检查和未经检查的异常开始。我们将看看它们是什么，为什么使用它们，以及它们在代码中的一些示例。

然后，我们将看看如何避免`NullPointerReference`异常。之后，我们将研究为特定类型的异常实现特定业务规则。在对异常和异常业务规则有了新的理解之后，我们将开始构建自己的自定义异常，然后最后看看为什么我们不应该使用异常来控制计算机程序的流程。

在本章中，我们将涵盖以下主题：

+   检查和未经检查的异常

+   避免`NullPointerExceptions`

+   业务规则异常

+   异常应提供有意义的信息

+   构建自定义异常

在本章结束时，您将具备以下技能：

+   您将能够理解 C#中的检查和未经检查的异常，以及它们的原因。

+   您将能够理解什么是`OverflowException`以及如何在编译时捕获它们。

+   您将了解什么是`NullPointerExceptions`以及如何避免它们。

+   您将能够编写自己的自定义异常，为客户提供有意义的信息，并帮助您和其他程序员轻松识别和解决引发的任何问题。

+   您将能够理解为什么不应该使用异常来控制程序流程。

+   您将知道如何使用 C#语句和布尔检查来替换业务规则异常，以控制程序流程。

# 检查和未经检查的异常

在未经检查的模式下，算术溢出会被*忽略*。在这种情况下，无法分配给目标类型的高阶位将从结果中丢弃。

默认情况下，C#在运行时执行非常量表达式时处于未经检查的上下文中。但是编译时常量表达式*始终*默认进行检查。在检查模式下遇到算术溢出时，会引发`OverflowException`。未经检查异常被使用的一个原因是为了提高性能。检查异常可能会稍微降低方法的性能。

经验法则是确保在检查上下文中执行算术运算。任何算术溢出异常都将被视为编译时错误，然后您可以在发布代码之前修复它们。这比发布代码然后不得不修复客户运行时错误要好得多。

在未经检查的模式下运行代码是危险的，因为您对代码进行了假设。假设并非事实，它们可能导致在运行时引发异常。运行时异常会导致客户满意度降低，并可能产生严重的后续异常，以某种方式对客户产生负面影响。

允许应用程序继续运行，即使发生了溢出异常，从商业角度来看是非常危险的。原因在于数据可能会处于不可逆转的无效状态。如果数据是关键的客户数据，那么这对企业来说可能会非常昂贵，你不希望承担这样的责任。

考虑以下代码。这段代码演示了在客户银行业务中未经检查的溢出有多糟糕：

```cs
private static void UncheckedBankAccountException()
{
    var currentBalance = int.MaxValue;
    Console.WriteLine($"Current Balance: {currentBalance}");
    currentBalance = unchecked(currentBalance + 1);
    Console.WriteLine($"Current Balance + 1 = {currentBalance}");
    Console.ReadKey();
}
```

想象一下，当客户看到将 1 英镑加到他们的银行余额 2,147,483,647 英镑时，他们的脸上会有多么恐慌！

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/a108b152-4768-43c9-acf0-164699f74f0b.png)

现在，是时候用一些代码示例演示检查和未检查异常了。首先，启动一个新的**控制台应用程序**并声明一些变量：

```cs
static byte y, z;
```

前面的代码声明了两个字节，我们将在算术代码示例中使用。现在，添加`CheckedAdd()`方法。如果在添加两个数字时遇到算术溢出导致的结果太大无法存储为字节，此方法将引发一个检查过的`OverflowException`：

```cs
private static void CheckedAdd()
{
    try
    {
        Console.WriteLine("### Checked Add ###");
        Console.WriteLine($"x = {y} + {z}");
        Console.WriteLine($"x = {checked((byte)(y + z))}");
    }
    catch (OverflowException oex)
    {
        Console.WriteLine($"CheckedAdd: {oex.Message}");
    }
}
```

然后，编写`CheckedMultiplication()`方法。如果在乘法过程中检测到算术溢出，导致的数字大于一个字节，将引发检查过的`OverflowException`：

```cs
private static void CheckedMultiplication()
{
    try
    {
        Console.WriteLine("### Checked Multiplication ###");
        Console.WriteLine($"x = {y} x {z}");
        Console.WriteLine($"x = {checked((byte)(y * z))}");
    }
    catch (OverflowException oex)
    {
        Console.WriteLine($"CheckedMultiplication: {oex.Message}");
    }
}
```

接下来，添加`UncheckedAdd()`方法。此方法将忽略由于加法而发生的任何溢出，因此不会引发`OverflowException`。溢出的结果将存储为一个字节，但值将是不正确的：

```cs
private static void UncheckedAdd()
{
    try
    {
         Console.WriteLine("### Unchecked Add ###");
         Console.WriteLine($"x = {y} + {z}");
         Console.WriteLine($"x = {unchecked((byte)(y + z))}");
    }
    catch (OverflowException oex)
    {
         Console.WriteLine($"CheckedAdd: {oex.Message}");
    }
}
```

现在，我们添加`UncheckedMultiplication()`方法。当遇到溢出时，此方法不会抛出`OverflowException`。异常将被简单地忽略。这将导致一个不正确的数字被存储为字节：

```cs
private static void UncheckedMultiplication()
{
    try
    {
         Console.WriteLine("### Unchecked Multiplication ###");
         Console.WriteLine($"x = {y} x {z}");
         Console.WriteLine($"x = {unchecked((byte)(y * z))}");
    }
    catch (OverflowException oex)
    {
        Console.WriteLine($"CheckedMultiplication: {oex.Message}");
    }
}
```

最后，是时候修改我们的`Main(string[] args)`方法，以便我们可以初始化变量并执行方法。在这里，我们将最大值添加到`y`变量和`2`添加到`z`变量。然后，我们运行`CheckedAdd()`和`CheckedMultiplication()`方法，这两个方法都会生成`OverflowException()`。这是因为`y`变量包含了一个字节的最大值。

因此，通过添加或乘以`2`，您超出了存储变量所需的地址空间。接下来，我们将运行`UncheckedAdd()`和`UncheckedMultiplication()`方法。这两种方法都忽略溢出异常，将结果分配给`x`变量，并忽略任何溢出的位。最后，我们在用户按下任意键时打印一条消息，然后退出：

```cs
static void Main(string[] args)
{
    y = byte.MaxValue;
    z = 2;
    CheckedAdd();
    CheckedMultiplication();
    UncheckedAdd();
    UncheckedMultiplication();
    Console.WriteLine("Press any key to exit.");
    Console.ReadLine();
}
```

当我们运行前面的代码时，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/575def5c-092b-4eda-b195-6fc08d6d56bd.png)

如您所见，当我们使用检查异常时，当遇到`OverflowException`时会引发异常。但当我们使用未检查异常时，不会引发异常。

从前面的截图可以看出，意外值可能导致问题，并且使用未检查异常可能导致某些行为。因此，在执行算术运算时的经验法则必须始终使用检查异常。

现在，让我们继续看一个程序员经常遇到的非常常见的异常，称为`NullPointerException`。

# 避免 NullPointerExceptions

`NullReferenceException`是大多数程序员经历过的常见异常。当尝试访问`null`对象的属性或方法时，会引发此异常。

为了防止计算机程序崩溃，程序员们常用的做法是使用`try{...}catch (NullReferenceExceptionre){...}`块。这是防御性编程的一部分。但问题是，很多时候错误只是*记录*和*重新抛出*。此外，还进行了很多不必要的计算。

处理`ArgumentNullExceptions`的一个更好的方法是实现`ArgumentNullValidator`。方法的参数通常是`null`对象的来源。在使用参数之前测试方法的参数并且如果发现它们因任何原因无效，则抛出适当的`Exception`是有意义的。在`ArgumentNullValidator`的情况下，您将把此验证器放在方法的顶部，然后测试每个参数。如果发现任何参数为`null`，则会抛出`NullReferenceException`。这将节省计算并消除了将方法代码包装在`try...catch`块中的需要。

为了明确事物，我们将编写`ArgumentNullValidator`并在一个方法中使用它来测试方法的参数：

```cs
public class Person
{
    public string Name { get; }
    public Person(string name)
    {
         Name = name;
    }
}
```

在上面的代码中，我们创建了一个名为`Name`的只读属性的`Person`类。这将是我们将用于传递到示例方法中以引发`NullReferenceException`的对象。接下来，我们将为验证器创建我们的`Attribute`，称为`ValidatedNotNullAttribibute`：

```cs
[AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
internal sealed class ValidatedNotNullAttribute : Attribute { }
```

现在我们有了我们的`Attribute`，是时候编写验证器了：

```cs
internal static class ArgumentNullValidator
{
    public static void NotNull(string name, 
     [ValidatedNotNull] object value)
    {
        if (value == null)
        {
            throw new ArgumentNullException(name);
        }
    }
}
```

`ArgumentNullValidator`接受两个参数：

+   对象的名称

+   对象本身

检查对象是否为`null`。如果是`null`，则抛出`ArgumentNullException`，并传入对象的名称。

以下方法是我们的`try/catch`示例方法。请注意，我们记录了一条消息并抛出了异常。然而，我们没有使用声明的异常参数，因此按理说应该将其删除。您会经常在代码中看到这种情况。这是不必要的，应该删除以整理代码：

```cs
private void TryCatchExample(Person person)
{
    try
    {
        Console.WriteLine($"Person's Name: {person.Name}");
    }
    catch (NullReferenceException nre)
    {
        Console.WriteLine("Error: The person argument cannot be null.");
        throw;
    }
}
```

接下来，我们将编写一个将使用`ArgumentNullValidator`的示例方法。我们将其称为`ArgumentNullValidatorExample`：

```cs
private void ArgumentNullValidatorExample(Person person)
{
    ArgumentNullValidator.NotNull("Person", person);
    Console.WriteLine($"Person's Name: {person.Name}");
    Console.ReadKey();
}
```

请注意，我们已经从包括大括号在内的九行代码减少到了只有两行。我们也不会在验证之前尝试使用该值。现在我们需要做的就是修改我们的`Main`方法来运行这些方法。通过注释掉其中一个方法并运行程序来测试每个方法。这样做时，最好逐步执行代码以查看发生了什么。

以下是运行`TryCatchExample`方法的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/af29322d-9c55-4bf5-919a-2d18d325f98e.png)

以下是运行`ArgumentNullValidatorExample`的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/c1e41646-e39e-46c3-a8ea-43d813d5e302.png)

如果您仔细研究前面的屏幕截图，您会发现在使用`ArgumentNullValidatorExample`时我们只记录了一次错误。当使用`TryCatchExample`抛出异常时，异常被记录了两次。

第一次，我们有一个有意义的消息，但第二次，消息是*神秘的*。然而，由调用方法`Main`记录的异常并不神秘。事实上，它非常有帮助，因为它向我们显示了`Person`参数的值不能为`null`。

希望这一部分向您展示了在使用构造函数和方法之前检查参数的价值。通过这样做，您可以看到参数验证器如何减少您的代码，从而使其更易读。

现在，我们将看看如何为特定异常实现业务规则。

# 业务规则异常

技术异常是由计算机程序由于程序员的错误和/或环境问题（例如磁盘空间不足）而抛出的异常。

但是业务规则异常是不同的。业务规则异常意味着这种行为是预期的，并且用于控制程序流程，而实际上，异常应该是程序的正常流程的例外，而不是方法的预期输出。

例如，想象一个在 ATM 机上从账户中取出 100 英镑的人，账户里没有钱，也没有透支的能力。ATM 接受用户的 100 英镑取款请求，因此发出`Withdraw(100);`命令。`Withdraw`方法检查余额，发现账户资金不足，因此抛出`InsufficientFundsException()`。

您可能认为拥有这样的异常是一个好主意，因为它们是明确的，并有助于识别问题，以便在收到这样的异常时执行非常具体的操作——但不是！这不是一个好主意。

在这种情况下，当用户提交请求时，应检查所请求的金额是否可以取款。如果可以，那么交易应该继续进行，如用户所请求的那样。但是，如果验证检查确定无法继续进行交易，那么程序应该按照正常的程序流程取消交易，并通知发出请求的用户，而不引发异常。

我们刚刚看到的取款情景表明，程序员已经正确考虑了程序的正常流程和不同的结果。程序流程已经适当地使用布尔检查编码，以允许成功的取款交易并防止不允许的取款交易。

让我们看看如何使用**业务规则异常**（**BREs**）来实现不允许透支的银行账户的取款。然后，我们将看看如何实现相同的场景，但是使用正常的程序流程而不是使用 BREs。

启动一个新的控制台应用程序，并添加两个名为`BankAccountUsingExceptions`和`BankAccountUsingProgramFlow`的文件夹。使用以下代码更新您的`void Main(string[] args)`方法：

```cs
private static void Main(string[] args)
{
    var usingBrExceptions = new UsingBusinessRuleExceptions();
    usingBrExceptions.Run();
    var usingPflow = new UsingProgramFlow();
    usingPflow.Run();
}
```

前面的代码运行每个情景。`UsingBusinessRuleExceptions()`演示了异常作为控制程序流程的预期输出的使用，而`UsingProgramFlow()`演示了在不使用异常条件的情况下控制程序流程的干净方式。

现在我们需要一个类来保存我们的活期账户信息。因此，在您的 Visual Studio 控制台项目中添加一个名为`CurrentAccount`的类，如下所示：

```cs
internal class CurrentAccount
{
    public long CustomerId { get; }
    public decimal AgreedOverdraft { get; }
    public bool IsAllowedToGoOverdrawn { get; }
    public decimal CurrentBalance { get; }
    public decimal AvailableBalance { get; private set; }
    public int AtmDailyLimit { get; }
    public int AtmWithdrawalAmountToday { get; private set; }
}
```

该类的属性只能通过构造函数内部或外部设置。现在，添加一个以客户标识符作为唯一参数的构造函数：

```cs
public CurrentAccount(long customerId)
{
    CustomerId = customerId;
    AgreedOverdraft = GetAgreedOverdraftLimit();
    IsAllowedToGoOverdrawn = GetIsAllowedToGoOverdrawn();
    CurrentBalance = GetCurrentBalance();
    AvailableBalance = GetAvailableBalance();
    AtmDailyLimit = GetAtmDailyLimit();
    AtmWithdrawalAmountToday = 0;
}
```

当前账户构造函数初始化所有属性。如前面的代码所示，一些属性是使用方法初始化的。让我们依次实现每个方法：

```cs
private static decimal GetAgreedOverdraftLimit()
{
    return 0;
}
```

`GetAgreedOverdraftLimit()`返回账户上约定的透支限额的值。在本例中，它被硬编码为零。但在实际情况中，它将从配置文件或其他数据存储中提取实际数字。这将允许非技术用户更新约定的透支限额，而无需开发人员更改代码。

`GetIsAllowedToGoOverdrawn()`确定账户是否可以透支，即使没有经过同意，有些银行是允许的。在这种情况下，我们只需返回`false`来确定账户无法透支：

```cs
private static bool GetIsAllowedToGoOverdrawn()
{
    return false;
}
```

为了本例的目的，我们将在`GetCurrentBalance()`方法中将用户的账户余额设置为 250 英镑：

```cs
private static decimal GetCurrentBalance()
{
    return 250.00M;
}
```

作为我们示例的一部分，我们需要确保即使用户的账户余额为 250 英镑，但其可用余额小于该金额，他们也无法取出超过可用余额的金额，因为这将导致透支。为此，我们将在`GetAvailableBalance()`方法中将可用余额设置为 173.64 英镑：

```cs
private static decimal GetAvailableBalance()
{
    return 173.64M;
}
```

在英国，ATM 机要么允许您最多取款 200 英镑，要么允许您最多取款 250 英镑。因此，在`GetAtmDailyLimit()`方法中，我们将将 ATM 每日限额设置为 250 英镑：

```cs
private static int GetAtmDailyLimit()
{
    return 250;
}
```

让我们通过使用业务规则异常和正常程序流程来处理程序中的不同条件，编写我们两种情景的代码。

## 示例 1 - 使用业务规则异常处理条件

向项目添加一个名为 `UsingBusinessRuleExceptions` 的新类，然后添加以下 `Run()` 方法：

```cs
public class UsingBusinessRuleExceptions
{
    public void Run()
    {
        ExceedAtmDailyLimit();
        ExceedAvailableBalance();
    }
}
```

`Run()` 方法调用两个方法：

+   第一个方法称为 `ExceedAtmDailyLimit()`。该方法故意超出了允许从 ATM 提取的每日金额。`ExceedAtmDailyLimit()` 导致 `ExceededAtmDailyLimitException`。

+   其次，调用 `ExceedAvailableBalance()` 方法，该方法故意引发 `InsufficientFundsException`。添加 `ExceedAtmDailyLimit()` 方法：

```cs
private void ExceedAtmDailyLimit()
{
     try
     {
            var customerAccount = new CurrentAccount(1);
            customerAccount.Withdraw(300);
            Console.WriteLine("Request accepted. Take cash and card.");
      }
      catch (ExceededAtmDailyLimitException eadlex)
      {
            Console.WriteLine(eadlex.Message);
      }
}
```

`ExceedAtmDailyLimit()` 方法创建一个新的 `CustomerAccount` 方法，并传入客户的标识符，表示为数字 `1`。然后，尝试提取 £300。如果请求成功，那么将在控制台窗口打印消息 `Request accepted. Take cash and card.`。如果请求失败，那么该方法会捕获 `ExceededAtmLimitException` 并将异常消息打印到控制台窗口：

```cs
private void ExceedAvailableBalance()
{
    try
    {
        var customerAccount = new CurrentAccount(1);
        customerAccount.Withdraw(180);
        Console.WriteLine("Request accepted. Take cash and card.");
    }
    catch (InsufficientFundsException ifex)
    {
        Console.WriteLine(ifex.Message);
    }
}
```

`ExceedAvailableBalance()` 方法创建一个新的 `CurrentAccount` 并传入客户标识符，表示为数字 `1`。然后尝试提取 £180。由于 `GetAvailableMethod()` 返回 £173.64，该方法导致 `InsufficientFundsException`。

通过这样，我们已经看到了如何使用业务规则异常来管理不同的条件。现在，让我们看看如何以正常的程序流程管理相同的条件，而不使用异常。

## 示例 2 - 使用正常程序流程处理条件

添加一个名为 `UsingProgramFlow` 的类，然后向其中添加以下代码：

```cs
public class UsingProgramFlow
{
    private int _requestedAmount;
    private readonly CurrentAccount _currentAccount;

    public UsingProgramFlow()
    {
        _currentAccount = new CurrentAccount(1);
    }
}
```

在 `UsingProgramFlow` 类的构造函数中，我们将创建一个新的 `CurrentAccount` 类并传入客户标识符。接下来，我们将添加 `Run()` 方法：

```cs
public void Run()
{
    _requestedAmount = 300;
    Console.WriteLine($"Request: Withdraw {_requestedAmount}");
    WithdrawMoney();
    _requestedAmount = 180;
    Console.WriteLine($"Request: Withdraw {_requestedAmount}");
    WithdrawMoney();
    _requestedAmount = 20;
    Console.WriteLine($"Request: Withdraw {_requestedAmount}");
    WithdrawMoney();
}
```

`Run()` 方法三次设置 `_requestedAmount` 变量。每次这样做时，在调用 `WithdrawMoney()` 方法之前，将在控制台窗口上打印提取的金额的消息。现在，添加 `ExceedsDailyLimit()` 方法：

```cs
private bool ExceedsDailyLimit()
{
    return (_requestedAmount > _currentAccount.AtmDailyLimit)
        || (_requestedAmount + _currentAccount.AtmWithdrawalAmountToday > _currentAccount.AtmDailyLimit);
}
```

`ExceedDailyLimit()` 方法如果 `_requestedAmount` 超过每日 ATM 提款限额，则返回 `true`。否则，返回 false。现在，添加 `ExceedsAvailableBalance()` 方法：

```cs
private bool ExceedsAvailableBalance()
{
    return _requestedAmount > _currentAccount.AvailableBalance;
}
```

`ExceedsAvailableBalance()` 方法如果请求的金额超过了可提取的金额，则返回 `true`。最后，我们来到最后一个方法，称为 `WithdrawMoney()`：

```cs
private void WithdrawMoney()
{
    if (ExceedsDailyLimit())
        Console.WriteLine("Cannot exceed ATM Daily Limit. Request denied.");
    else if (ExceedsAvailableBalance())
        Console.WriteLine("Cannot exceed available balance. You have no agreed 
         overdraft facility. Request denied.");
    else
        Console.WriteLine("Request granted. Take card and cash.");
}
```

`WithdrawMoney()` 方法不使用 BREs 来控制程序流程。相反，该方法调用布尔验证方法来确定程序流程。如果 `_requestedAmount` 超过了由调用 `ExceedsDailyLimit()` 确定的 ATM 每日限额，则请求被拒绝。否则，将进行下一个检查，以查看 `_requestedAmount` 是否超过了 `AvailableBalance`。如果是，则拒绝请求。如果不是，则执行授予请求的代码。

我希望您能看到，使用可用逻辑控制程序的流程比期望抛出异常更有意义。代码更清晰，更正确。异常应该保留给不属于业务需求的特殊情况。

当正确引发适当的异常时，对它们提供有意义的信息非常重要。晦涩的错误消息对任何人都没有好处，实际上可能会给最终用户或开发人员增加不必要的压力。现在，我们将看看如何在计算机程序引发的任何异常中提供有意义的信息。

# 异常应该提供有意义的信息

声明“没有错误”并终止程序的关键错误根本没有用。我亲身经历过实际的“没有错误”关键异常。这是一个阻止应用程序工作的关键异常。然而，消息告诉我们没有错误。好吧，如果没有错误，那么为什么屏幕上会出现关键异常警告？为什么我无法继续使用应用程序？显然，要引发关键异常，必须在某个地方发生了关键异常。但是在哪里，为什么？

当这些异常深植于你正在使用的框架或库中（你无法控制），并且你无法访问源代码时，这样的异常会变得更加恼人。这些异常导致程序员因沮丧而说出负面的话。我曾经有过这样的经历，也见过同事有同样的情况。沮丧的主要原因之一是代码引发了错误，用户或程序员已经被通知，但没有有用的信息来建议问题所在或查找位置，甚至采取什么补救措施。

异常必须提供对技术挑战者尤其友好的信息。在开发阅读障碍测试和评估软件的时候，我和许多教师和 IT 技术人员一起工作过。

可以说，许多各种能力水平的 IT 技术人员和教师在回应软件异常消息时经常一无所知。

我支持的软件的许多最终用户一直困惑的一个错误是**错误 76：路径未找到**。这是一个古老的微软异常，早在 Windows 95 时代就存在，今天仍然存在。对于引发此异常的软件的最终用户来说，错误消息是完全无用的。最终用户知道哪个文件和位置找不到，并知道应采取什么步骤来解决问题将是有用的。

一个潜在的解决方案是实施以下步骤：

1.  检查位置是否存在。

1.  如果位置不存在或访问被拒绝，则根据需要显示文件保存或打开对话框。

1.  将用户选择的位置保存到配置文件以供将来使用。

1.  在同一段代码的后续运行中，使用用户设置的位置。

但是，如果你要保留错误消息，那么你至少应该提供缺失的位置和/或文件的名称。

有了这些说法，现在是时候看看我们如何构建自己的异常，以提供对最终用户和程序员有用的信息了。但请注意：你必须小心，不要透露敏感信息或数据。

# 构建自定义异常

Microsoft .NET Framework 已经有许多可以引发的异常，你可以捕获。但可能会有一些情况，你需要一个提供更详细信息或在术语上更加用户友好的自定义异常。

因此，我们现在将看看构建自定义异常的要求是什么。构建自定义异常其实非常简单。你只需要给你的类一个以`Exception`结尾的名称，并继承自`System.Exception`。然后，你需要添加三个构造函数，如下面的代码示例所示：

```cs
    public class TickerListNotFoundException : Exception
    {
        public TickerListNotFoundException() : base()
        {
        }

        public TickerListNotFoundException(string message)
            : base(message)
        {
        }

        public TickerListNotFoundException(
            string message, 
            Exception innerException
        )
            : base(message, innerException)
        {
        }
    }
```

`TickerListNotFoundException`继承自`System.Exception`类。它包含三个必需的构造函数：

+   一个默认构造函数

+   一个接受异常消息文本字符串的构造函数

+   一个接受异常消息文本字符串和`Exception`对象的构造函数

现在，我们将编写并执行三种方法，这些方法将使用我们自定义异常的每个构造函数。您将能够清楚地看到使用自定义异常来创建更有意义的异常的好处：

```cs
static void Main(string[] args)
{
    ThrowCustomExceptionA();
    ThrowCustomExceptionB();
    ThrowCustomExceptionC();
}
```

上述代码显示了我们更新的`Main(string[] args)`方法，该方法已更新以依次执行我们的三种方法。这将测试每个自定义异常的构造函数：

```cs
private static void ThrowCustomExceptionA()
{
    try
    {
        Console.WriteLine("throw new TickerListNotFoundException();");
        throw new TickerListNotFoundException();
    }
    catch (Exception tlnfex)
    {
        Console.WriteLine(tlnfex.Message);
    }
}
```

`ThrowCustomExceptionA()`方法通过使用默认构造函数抛出一个新的`TickerListNotFoundException`。当您运行代码时，打印到控制台窗口的消息会通知用户已抛出`CH05_CustomExceptions.TickerListNotFoundException`：

```cs
private static void ThrowCustomExceptionB()
{
    try
    {
        Console.WriteLine("throw new 
         TickerListNotFoundException(Message);");
        throw new TickerListNotFoundException("Ticker list not found.");
    }
    catch (Exception tlnfex)
    {
        Console.WriteLine(tlnfex.Message);
    }
}
```

`ThrowCustomExceptionB()`通过使用接受文本消息的构造函数抛出一个新的`TickerListNotFoundException`。在这种情况下，最终用户被告知找不到股票列表：

```cs
private static void ThrowCustomExceptionC()
{
    try
    {
        Console.WriteLine("throw new TickerListNotFoundException(Message, 
         InnerException);");
        throw new TickerListNotFoundException(
            "Ticker list not found for this exchange.",
            new FileNotFoundException(
                "Ticker list file not found.",
                @"F:\TickerFiles\LSE\AimTickerList.json"
            )
        );
    }
    catch (Exception tlnfex)
    {
        Console.WriteLine($"{tlnfex.Message}\n{tlnfex.InnerException}");
    }
}
```

最后，`ThrowCustomExceptionC()`方法通过使用接受文本消息和内部异常的构造函数抛出`TickerListNotFoundException`。在我们的示例中，我们提供了一个有意义的消息，说明在该交易所找不到股票列表。内部的`FileNotFoundException`通过提供未找到的特定文件的名称来扩展这一点，这恰好是**伦敦证券交易所**（**LSE**）上的 Aim 公司的股票列表。

在这里，我们可以看到创建自定义异常的真正优势。但在大多数情况下，使用.NET Framework 中的内在异常应该就足够了。自定义异常的主要好处是它们是更有意义的异常，有助于调试和解决问题。

以下是 C#异常处理最佳实践的简要列表：

+   使用 try/catch/finally 块来从错误中恢复或释放资源。

+   处理常见条件而不抛出异常。

+   设计类以避免异常。

+   抛出异常而不是返回错误代码。

+   使用预定义的.NET 异常类型。

+   异常类的名称以单词**Exception**结尾。

+   在自定义异常类中包含三个构造函数。

+   确保在代码远程执行时可用异常数据。

+   使用语法正确的错误消息。

+   在每个异常中包含本地化的字符串消息。

+   在自定义异常中根据需要提供额外的属性。

+   放置 throw 语句，以便堆栈跟踪将有所帮助。

+   使用异常生成器方法。

+   当方法由于异常而无法完成时，恢复状态。

现在，是时候总结我们在异常处理方面学到的内容了。

# 总结

在本章中，您了解了已检查异常和未检查异常。已检查异常可以防止算术溢出条件进入任何生产代码，因为它们在编译时被捕获。未检查异常在编译时不被检查，通常会进入生产代码。这可能导致一些*难以跟踪*的错误在您的代码中通过意外数据值并最终导致抛出异常，导致程序崩溃。

然后，您了解了常见的`NullPointerException`以及如何使用自定义`Attribute`和`Validator`类来验证传入的参数，这些类放置在方法的顶部。这使您能够在验证失败时提供有意义的反馈。从长远来看，这将导致更健壮的程序。

然后，我们讨论了使用**BREs**来控制程序流程。您将学习如何通过期望异常输出来控制程序流程。然后，您将看到如何通过使用条件检查而不是使用异常来更好地控制计算机代码的流程。

讨论随后转向提供有意义的异常消息的重要性以及如何实现这一点；也就是说，通过编写继承自`Exception`类并实现所需的三个参数的自定义异常。通过提供的示例，你学会了如何使用自定义异常以及它们如何帮助更好地调试和解决问题。

所以，现在是时候通过回答一些问题来检验你所学到的知识了。如果你希望扩展本章学到的知识，还有进一步的阅读材料。

在下一章中，我们将学习单元测试以及如何先编写测试使其失败。然后，我们将编写足够的代码使测试通过，并在继续进行下一个单元测试之前对工作代码进行重构。

# 问题

1.  什么是已检查异常？

1.  什么是未检查异常？

1.  算术溢出异常是什么？

1.  什么是`NullPointerException`？

1.  你如何验证空参数以改进你的整体代码？

1.  BRE 代表什么？

1.  BRE 是好还是坏的实践，你为什么这样认为？

1.  BRE 的替代方案是什么，它是好还是坏，你为什么这样认为？

1.  你如何提供有意义的异常消息？

1.  编写自定义异常的要求是什么？

# 进一步阅读

+   [`docs.microsoft.com/en-us/dotnet/standard/exceptions/`](https://docs.microsoft.com/en-us/dotnet/standard/exceptions/)：这是处理和抛出.NET 异常的官方文档。

+   [`reflectoring.io/business-exceptions/`](https://reflectoring.io/business-exceptions/)：本文作者提供了五个原本认为 BRE 是一个好主意后认为它们是一个坏主意的原因。本文中还有一些本章未涉及的额外信息。

+   [`docs.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions`](https://docs.microsoft.com/en-us/dotnet/standard/exceptions/best-practices-for-exceptions)：微软关于 C#异常处理的最佳实践，包括代码示例和解释。


# 第六章：单元测试

之前，我们讨论了异常处理，如何正确实施以及在问题发生时对客户和程序员有何用处。在本章中，我们将看看程序员如何实施他们自己的质量保证（QA），以提供健壮的、不太可能在生产中产生异常的优质代码。

我们首先看看为什么应该测试我们自己的代码，以及什么样的测试才算是好测试。然后，我们看看 C#程序员可以使用的几种测试工具。然后，我们转向单元测试的三大支柱：失败、通过和重构。最后，我们看看多余的单元测试以及为什么它们应该被删除。

在本章中，我们将涵盖以下主题：

+   理解好测试的原因

+   理解测试工具

+   TDD 方法实践-失败、通过和重构

+   删除多余的测试、注释和无用代码

到本章结束时，你将获得以下技能：

+   能够描述良好代码的好处

+   能够描述不进行单元测试可能带来的潜在负面影响

+   能够安装和使用 MSTest 来编写和运行单元测试

+   能够安装和使用 NUnit 来编写和运行单元测试

+   能够安装和使用 Moq 来编写虚假（模拟）对象

+   能够安装和使用 SpecFlow 来编写符合客户规范的软件

+   能够编写失败的测试，然后使其通过，然后进行任何必要的重构

# 技术要求

要访问本章的代码文件，你可以访问以下链接：[`github.com/PacktPublishing/Clean-Code-in-C-/tree/master/CH06`](https://github.com/PacktPublishing/Clean-Code-in-C-/tree/master/CH06)。

# 理解好测试的原因

作为程序员，如果你对一个你觉得有趣的新开发项目感到高度积极，那是很不错的。但是，如果你被叫去处理一个错误，那会非常令人沮丧。如果不是你的代码，你对代码背后的完整理解也不足，那情况会更糟。如果是你自己的代码，你会有那种“我在想什么？”的时刻！你越是被叫去处理现有代码的维护工作，你就越能体会到进行单元测试的必要性。随着这种认识的增长，你开始看到学习测试方法和技术（如测试驱动开发（TDD）和行为驱动开发（BDD））的真正好处。

当你在其他人的代码上担任维护程序员一段时间后，你会看到好的、坏的和丑陋的代码。这样的代码可以让你积极地学习，让你明白编程的更好方式是什么，以及为什么不应该这样做。糟糕的代码会让你大喊“不。就是不行！”丑陋的代码会让你眼睛发红，头脑麻木。

直接与客户打交道，为他们提供技术支持，你会看到良好的客户体验对业务成功有多么关键。相反，你也会看到糟糕的客户体验如何导致一些非常沮丧、愤怒和极其粗鲁的客户；以及由于客户退款和因社交媒体和评论网站上的恶劣客户抱怨而导致销售迅速流失的情况。

作为技术负责人，你有责任进行技术代码审查，以确保员工遵守公司的编码准则和政策，分类错误，并协助项目经理管理你负责领导的人员。作为技术负责人，高水平的项目管理、需求收集和分析、架构设计和清晰的编程是很重要的。你还需要具备良好的人际交往能力。

你的项目经理只关心按照业务需求按时按预算交付项目。他们真的不关心你如何编写软件，只关心你能否按时按约定预算完成工作。最重要的是，他们关心发布的软件是否完全符合业务要求——不多也不少——以及软件是否达到非常高的专业水准，因为代码的质量同样可以提升或摧毁公司品牌。当项目经理对你很苛刻时，你知道业务正在给他们施加更大的压力。这种压力会传递给你。

作为技术负责人，你处于项目经理和项目团队之间。在日常工作中，你将主持 Scrum 会议并处理问题。这些问题可能是编码人员需要分析人员的资源，测试人员等待开发人员修复错误，等等。但最困难的工作将是进行同行代码审查并提供建设性反馈，以达到期望的结果而不冒犯人。这就是为什么你应该非常认真地对待清晰的编码，因为如果你批评一个人的代码，如果你自己的代码不合格，你就会招致反弹。此外，如果软件测试失败或出现大量错误，你将成为项目经理的责骂对象。

因此，作为技术负责人，鼓励 TDD 是一个好主意。最好的方法是*以身作则*。现在我知道，即使是受过学位教育和经验丰富的程序员也可能对 TDD 持保留态度。最常见的原因之一是学习和实践起来可能很困难，而且在代码变得更加复杂时，TDD 可能会显得更加耗时。我曾经从那些不喜欢单元测试的同事那里听到过这种反对意见。

但作为一个程序员，如果你想真正自信（一旦你编写了一段代码，你就能对其质量有信心，并且不会被退回来修复自己的错误），那么 TDD 是提升自己作为程序员水平的绝佳方式。当你学会在开始编程之前先进行测试，这很快就会成为*习惯性*。作为程序员，这样的习惯对你非常有用和有益，尤其是当你需要找新工作时，因为许多就业机会都在招聘具有 TDD 或 BDD 经验的人。

在编写代码时需要考虑的另一件事是，简单的、非关键的记事应用中的错误并不是世界末日。但如果你在国防或医疗领域工作呢？想象一下，一种大规模杀伤性武器被编程以朝特定方向击中敌方领土上的特定目标，但出现了问题，导致导弹瞄准了你盟友的平民人口。或者，想象一下，如果你的亲人因为医疗设备软件中的错误而处于危急生命支持状态，最终死亡，而这是你自己的错。然后，再想想，如果一架载有乘客的客机上的安全软件出现问题，导致飞机坠毁在人口密集区，造成机上和地面的人员伤亡，会发生什么？

软件越关键，就越需要认真对待单元测试技术（如 TDD 和 BDD）。我们将在本章后面讨论 BDD 和 TDD 工具。在编写软件时，想象一下如果你是客户，如果你编写的代码出现问题，你会受到什么影响。这会如何影响你的家人、朋友和同事？此外，想想如果你对关键故障负责的话，会有哪些道德和法律责任。

作为程序员，了解为什么应该学会测试自己的代码是很重要的。他们说“程序员永远不应该测试自己的代码”是对的。但这只适用于代码已经完成并准备好进入生产测试之前的情况。因此，在代码仍在编程过程中，程序员应该始终测试自己的代码。然而，一些企业时间非常紧迫，以至于适当的质量保证经常被牺牲，以便企业能够率先上市。

对于企业来说，率先上市可能非常重要，但第一印象至关重要。如果一个企业率先上市，而产品存在严重缺陷并被全球广播，这可能会对企业产生长期的负面影响。因此，作为程序员，你必须非常谨慎，并尽力确保如果软件存在缺陷，你不是责任人。当企业出现问题时，责任人将会受到惩罚。在不粘锅管理中，管理人员会把推动荒谬的截止日期的罪责从自己身上转嫁到不得不满足截止日期并做出牺牲的程序员身上。

因此，作为程序员，你测试自己的代码并经常测试是非常重要的，特别是在将其发布给测试团队之前。这就是为什么你被积极鼓励过渡到根据你当前正在实施的规范编写你的测试的思维方式和习惯行为。你的测试应该一开始就失败。然后你只需编写足够的代码来使测试通过，然后根据需要重构你的代码。

开始使用 TDD 或 BDD 可能很困难。但一旦掌握了，TDD 和 BDD 就会变得很自然。你可能会发现，从长远来看，你留下的代码更加清晰易读，易于维护。你可能还会发现，你对修改代码而不破坏它的能力也大大提高了。显然，从某种意义上来说，代码更多了，因为你有生产方法和测试方法。但实际上，你可能会写更少的代码，因为你不会添加你认为可能需要的额外代码！

想象一下自己坐在电脑前，手头有一份软件规范需要翻译成可运行的软件。许多程序员有一个坏习惯，我过去也曾犯过，那就是他们直接开始编码，而没有进行任何真正的设计工作。根据我的经验，这实际上会延长开发代码的时间，并经常导致更多的错误和难以维护和扩展的代码。事实上，尽管对一些程序员来说似乎违反直觉，但适当的规划和设计实际上会加快编码速度，特别是考虑到维护和扩展。

这就是测试团队的作用。在我们进一步讨论之前，让我们描述一下用例、测试设计、测试用例和测试套件，以及它们之间的关系。

用例解释了单个操作的流程，比如添加客户记录。测试设计将包括一个或多个测试用例，用于测试单个用例可能发生的不同情景。测试用例可以手动进行，也可以是由测试套件执行的自动化测试。测试套件是用于发现和运行测试并向最终用户报告结果的软件。编写用例将是业务分析师的角色。至于测试设计、测试用例和测试套件，这将是专门的测试团队的责任。开发人员无需担心编写用例、测试设计或测试用例，并在测试套件中执行它们。开发人员必须专注于编写和使用他们的单元测试来编写失败的代码，然后运行，并根据需要进行重构。

软件测试人员与程序员合作。这种合作通常从项目开始时开始，并持续到最后。开发团队和测试团队将通过共享每个产品待办事项的测试用例来合作。这个过程通常包括编写测试用例。为了通过测试，它们必须满足测试标准。这些测试用例通常将使用手动测试和一些测试套件自动化的组合来运行。

在开发阶段，测试人员编写他们的 QA 测试，开发人员编写他们的单元测试。当开发人员将他们的代码提交给测试团队时，测试团队将运行他们的一系列测试。这些测试的结果将反馈给开发人员和项目利益相关者。如果遇到问题，这被称为技术债务。开发团队将不得不考虑解决测试团队提出的问题所需的时间。当测试团队确认软件已经达到所需的质量水平时，代码将被传递给基础设施以发布到生产环境中。

假设我们正在启动一个全新的项目（也称为绿地项目），我们将选择适当的项目类型并选中包括测试项目的选项。这将创建一个解决方案，包括我们的主要项目和测试项目。

我们创建的项目类型和要实施的项目特性将取决于用例。用例在系统分析期间用于识别、确认和组织软件需求。从用例中，测试用例可以分配给验收标准。作为程序员，您可以使用这些用例及其测试用例来为每个测试用例编写自己的单元测试。然后，您的测试将作为测试套件的一部分运行。在 Visual Studio 2019 中，您可以从“视图|测试资源管理器”菜单中访问测试资源管理器。当您构建项目时，将会发现测试。发现测试后，它们将在测试资源管理器中显示。然后，您可以在测试资源管理器中运行和/或调试您的测试。

值得注意的是，在这个阶段，设计测试并提出适当数量的测试用例将是测试人员的责任，而不是开发人员的责任。一旦软件离开开发人员的手，他们还负责 QA。但是，单元测试代码的责任仍然是开发人员的责任，这就是测试用例可以在编写代码的单元测试中提供真正帮助和动力的地方。

创建解决方案时，您要做的第一件事是打开提供的测试类。在该测试类中，您编写必须完成的伪代码。然后，您逐步执行伪代码，并添加测试方法，测试必须完成的每个步骤，以便达到完成软件项目的目标。您编写的每个测试方法都是为了失败。然后，您只需编写足够的代码来通过测试。然后，一旦测试通过，您就可以在进行下一个测试之前重构代码。因此，您可以看到，单元测试并不是什么高深的科学。但是，编写一个好的单元测试需要什么呢？

任何正在测试中的代码都应该提供特定的功能。一个功能接受输入并产生输出。

在正常运行的计算机程序中，一个方法（或函数）将具有*可接受*范围的输入和输出，以及*不可接受*范围的输入和输出。因此，完美的单元测试将测试最低可接受值，最高可接受值，并提供超出可接受值范围的测试用例，无论高低。

单元测试必须是原子的，这意味着它们只能测试一件事。由于方法可以在同一个类中链接在一起，甚至可以跨多个程序集中的多个类进行链接，因此为了保持它们的原子性，通常有必要为受测试的类提供虚假或模拟对象。输出必须确定它是通过还是失败。良好的单元测试绝对不能是不确定的。

测试的结果应该是可重复的，即在特定条件下，它要么总是通过，要么总是失败。也就是说，同一个测试一遍又一遍地运行时，每次运行都不应该有不同的结果。如果有的话，那么它就不是可重复的。单元测试不应该依赖于其他测试在它们之前运行，并且它们应该与其他方法和类隔离开来。您还应该力求使单元测试在毫秒内运行。任何需要一秒或更长时间才能运行的测试都太长了。如果代码运行时间超过一秒，那么您应该考虑重构或实现一个用于测试的模拟对象。由于我们是忙碌的程序员，单元测试应该易于设置，不需要大量编码或配置。以下图表显示了单元测试的生命周期：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/3012452a-e653-4059-99a1-54f3a4c3ade9.png)

在本章中，我们将编写单元测试和模拟对象。但在此之前，我们需要了解一些作为 C#程序员可用的工具。

# 理解测试工具

我们将在 Visual Studio 中查看的测试工具有**MSTest**、**NUnit**、**Moq**和**SpecFlow**。每个测试工具都会创建一个控制台应用程序和相关的测试项目。NUnit 和 MSTest 是单元测试框架。NUnit 比 MSTest 早得多，因此与 MSTest 相比，它具有更成熟和功能齐全的 API。我个人更喜欢 NUnit 而不是 MSTest。

Moq 与 MSTest 和 NUnit 不同，因为它不是一个测试框架，而是一个模拟框架。模拟框架会用虚拟（假的）实现替换项目中的真实类，用于测试目的。您可以将 Moq 与 MSTest 或 NUnit 一起使用。最后，SpecFlow 是一个 BDD 框架。您首先使用用户和技术人员都能理解的业务语言在一个特性文件中编写一个特性。然后为该特性生成一个步骤文件。步骤文件包含实现该特性所需的方法作为步骤。

通过本章结束时，您将了解每个工具的作用，并能够在自己的项目中使用它们。因此，让我们开始看看 MSTest。

## MSTest

在本节中，我们将安装和配置 MSTest 框架。我们将编写一个带有测试方法并初始化的测试类。我们将执行程序集设置和清理、类清理和方法清理，并进行断言。

要在 Visual Studio 的命令行中安装 MSTest 框架，您需要通过 Tools | NuGet Package Manager | Package Manager Console 打开 Package Manager Console：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/5b236774-e309-4dfa-b302-588fcceab5f9.png)

然后，运行以下三个命令来安装 MSTest 框架：

```cs
install-package mstest.testframework
install-package mstest.testadapter
install-package microsoft.net.tests.sdk
```

或者，您可以添加一个新项目，并在 Solution Explorer 的 Context | Add 菜单中选择 Unit Test Project (.NET Framework)。请参阅以下截图。在命名测试项目时，接受的标准是以`<ProjectName>.Tests`的形式。这有助于将它们与测试关联起来，并将它们与受测试的项目区分开来：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/8b5325f3-0e39-414a-abbb-65c908b7a64f.png)

以下代码是在将 MSTest 项目添加到解决方案时生成的默认单元测试代码。正如您所看到的，该类导入了`Microsoft.VisualStudio.TestTools.UnitTesting`命名空间。`[TestClass]`属性标识 MS 测试框架，该类是一个测试类。`[TestMethod]`属性标记该方法为测试方法。所有具有`[TestMethod]`属性的类都将出现在测试播放器中。`[TestClass]`和`[TestMethod]`属性是强制性的：

```cs
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CH05_MSTestUnitTesting.Tests
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void TestMethod1()
        {
        }
    }
}
```

还有其他方法和属性可以选择组合以生成完整的测试执行工作流程。这些包括`[AssemblyInitialize]`、`[AssemblyCleanup]`、`[ClassInitialize]`、`[ClassCleanup]`、`[TestInitialize]`和`[TestCleanup]`。正如它们的名称所暗示的那样，初始化属性用于在运行测试之前在程序集、类和方法级别执行任何初始化。同样，清理属性在测试运行后在方法、类和程序集级别执行以执行任何必要的清理操作。我们将依次查看每个属性，并在运行最终代码时将它们添加到您的项目中，以便了解它们的执行顺序。

`WriteSeparatorLine()`方法是一个辅助方法，用于分隔我们的测试方法输出。这将帮助我们更容易地跟踪我们的测试类中发生的情况：

```cs
private static void WriteSeparatorLine()
{
    Debug.WriteLine("--------------------------------------------------");
}
```

可选地，分配`[AssemblyInitialize]`属性以在执行测试之前执行代码：

```cs
[AssemblyInitialize]
public static void AssemblyInit(TestContext context)
{
    WriteSeparatorLine();
    Debug.WriteLine("Optional: AssemblyInitialize");
    Debug.WriteLine("Executes once before the test run.");
}
```

然后，您可以选择分配`[ClassInitialize]`属性以在执行测试之前执行一次代码：

```cs
[ClassInitialize]
public static void TestFixtureSetup(TestContext context)
{
    WriteSeparatorLine();
    Console.WriteLine("Optional: ClassInitialize");
    Console.WriteLine("Executes once for the test class.");
}
```

然后，通过将`[TestInitialize]`属性分配给设置方法，在每个单元测试之前运行设置代码：

```cs
[TestInitialize]
public void Setup()
{
    WriteSeparatorLine();
    Debug.WriteLine("Optional: TestInitialize");
    Debug.WriteLine("Runs before each test.");
}
```

当您完成测试运行后，可以选择分配`[AssemblyCleanup]`属性以执行任何必要的清理操作：

```cs
[AssemblyCleanup]
public static void AssemblyCleanup()
{
    WriteSeparatorLine();
    Debug.WriteLine("Optional: AssemblyCleanup");
    Debug.WriteLine("Executes once after the test run.");
}
```

标记为`[ClassCleanup]`的可选方法在类中的所有测试执行后运行一次。您无法保证此方法何时运行，因为它可能不会立即在所有测试执行后运行：

```cs
[ClassCleanup]
public static void TestFixtureTearDown()
{
    WriteSeparatorLine();
    Debug.WriteLine("Optional: ClassCleanup");
    Debug.WriteLine("Runs once after all tests in the class have been 
     executed.");
    Debug.WriteLine("Not guaranteed that it executes instantly after all 
     tests the class have executed.");
}
```

在每个测试运行后执行清理操作，将`[TestCleanup]`属性应用于测试清理方法：

```cs
[TestCleanup]
public void TearDown()
{
    WriteSeparatorLine();
    Debug.WriteLine("Optional: TestCleanup");
    Debug.WriteLine("Runs after each test.");
    Assert.Fail();
}
```

现在我们的代码已经就位，构建它。然后，从“测试”菜单中，选择“测试资源管理器”。您应该在测试资源管理器中看到以下测试。正如您从以下截图中所看到的，该测试尚未运行：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/ddfa336a-8927-49a7-a440-fe06d8cc87ef.png)

因此，让我们运行我们唯一的测试。哦不！我们的测试失败了，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/5f5daca3-94d6-43f7-86c2-5ee95570875b.png)

按照下面的片段中所示更新`TestMethod1()`代码，然后再次运行测试：

```cs
[TestMethod]
public void TestMethod1()
{
    WriteSeparatorLine();
    Debug.WriteLine("Required: TestMethod");
    Debug.WriteLine("A test method to be run by the test runner.");
    Debug.WriteLine("This method will appear in the test list.");
    Assert.IsTrue(true);
}
```

您可以看到测试在测试资源管理器中已通过，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/16ff87f8-3e94-4b04-9129-30ed1b316b5f.png)

因此，从先前的截图中，您可以看到尚未执行的测试为*蓝色*，失败的测试为*红色*，通过的测试为*绿色*。从“工具”|“选项”|“调试”|“常规”，选择将所有输出窗口文本重定向到“立即窗口”。然后，选择“运行”|“调试所有测试”。

当您运行测试并将输出打印到“立即窗口”时，将清楚地看到属性的执行顺序。以下截图显示了我们测试方法的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/ca7e3c1b-fac4-4c63-a123-24020262e564.png)

正如您已经看到的，我们使用了两个`Assert`方法——`Assert.Fail()`和`Assert.IsTrue(true)`。`Assert`类非常有用，因此了解单元测试类中可用的方法是很值得的。这些可用的方法列在下面并进行描述：

| **方法** | **描述** |
| --- | --- |
| `Assert.AreEqual()` | 测试指定的值是否相等，并在两个值不相等时引发异常。 |
| `Assert.AreNotEqual()` | 测试指定的值是否不相等，并在两个值相等时引发异常。 |
| `Assert.ArtNotSame()` | 测试指定的对象是否引用不同的对象，并在两个输入引用相同对象时引发异常。 |
| `Assert.AreSame()` | 测试指定的对象是否都引用同一个对象，并在两个输入不引用相同对象时引发异常。 |
| `Assert.Equals()` | 此对象将始终使用`Assert.Fail`抛出异常。因此，我们可以使用`Assert.AreEqual`代替。 |
| `Assert.Fail()` | 抛出`AssertFailedException`异常。 |
| `Assert.Inconclusive()` | 抛出`AssertInconclusiveException`异常。 |
| `Assert.IsFalse()` | 测试指定的条件是否为假，并在条件为真时引发异常。 |
| `Assert.IsInstanceOfType()` | 测试指定的对象是否是预期类型的实例，并在预期类型不在对象的继承层次结构中时引发异常。 |
| `Assert.IsNotInstanceOfType()` | 测试指定的对象是否是错误类型的实例，并在指定类型在对象的继承层次结构中时引发异常。 |
| `Assert.IsNotNull()` | 测试指定的对象是否非 null，并在其为 null 时引发异常。 |
| `Assert.IsNull()` | 测试指定的对象是否为 null，并在其不为 null 时引发异常。 |
| `Assert.IsTrue()` | 测试指定的条件是否为真，并在条件为假时引发异常。 |
| `Assert.ReferenceEquals()` | 确定指定的对象实例是否是同一个实例。 |
| `Assert.ReplaceNullChars()` | 用"`\\0`"替换空字符（`'\0'`）。 |
| `Assert.That()` | 获取`Assert`功能的单例实例。 |
| `Assert.ThrowsException()` | 测试由委托操作指定的代码是否引发了类型为`T`的给定异常（而不是派生类型），如果代码没有引发异常，或引发了除`T`之外的类型的异常，则引发`AssertFailedException`。简而言之，这需要一个委托，并断言它引发了带有预期消息的预期异常。 |
| `Assert.ThrowsExceptionAsync()` | 测试由委托操作指定的代码是否引发了类型为`T`的给定异常（而不是派生类型），如果代码没有引发异常，或引发了除`T`之外的类型的异常，则引发`AssertFailedException`。 |

现在我们已经看过了 MSTest，是时候看看 NUnit 了。

## NUnit

如果在 Visual Studio 中未安装 NUnit，则可以通过 Extensions | Manage Extensions 下载并安装它。之后，创建一个新的 NUnit 测试项目（.NET Core）。以下代码包含了 NUnit 创建的默认类，名为`Tests`：

```cs
public class Tests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void Test1()
    {
        Assert.Pass();
    }
}
```

从`Test1`方法中可以看出，测试方法也使用了`Assert`类，就像 MSTest 用于测试代码断言一样。 NUnit Assert 类为我们提供了以下方法（请注意，以下表中标记为[NUnit]的方法是特定于 NUnit 的；其他所有方法也存在于 MSTest 中）：

| **方法** | **描述** |
| --- | --- |
| `Assert.AreEqual()` | 验证两个项是否相等。如果它们不相等，则引发异常。 |
| `Assert.AreNotEqual()` | 验证两个项是否不相等。如果它们相等，则引发异常。 |
| `Assert.AreNotSame()` | 验证两个对象是否不引用同一个对象。如果是，则引发异常。 |
| `Assert.AreSame()` | 验证两个对象是否引用同一个对象。如果不是，则引发异常。 |
| `Assert.ByVal()` | [NUnit] 对实际值应用约束，如果约束满足则成功，并在失败时引发断言异常。在私有 setter 导致 Visual Basic 编译错误的罕见情况下，用作`That`的同义词。 |
| `Assert.Catch()` | [NUnit] 验证委托在调用时是否抛出异常，并返回该异常。 |
| `Assert.Contains()` | [NUnit] 验证值是否包含在集合中。 |
| `Assert.DoesNotThrow()` | [NUnit] 验证方法是否不会抛出异常。 |
| `Assert.Equal()` | [NUnit] 不要使用。请改用`Assert.AreEqual()`。 |
| `Assert.Fail()` | 抛出`AssertionException`。 |
| `Assert.False()` | [NUnit] 验证条件是否为假。如果条件为真，则抛出异常。 |
| `Assert.Greater()` | [NUnit] 验证第一个值是否大于第二个值。如果不是，则抛出异常。 |
| `Assert.GreaterOrEqual()` | [NUnit] 验证第一个值是否大于或等于第二个值。如果不是，则抛出异常。 |
| `Assert.Ignore()` | [NUnit] 抛出带有传入消息和参数的`IgnoreException`。这会导致测试被报告为被忽略。 |
| `Assert.Inconclusive()` | 抛出带有传入消息和参数的`InconclusiveException`。这会导致测试被报告为不确定。 |
| `Assert.IsAssignableFrom()` | [NUnit] 验证对象是否可以分配给给定类型的值。 |
| `Assert.IsEmpty()` | [NUnit] 验证值（如字符串或集合）是否为空。 |
| `Assert.IsFalse()` | 验证条件是否为假。如果为真，则抛出异常。 |
| `Assert.IsInstanceOf()` | [NUnit] 验证对象是否是给定类型的实例。 |
| `Assert.NAN()` | [NUnit] 验证值是否不是一个数字。如果是，则抛出异常。 |
| `Assert.IsNotAssignableFrom()` | [NUnit] 验证对象是否不可从给定类型分配。 |
| `Assert.IsNotEmpty()` | [NUnit] 验证字符串或集合是否不为空。 |
| `Asserts.IsNotInstanceOf()` | [NUnit] 验证对象不是给定类型的实例。 |
| `Assert.InNotNull()` | 验证对象是否不为 null。如果为 null，则抛出异常。 |
| `Assert.IsNull()` | 验证对象是否为 null。如果不是，则抛出异常。 |
| `Assert.IsTrue()` | 验证条件是否为真。如果为假，则抛出异常。 |
| `Assert.Less()` | [NUnit] 验证第一个值是否小于第二个值。如果不是，则抛出异常。 |
| `Assert.LessOrEqual()` | [NUnit] 验证第一个值是否小于或等于第二个值。如果不是，则抛出异常。 |
| `Assert.Multiple()` | [NUnit] 包装包含一系列断言的代码，应该全部执行，即使它们失败。失败的结果将被保存，并在代码块结束时报告。 |
| `Assert.Negative()` | [NUnit] 验证数字是否为负数。如果不是，则抛出异常。 |
| `Assert.NotNull()` | [NUnit] 验证对象是否不为 null。如果为 null，则抛出异常。 |
| `Assert.NotZero()` | [NUnit] 验证数字是否不为零。如果为零，则抛出异常。 |
| `Assert.Null()` | [NUnit] 验证对象是否为 null。如果不是，则抛出异常。 |
| `Assert.Pass()` | [NUnit] 抛出带有传入消息和参数的`SuccessException`。这允许测试被提前结束，并将成功结果返回给 NUnit。 |
| `Assert.Positive()` | [NUnit] 验证数字是否为正数。 |
| `Assert.ReferenceEquals()` | [NUnit] 不要使用。抛出`InvalidOperationException`。 |
| `Assert.That()` | 验证条件是否为真。如果不是，则抛出异常。 |
| `Assert.Throws()` | 验证委托在调用时是否抛出特定异常。 |
| `Assert.True()` | [NUnit] 验证条件是否为真。如果不是，则调用异常。 |
| `Assert.Warn()` | [NUnit] 使用提供的消息和参数发出警告。 |
| `Assert.Zero()` | [NUnit] 验证数字是否为零。 |

NUnit 的生命周期始于`TestFixtureSetup`，在第一个测试`SetUp`之前执行。然后，在每个测试之前执行`SetUp`。每个测试执行完毕后，执行`TearDown`。最后，在最后一个测试`TearDown`之后执行`TestFixtureTearDown`。我们现在将更新`Tests`类，以便我们可以调试并看到 NUnit 的生命周期在运行中：

```cs
using System;
using System.Diagnostics;
using NUnit.Framework;

namespace CH06_NUnitUnitTesting.Tests
{
    [TestFixture]
    public class Tests : IDisposable
    {
        public TestClass()
        {
            WriteSeparatorLine();
            Debug.WriteLine("Constructor");
        }

        public void Dispose()
        {
            WriteSeparatorLine();
            Debug.WriteLine("Dispose"); 
        } 
    }
}
```

我们已经在类中添加了`[TestFixture]`并实现了`IDisposable`接口。`[TextFixture]`属性对于非参数化和非泛型的夹具是可选的。只要至少有一个方法被标记为`[Test]`、`[TestCase]`或`[TestCaseSource]`属性，类就会被视为`[TextFixture]`。

`WriteSeparatorLine()`方法作为我们调试输出的分隔符。这个方法将在`Tests`类中所有方法的顶部调用：

```cs
private static void WriteSeparatorLine()
{
 Debug.WriteLine("--------------------------------------------------");
}
```

标有`[OneTimeSetUp]`属性的方法将在该类中的任何测试运行之前运行一次。这里将执行所有不同测试所需的任何初始化：

```cs
[OneTimeSetUp]
public void OneTimeSetup()
{
    WriteSeparatorLine();
    Debug.WriteLine("OneTimeSetUp");
    Debug.WriteLine("This method is run once before any tests in this 
     class are run.");
}
```

标有`[OneTimeTearDown]`属性的方法在所有测试运行后运行一次，并在类被处理之前运行：

```cs
[OneTimeTearDown]
public void OneTimeTearDown()
{
    WriteSeparatorLine();
    Debug.WriteLine("OneTimeTearDown");
    Debug.WriteLine("This method is run once after all tests in this 
    class have been run.");
    Debug.WriteLine("This method runs even when an exception occurs.");
}
```

标有`[Setup]`属性的方法在每个测试方法之前运行一次：

```cs
[SetUp]
public void Setup()
{
    WriteSeparatorLine();
    Debug.WriteLine("Setup");
    Debug.WriteLine("This method is run before each test method is run.");
}
```

标有`[TearDown]`属性的方法在每个测试方法完成后运行一次：

```cs
[TearDown]
public void Teardown()
{
    WriteSeparatorLine();
    Debug.WriteLine("Teardown");
    Debug.WriteLine("This method is run after each test method 
     has been run.");
    Debug.WriteLine("This method runs even when an exception occurs.");
}
```

`Test2()`方法是一个测试方法，由`[Test]`属性表示，并且将作为第二个测试方法运行，由`[Order(1)]`属性确定。这个方法抛出`InconclusiveException`：

```cs
  [Test]
  [Order(1)]
  public void Test2()
  {
      WriteSeparatorLine();
      Debug.WriteLine("Test:Test2");
      Debug.WriteLine("Order: 1");
      Assert.Inconclusive("Test 2 is inconclusive.");
  }
```

`Test1()`方法是一个测试方法，由`[Test]`属性表示，并且将作为第一个测试方法运行，由`[0rder(0)]`属性确定。这个方法通过`SuccessException`：

```cs
[Test]
[Order(0)]
public void Test1()
{
    WriteSeparatorLine();
    Debug.WriteLine("Test:Test1");
    Debug.WriteLine("Order: 0");
    Assert.Pass("Test 1 passed with flying colours.");
}
```

`Test3()`方法是一个测试方法，由`[Test]`属性表示，并且将作为第三个测试方法运行，由`[Order(2)]`属性确定。这个方法抛出`AssertionException`：

```cs
[Test]
[Order(2)]
public void Test3()
{
    WriteSeparatorLine();
    Debug.WriteLine("Test:Test3");
    Debug.WriteLine("Order: 2");
    Assert.Fail("Test 1 failed dismally.");
}
```

当你调试所有测试时，你的立即窗口应该看起来像下面的截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/1d3fee70-f43a-4edb-8cdc-c7d7525fa9e1.png)

你现在已经接触过 MSTest 和 NUnit，并且已经看到了每个框架的测试生命周期。现在是时候看一下 Moq 了。

从 NUnit 方法表和 MSTest 方法表的比较中可以看出，NUnit 可以实现更精细的单元测试，执行性能更好，因此比 MSTest 更广泛地使用。

## Moq

单元测试应该只测试被测试的方法。参见下图。如果被测试的方法调用其他方法，这些方法可以是当前类中的方法，也可以是不同类中的方法，那么不仅测试方法，其他方法也会被测试：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/1d62c94e-84a0-415b-b6e2-31dd12e48f47.png)

克服这个问题的一种方法是使用模拟（虚假）对象。模拟对象只会测试你想要测试的方法，你可以让模拟对象按你想要的方式工作。如果你要编写自己的模拟对象，你很快就会意识到这需要大量的工作。这在时间敏感的项目中可能是不可接受的，而且你的代码变得越复杂，你的模拟对象也变得越复杂。

你最终会放弃这个糟糕的工作，或者你会寻找一个适合你需求的模拟框架。Rhino Mocks 和 Moq 是.NET Framework 的两个模拟框架。在本章中，我们只会看 Moq，它比 Rhino Mocks 更容易学习和使用。有关 Rhino Mocks 的更多信息，请访问[`hibernatingrhinos.com/oss/rhino-mocks`](http://hibernatingrhinos.com/oss/rhino-mocks)。

在使用 Moq 进行测试时，我们首先添加模拟对象，然后配置模拟对象执行某些操作。然后我们断言配置是否起作用，并且模拟对象是否被调用。这些步骤使我们能够确定模拟对象是否正确设置。Moq 只生成测试替身。它不测试代码。您仍然需要一个像 NUnit 这样的测试框架来测试您的代码。

我们现在将看一个使用 Moq 和 NUnit 的例子。

创建一个新的控制台应用程序，命名为`CH06_Moq`。添加以下接口和类——`IFoo`、`Bar`、`Baz`和`UnitTests`。然后，通过 Nuget 包管理器，安装 Moq、NUnit 和 NUnit3TestAdapter。使用以下代码更新`Bar`类：

```cs
namespace CH06_Moq
{
    public class Bar
    {
        public virtual Baz Baz { get; set; }
        public virtual bool Submit() { return false; }
    }
}
```

`Bar`类有一个虚拟属性，类型为`Baz`，以及一个名为`Submit()`的虚拟方法，返回值为`false`。现在按照以下方式更新`Baz`类：

```cs
namespace CH06_Moq
{
    public class Baz
    {
        public virtual string Name { get; set; }
    }
}
```

`Baz`类有一个名为`Name`的单个虚拟属性，类型为字符串。修改`IFoo`文件，包含以下源代码：

```cs
namespace CH06_Moq
{
    public interface IFoo
    {
        Bar Bar { get; set; }
        string Name { get; set; }
        int Value { get; set; }
        bool DoSomething(string value);
        bool DoSomething(int number, string value);
        string DoSomethingStringy(string value);
        bool TryParse(string value, out string outputValue);
        bool Submit(ref Bar bar);
        int GetCount();
        bool Add(int value);
    }
}
```

`IFoo`接口有许多属性和方法。正如您所看到的，该接口引用了`Bar`类，我们知道`Bar`类包含对`Baz`类的引用。我们现在将开始更新我们的`UnitTests`类，使用 NUnit 和 Moq 测试我们新创建的接口和类。修改`UnitTests`类文件，使其看起来像下面的代码：

```cs
using Moq;
using NUnit.Framework;
using System;

namespace CH06_Moq
{
    [TestFixture]
    public class UnitTests
    {
    }
}
```

现在，添加`AssertThrows`方法，断言是否抛出了指定的异常：

```cs
public bool AssertThrows<TException>(
    Action action,
    Func<TException, bool> exceptionCondition = null
) where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException ex)
        {
            if (exceptionCondition != null)
            {
                return exceptionCondition(ex);
            }
            return true;
        }
        catch
        {
            return false;
        }
        return false;
    }
```

`AssertThrows`方法是一个通用方法，如果您的方法抛出指定的异常，它将返回`true`，如果没有抛出异常，则返回`false`。在本章的后续测试异常时，我们将使用这个方法。现在，添加`DoSomethingReturnsTrue()`方法：

```cs
[Test]
public void DoSomethingReturnsTrue()
{
    var mock = new Mock<IFoo>();
    mock.Setup(foo => foo.DoSomething("ping")).Returns(true);
    Assert.IsTrue(mock.Object.DoSomething("ping"));
}
```

`DoSomethingReturnsTrue()`方法创建了`IFoo`接口的一个新的模拟实现。然后设置`DoSomething()`方法接受包含单词`"ping"`的字符串，并返回`true`。最后，该方法断言当`DoSomething()`方法被调用时，传入文本`"ping"`，方法返回值为`true`。我们现在将实现一个类似的测试方法，如果值为`"tracert"`，则返回`false`：

```cs
[Test]
public void DoSomethingReturnsFalse()
{
    var mock = new Mock<IFoo>();
    mock.Setup(foo => foo.DoSomething("tracert")).Returns(false);
    Assert.IsFalse(mock.Object.DoSomething("tracert"));
}
```

`DoSomethingReturnsFalse()`方法遵循与`DoSomethingReturnsFalse()`方法相同的过程。我们创建一个`IFoo`接口的模拟对象，设置它在参数值为`"tracert"`时返回`false`，然后断言参数值为`"tracert"`时返回`false`。接下来，我们将测试我们的参数：

```cs
[Test]
public void OutArguments()
{
    var mock = new Mock<IFoo>();
    var outString = "ack";
    mock.Setup(foo => foo.TryParse("ping", out outString)).Returns(true);
    Assert.AreEqual("ack", outString);
    Assert.IsTrue(mock.Object.TryParse("ping", out outString));
}
```

`OutArguments()`方法创建了`IFoo`接口的一个实现。然后声明一个将用作输出参数的字符串，并赋值为`"ack"`。接下来，设置`IFoo`模拟对象的`TryParse()`方法，对输入值`"ping"`返回`true`，并输出字符串值`"ack"`。然后我们断言`outString`等于值`"ack"`。最后的检查断言`TryParse()`对输入值`"ping"`返回`true`：

```cs
[Test]
public void RefArguments()
{
    var instance = new Bar();
    var mock = new Mock<IFoo>();
    mock.Setup(foo => foo.Submit(ref instance)).Returns(true);
    Assert.AreEqual(true, mock.Object.Submit(ref instance));
}
```

`RefArguments()`方法创建了`Bar`类的一个实例。然后，创建了`IFoo`接口的一个模拟实现。然后设置`Submit()`方法，如果传入的引用类型是`Bar`类型，则返回`true`。然后我们断言传入的参数是`Bar`类型的`true`。在我们的`AccessInvocationArguments()`测试方法中，我们创建了`IFoo`接口的一个新实现：

```cs
[Test]
public void AccessInvocationArguments()
{
    var mock = new Mock<IFoo>();
    mock.Setup(foo => foo.DoSomethingStringy(It.IsAny<string>()))
        .Returns((string s) => s.ToLower());
    Assert.AreEqual("i like oranges!", mock.Object.DoSomethingStringy("I LIKE ORANGES!"));
}
```

然后设置`DoSomethingStringy()`方法将输入转换为小写并返回。最后，我们断言返回的字符串是传入的字符串转换为小写后的字符串：

```cs
[Test]
public void ThrowingWhenInvokedWithSpecificParameters()
{
    var mock = new Mock<IFoo>();
    mock.Setup(foo => foo.DoSomething("reset"))
        .Throws<InvalidOperationException>();
    mock.Setup(foo => foo.DoSomething(""))
        .Throws(new ArgumentException("command"));
    Assert.IsTrue(
        AssertThrows<InvalidOperationException>(
            () => mock.Object.DoSomething("reset")
        )
    );
    Assert.IsTrue(
        AssertThrows<ArgumentException>(
            () => mock.Object.DoSomething("")
        )
    );
    Assert.Throws(
        Is.TypeOf<ArgumentException>()
          .And.Message.EqualTo("command"),
          () => mock.Object.DoSomething("")
    );
 }
```

在我们的最终测试方法`ThrowingWhenInvokedWithSpecificParameters()`中，我们创建了`IFoo`接口的一个模拟实现。然后配置`DoSomething()`方法，在传入值为`"reset"`时抛出`InvalidOperationException`。

当传入空字符串时，会抛出一个`ArgumentException`异常。然后我们断言当输入值为`"reset"`时会抛出`InvalidOperationException`。当输入值为空字符串时，我们断言会抛出`ArgumentException`，并断言`ArgumentException`的消息为`"command"`。

你已经看到了如何使用一个名为 Moq 的模拟框架来创建模拟对象，以使用 NUnit 测试你的代码。现在我们要看的最后一个工具是**SpecFlow**。SpecFlow 是一个 BDD 工具。

## SpecFlow

用户关注的行为测试是 BDD 的主要功能，这些测试是在编码之前编写的。BDD 是一种从 TDD 演变而来的软件开发方法。你可以从一系列特性开始 BDD。特性是用正式的商业语言编写的规范。这种语言可以被项目中的所有利益相关者理解。一旦特性被同意和生成，开发人员就需要为特性语句开发步骤定义。一旦步骤定义被创建，下一步就是创建外部项目来实现特性并添加引用。然后，步骤定义被扩展以实现特性的应用代码。

这种方法的一个好处是，作为程序员，你可以保证按照业务的要求交付成果，而不是按照你认为他们要求的交付成果。这可以为企业节省大量资金和时间。过去的历史表明，许多项目因为业务团队和编程团队之间对需要交付的内容缺乏清晰度而失败。BDD 有助于在开发新特性时减轻这种潜在风险。

在本章的这一部分中，我们将使用 BDD 软件开发方法来开发一个非常简单的计算器示例，使用 SpecFlow。

我们将首先编写一个特性文件，作为我们的规范和验收标准。然后我们将从特性文件中生成我们的步骤定义，以生成我们所需的方法。一旦我们的步骤定义生成了所需的方法，我们将为它们编写代码，以完成我们的特性。

创建一个新的类库，并添加以下包——NUnit、NUnit3TestAdapter、SpecFlow、SpecRun.SpecFlow 和 SpecFlow.NUnit。添加一个名为`Calculator`的新的 SpecFlow Feature 文件：

```cs
Feature: Calculator
  In order to avoid silly mistakes
  As a math idiot
  I want to be told the sum of two numbers

@mytag
Scenario: Add two numbers
  Given I have entered 50 into the calculator
  And I have entered 70 into the calculator
  When I press add
  Then the result should be 120 on the screen
```

在创建`Calculator.feature`文件时，上述文本会自动添加到文件中。因此，我们将使用这个作为我们学习使用 SpecFlow 进行 BDD 的起点。在撰写本文时，值得注意的是 SpecFlow 和 SpecMap 已被**Tricentis**收购。Tricentis 表示 SpecFlow、SpecFlow+和 SpecMap 都将保持免费，所以现在是学习和使用 SpecFlow 和 SpecMap 的好时机，如果你还没有这样做的话。

现在我们有了我们的特性文件，我们需要创建步骤定义，将我们的特性请求与我们的代码绑定。在代码编辑器中右键单击，会弹出上下文菜单。选择生成步骤定义。你应该会看到以下对话框：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/61f9cd3d-8061-46b9-ae24-40da636c3445.png)

为类名输入`CalculatorSteps`。点击生成按钮生成步骤定义并保存文件。打开`CalculatorSteps.cs`文件，你应该会看到以下代码：

```cs
using TechTalk.SpecFlow;

namespace CH06_SpecFlow
{
    [Binding]
    public class CalculatorSteps
    {
        [Given(@"I have entered (.*) into the calculator")]
        public void GivenIHaveEnteredIntoTheCalculator(int p0)
        {
            ScenarioContext.Current.Pending();
        }

        [When(@"I press add")]
        public void WhenIPressAdd()
        {
            ScenarioContext.Current.Pending();
        }

        [Then(@"the result should be (.*) on the screen")]
        public void ThenTheResultShouldBeOnTheScreen(int p0)
        {
            ScenarioContext.Current.Pending();
        }
    }
}
```

步骤文件的内容与特性文件的比较如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/cln-code-cs/img/386ea8ad-8b99-4cc7-861e-30d2c32b3b4b.png)

实现特性的代码必须在一个单独的文件中。创建一个新的类库，命名为`CH06_SpecFlow.Implementation`。然后，添加一个名为`Calculator.cs`的文件。在 SpecFlow 项目中添加对新创建的库的引用，并在`CalculatorSteps.cs`文件的顶部添加以下行：

```cs
private Calculator _calculator = new Calculator();
```

现在，我们可以扩展我们的步骤定义，以便它们实现应用程序代码。在`CalculatorSteps.cs`文件中，用数字替换所有的`p0`参数。这使参数要求更加*明确*。在`Calculate`类的顶部，添加两个名为`FirstNumber`和`SecondNumber`的公共属性，如下面的代码所示：

```cs
public int FirstNumber { get; set; }
public int SecondNumber { get; set; }
```

在`CalculatorSteps`类中，更新`GivenIHaveEnteredIntoTheCalculator()`方法如下：

```cs
[Given(@"I have entered (.*) into the calculator")]
public void GivenIHaveEnteredIntoTheCalculator(int number)
{
    calculator.FirstNumber = number;
}
```

现在，如果尚不存在，添加第二个方法`GivenIHaveAlsoEnteredIntoTheCalculator()`，并将`number`参数分配给计算器的第二个数字：

```cs
public void GivenIHaveAlsoEnteredIntoTheCalculator(int number)
{
    calculator.SecondNumber = number;
}
```

在`CalculatorSteps`类的顶部和任何步骤之前添加`private int result;`。将`Add()`方法添加到`Calculator`类中：

```cs
public int Add()
{
    return FirstNumber + SecondNumber;
}
```

现在，更新`CalculatorSteps`类中的`WhenIPressAdd()`方法，并用调用`Add()`方法的结果更新`result`变量：

```cs
[When(@"I press add")]
public void WhenIPressAdd()
{
    _result = _calculator.Add();
}
```

接下来，修改`ThenTheResultShouldBeOnTheScreen()`方法如下：

```cs
[Then(@"the result should be (.*) on the screen")]
public void ThenTheResultShouldBeOnTheScreen(int expectedResult)
{
    Assert.AreEqual(expectedResult, _result);
}
```

构建您的项目并运行测试。您应该看到测试通过。只编写了通过功能所需的代码，并且您的代码已通过测试。

您可以在[`specflow.org/docs/`](https://specflow.org/docs/)找到更多关于 SpecFlow 的信息。我们已经介绍了一些可用于开发和测试代码的工具。现在是时候看一个真正简单的例子，演示我们如何使用 TDD 进行编码。我们将首先编写失败的代码。然后，我们将编写足够的代码使测试通过。最后，我们将重构代码。

# TDD 方法实践-失败，通过和重构

在本节中，您将学习编写失败的测试。然后，您将学习编写足够的代码使测试通过，然后如果必要，您将执行任何需要进行的重构。

让我们深入了解 TDD 的实际例子之前，让我们考虑一下为什么我们需要 TDD。在前一节中，您看到了我们如何创建功能文件并从中生成步骤文件，以编写满足业务需求的代码。确保您的代码满足业务需求的另一种方法是使用 TDD。通过 TDD，您从一个失败的测试开始。然后，您只编写足够的代码使测试通过，并在需要时对新代码进行重构。这个过程重复进行，直到所有功能都被编码。

但是，*为什么*我们需要 TDD 呢？

业务软件规格是由与项目利益相关者合作设计新软件或对现有软件进行扩展和修改的业务分析师组合起来的。一些软件是关键的，不能出现错误。这样的软件包括处理私人和商业投资的金融系统；需要功能软件才能工作的医疗设备，包括关键的生命支持和扫描设备；交通管理和导航系统的交通信号软件；太空飞行系统；以及武器系统。

好的，但 TDD 在哪里适用呢？

好吧，你已经得到了编写软件规范的任务。你需要做的第一件事是创建你的项目。然后，你为你要实现的功能编写伪代码。然后，你继续为每个伪代码编写测试。测试失败。然后，你编写必要的代码使测试通过，然后根据需要重构你的代码。你正在编写经过充分测试和健壮的代码。你能够保证你的代码在隔离环境中按预期执行。如果你的代码是一个更大系统的组件，那么测试团队将负责测试你的代码的集成，而不是你。作为开发人员，你已经赢得了对代码的信心，可以将其发布给测试团队。如果测试团队发现了以前被忽视的用例，他们会与你分享。然后，你将编写进一步的测试并使其通过，然后将更新后的代码发布给他们。这种工作方式确保了代码的最高标准，并且可以信任它按照给定输入的预期输出进行工作。最后，TDD 使软件进展可衡量，这对经理来说是个好消息。

现在是我们进行 TDD 的小演示的时候了。在这个例子中，我们将使用 TDD 来开发一个简单的日志记录应用程序，可以处理内部异常，并将异常记录到一个带有时间戳的文本文件中。我们将编写程序并使测试通过。一旦我们编写了程序并使所有测试通过，然后我们将重构我们的代码，使其可重用和更易读，当然，我们将确保我们的测试仍然通过。

1.  创建一个新的控制台应用程序，并将其命名为`CH06_FailPassRefactor`。添加一个名为`UnitTests`的类，其中包含以下伪代码：

```cs
using NUnit.Framework;

namespace CH06_FailPassRefactor
{
    [TestFixture]
    public class UnitTests
    {
        // The PseudoCode.
        // [1] Call a method to log an exception.
        // [2] Build up the text to log including 
        // all inner exceptions.
        // [3] Write the text to a file with a timestamp.
    }
}
```

1.  我们将编写我们的第一个单元测试来满足条件`[1]`。在我们的单元测试中，我们将测试创建`Logger`变量，调用`Log()`方法，并通过测试。所以，让我们写代码：

```cs
// [1] Call a method to log an exception.
[Test]
public void LogException()
{
    var logger = new Logger();
    var logFileName = logger.Log(new ArgumentException("Argument cannot be null"));
    Assert.Pass();
}
```

这个测试不会运行，因为项目无法构建。这是因为`Logger`类不存在。因此，在项目中添加一个名为`Logger`的内部类。然后运行你的测试。构建仍然会*失败*，测试也不会运行，因为现在缺少`Log()`方法。所以让我们在`Logger`类中添加`Log()`方法。然后，我们将尝试再次运行我们的测试。这次，测试应该成功。

1.  在这个阶段，我们将执行任何必要的重构。但由于我们刚刚开始，没有需要重构的地方，所以我们可以继续进行下一个测试。

我们的代码生成日志消息并保存到磁盘的功能将包含私有成员。使用 NUnit，你不测试私有成员。这种思想是，如果你必须测试私有成员，那么你的代码肯定有问题。所以，我们将继续进行下一个单元测试，确定日志文件是否存在。在编写单元测试之前，我们将编写一个返回具有内部异常的异常的方法。我们将在我们的单元测试中将返回的异常传递给`Log()`方法：

```cs
private Exception GetException()
{
    return new Exception(
        "Exception: Main exception.",
        new Exception(
            "Exception: Inner Exception.",
            new Exception("Exception: Inner Exception Inner Exception")
        )
    );
}
```

1.  现在，我们已经有了`GetException()`方法，我们可以编写我们的单元测试来检查日志文件是否存在：

```cs
[Test]
public void CheckFileExists()
{
    var logger = new Logger();
    var logFile = logger.Log(GetException());
    FileAssert.Exists(logFile);
}
```

1.  如果我们构建我们的代码并运行`CheckFileExists()`测试，它将失败，所以我们需要编写代码使其成功。在`Logger`类中，将`private StringBuilder _stringBuilder;`添加到`Logger`类的顶部。然后，修改`Log()`方法，并在`Logger`类中添加以下方法：

```cs
private StringBuilder _stringBuilder;

public string Log(Exception ex)
{
    _stringBuilder = new StringBuilder();
    return SaveLog();
}

private string SaveLog()
{
    var fileName = $"LogFile{DateTime.UtcNow.GetHashCode()}.txt";
    var dir = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
    var file = $"{dir}\\{fileName}";
    return file;
}
```

1.  我们已经调用了`Log()`方法，并生成了一个日志文件。现在，我们只需要将文本记录到文件中。根据我们的伪代码，我们需要记录主异常和所有内部异常。让我们编写一个检查日志文件是否包含消息`"Exception: Inner Exception Inner Exception"`的测试：

```cs
[Test]
public void ContainsMessage()
{
    var logger = new Logger();
    var logFile = logger.Log(GetException());
    var msg = File.ReadAllText(logFile);
    Assert.IsTrue(msg.Contains("Exception: Inner Exception Inner Exception"));
}
```

1.  现在，我们知道测试将会失败，因为字符串生成器是*空的*，所以我们将在`Logger`类中添加一个方法，该方法将接受一个异常，记录消息，并检查异常是否有内部异常。如果有，那么它将使用参数`isInnerException`调用自身：

```cs
private void BuildExceptionMessage(Exception ex, bool isInnerException)
{
    if (isInnerException)
        _stringBuilder.Append("Inner Exception: ").AppendLine(ex.Message);
    else
        _stringBuilder.Append("Exception: ").AppendLine(ex.Message);
    if (ex.InnerException != null)
       BuildExceptionMessage(ex.InnerException, true);
}
```

1.  最后，更新`Logger`类的`Log()`方法以调用我们的`BuildExceptionMessage()`方法：

```cs
public string Log(Exception ex)
{
    _stringBuilder = new StringBuilder();
    _stringBuilder.AppendLine("-----------------------
      -----------------");
    BuildExceptionMessage(ex, false);
    _stringBuilder.AppendLine("-----------------------
      -----------------");
    return SaveLog();
}
```

现在我们所有的测试都通过了，我们有一个完全正常运行的程序，但是这里有一个重构的机会。名为`BuildExceptionMessage()`的方法是可以重复使用的候选方法，特别是在调试时非常有用，尤其是当您有一个带有内部异常的异常时，所以我们将把该方法移动到自己的方法中。请注意，`Log()`方法也正在构建要记录的文本的开头和结尾部分。

我们可以并且将把这个移到`BuildExceptionMessage()`方法中：

1.  创建一个新的类并将其命名为`Text`。在构造函数中添加一个私有的`StringBuilder`成员变量并对其进行实例化。然后，通过添加以下代码来更新类：

```cs
public string ExceptionMessage => _stringBuilder.ToString();

public void BuildExceptionMessage(Exception ex, bool isInnerException)
{
    if (isInnerException)
    {
        _stringBuilder.Append("Inner Exception: ").AppendLine(ex.Message);
    }
    else
    {
        _stringBuilder.AppendLine("--------------------------------------------------------------");
        _stringBuilder.Append("Exception: ").AppendLine(ex.Message);
    }
    if (ex.InnerException != null)
        BuildExceptionMessage(ex.InnerException, true);
    else
        _stringBuilder.AppendLine("--------------------------------------------------------------");
}
```

1.  现在我们有一个有用的`Text`类，它可以从带有内部异常的异常中返回有用的异常消息，但是我们也可以重构`SaveLog()`方法中的代码。我们可以将生成唯一哈希文件名的代码提取到自己的方法中。因此，让我们向`Text`类添加以下方法：

```cs
public string GetHashedTextFileName(string name, SpecialFolder folder)
{
    var fileName = $"{name}-{DateTime.UtcNow.GetHashCode()}.txt";
    var dir = Environment.GetFolderPath(folder);
    return $"{dir}\\{fileName}";
}
```

1.  `GetHashedTextFileName()` 方法接受用户指定的文件名和特殊文件夹。然后在文件名末尾添加连字符和当前 UTC 日期的哈希码。然后添加`.txt`文件扩展名并将文本分配给`fileName`变量。然后将调用者请求的特殊文件夹的绝对路径分配给`dir`变量，然后将路径和文件名返回给用户。此方法保证返回唯一的文件名。

1.  用以下代码替换`Logger`类的主体：

```cs
        private Text _text;

        public string Log(Exception ex)
        {
            BuildMessage(ex);
            return SaveLog();
        }

        private void BuildMessage(Exception ex)
        {
            _text = new Text();
            _text.BuildExceptionMessage(ex, false);
        }

        private string SaveLog()
        {
            var filename = _text.GetHashedTextFileName("Log", 
              Environment.SpecialFolder.MyDocuments);
            File.WriteAllText(filename, _text.ExceptionMessage);
            return filename;
        }
```

该类仍然在做同样的事情，但是它更清洁、更小，因为消息和文件名的生成已经移动到一个单独的类中。如果您运行代码，它的行为方式是相同的。如果您运行测试，它们都会通过。

在这一部分中，我们编写了失败的单元测试，然后修改它们使其通过。然后，我们重构了代码，使其更加清晰，这导致我们编写的代码可以在同一项目或其他项目中重复使用。现在让我们简要地看一下多余的测试。

# 删除多余的测试、注释和死代码

正如书中所述，我们对编写清晰的代码很感兴趣。随着我们的程序和测试的增长以及开始重构，一些代码将变得多余。任何多余的代码并且没有被调用的代码都被称为**死代码**。一旦识别出死代码，就应该立即删除。死代码不会在编译后的代码中执行，但它仍然是需要维护的代码库的一部分。带有死代码的代码文件比它们需要的要长。除了使文件变得更大之外，它还可能使阅读源代码变得更加困难，因为它可能打断代码的自然流程，并给阅读它的程序员增加困惑和延迟。不仅如此，对于项目中的新程序员来说，最不希望的是浪费宝贵的时间来理解永远不会被使用的死代码。因此最好是摆脱它。

至于注释，如果做得当，它们可以非常有用，特别是 API 注释对 API 文档生成特别有益。但有些注释只会给代码文件增加噪音，令人惊讶的是，很多程序员会因此感到非常恼火。有一群程序员会对一切都做注释。另一群则什么都不注释，因为他们认为代码应该像读书一样。还有一些人采取平衡的态度，只在必要时才对代码做注释。

当你看到这样的注释时——“这会偶尔生成一个随机 bug。不知道为什么。但欢迎你来修复它！”——警钟应该响起。首先，写下这条注释的程序员应该坚持在代码上工作，直到找出生成 bug 的条件，然后修复 bug。如果你知道写下这条注释的程序员是谁，那就把代码还给他们去修复，并删除注释。我在多个场合看到过这样的代码，也看到过网上对这些注释表达强烈情绪的评论。我想这是应对懒惰程序员的一种方式。如果他们不是懒惰，而只是经验不足，那么这是一个很好的学习任务，可以学习问题诊断和解决的艺术。

如果代码已经经过检查和批准，你发现有一些代码块被注释掉了，那就把它们删除。这些代码仍然存在于版本控制历史中，如果需要的话，你可以从那里检索出来。

代码应该像读书一样，所以你不应该让你的代码变得晦涩难懂，只是为了给同事留下好印象，因为我保证，当你几周后回到自己的代码时，你会摸着头想知道自己的代码是做什么的，为什么要这样写。我见过很多初学者犯这个错误。

冗余测试也应该被移除。你只需要运行必要的测试。对于冗余代码的测试没有价值，可能会浪费大量时间。此外，如果你的公司有在云中运行测试的 CI/CD 流水线，那么冗余测试和死代码会给构建、测试和部署流水线增加业务成本。这意味着你上传、构建、测试和部署的代码行数越少，公司在运行成本上的支出就越少。记住，在云中运行进程是要花钱的，企业的目标是尽量少花钱，但赚取大量利润。

现在我们完成了这一章，让我们总结一下我们学到的东西。

# 总结

我们首先看了开发人员编写单元测试以开发质量保证代码的重要性。我们确定了软件中可能出现的理论问题，包括生命损失和昂贵的诉讼。然后讨论了单元测试和什么是好的单元测试。我们确定了一个好的单元测试必须是原子的、确定性的、可重复的和快速的。

接下来，我们将看一下开发人员可用的辅助 TDD 和 BDD 的工具。我们讨论了 MSTest 和 NUnit，并提供了示例，展示了如何实施 TDD。然后，我们看了如何使用一个名为 Moq 的模拟框架与 NUnit 一起测试模拟对象。我们的工具介绍最后以 SpecFlow 结束——这是一个 BDD 工具，允许我们用业务语言编写功能，技术人员和非技术人员都能理解，以确保业务得到的是业务想要的。

接着，我们使用 *失败、通过和重构* 方法，通过一个非常简单的 TDD 示例来使用 NUnit，最后看了为什么我们应该删除不必要的注释、冗余测试和死代码。

在本章的最后，您将找到有关测试软件程序的进一步资源。在下一章中，我们将看一下端到端测试。但在那之前，您可能也可以尝试以下问题，看看您对单元测试有多少了解。

# 问题

1.  什么是一个好的单元测试？

1.  一个好的单元测试不应该是什么？

1.  TDD 代表什么？

1.  BDD 代表什么？

1.  什么是单元测试？

1.  什么是模拟对象？

1.  什么是虚拟对象？

1.  列出一些单元测试框架。

1.  列出一些模拟框架。

1.  列出一个 BDD 框架。

1.  应该从源代码文件中删除什么？

# 进一步阅读

+   可以在[`softwaretestingfundamentals.com/unit-testing`](http://softwaretestingfundamentals.com/unit-testing/)找到对单元测试的简要概述，以及链接到不同类型的单元测试，包括集成测试、验收测试和测试人员工作描述的更多信息。

+   Rhino Mocks 的主页可以在[`hibernatingrhinos.com/oss/rhino-mocks`](http://hibernatingrhinos.com/oss/rhino-mocks)找到。
