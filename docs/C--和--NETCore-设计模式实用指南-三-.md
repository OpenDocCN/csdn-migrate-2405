# C# 和 .NETCore 设计模式实用指南（三）

> 原文：[`zh.annas-archive.org/md5/99BBE5B6F8F1801CD147129EA46FD82D`](https://zh.annas-archive.org/md5/99BBE5B6F8F1801CD147129EA46FD82D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：实施 Web 应用程序的设计模式-第二部分

在上一章中，我们将我们的 FlixOne 库存管理控制台应用程序扩展为 Web 应用程序，同时说明了不同的模式。我们还涵盖了**用户界面**（**UI**）架构模式，如**模型-视图-控制器**（**MVC**）、**模型视图呈现器**（**MVP**）等。上一章旨在讨论 MVC 等模式。现在我们需要扩展我们现有的应用程序，以纳入更多模式。

在本章中，我们将继续使用我们现有的 FlixOne Web 应用程序，并通过编写代码来扩展应用程序，以查看认证和授权的实现。除此之外，我们还将讨论**测试驱动开发**（**TDD**）。

在本章中，我们将涵盖以下主题：

+   认证和授权

+   创建一个.NET Core Web 测试项目

# 技术要求

本章包含各种代码示例，以解释概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

要运行和执行代码，Visual Studio 2019 是必需的（您也可以使用 Visual Studio 2017 来运行应用程序）。

# 安装 Visual Studio

要运行这些代码示例，您需要安装 Visual Studio（首选**集成开发环境**（**IDE**））。要做到这一点，请按照以下说明进行操作：

1.  从以下下载链接下载 Visual Studio，其中包含安装说明：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照您在那里找到的安装说明进行操作。Visual Studio 有多个版本可供安装。在这里，我们使用的是 Windows 版的 Visual Studio。

# 设置.NET Core

如果您没有安装.NET Core，则需要按照以下说明进行操作：

1.  使用[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)下载 Windows 版.NET Core。

1.  有关多个版本和相关库，请访问[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

# 安装 SQL Server

如果您没有安装 SQL Server，则需要按照以下说明进行操作：

1.  从以下链接下载 SQL Server：[`www.microsoft.com/en-in/download/details.aspx?id=1695`](https://www.microsoft.com/en-in/download/details.aspx?id=1695)。

1.  您可以在这里找到安装说明：[`docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017`](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017)。

有关故障排除和更多信息，请参考以下链接：[`www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm`](https://www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm)。

完整的源代码可以从以下链接获得：[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter7`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter7)。

# 扩展.NET Core Web 应用程序

在本章中，我们将继续使用我们的 FlixOne 库存应用程序。在本章中，我们将讨论 Web 应用程序模式，并扩展我们在上一章中开发的 Web 应用程序。

本章将继续上一章开发的 Web 应用程序。如果您跳过了上一章，请返回查看，以与当前章节同步。

在本节中，我们将介绍需求收集的过程，然后讨论我们之前开发的 Web 应用程序所面临的各种挑战。

# 项目启动

在第六章中，*为 Web 应用程序实现设计模式-第一部分*，我们扩展了我们的 FlixOne 库存控制台应用程序并开发了一个 Web 应用程序。在考虑了以下几点后，我们扩展了该应用程序：

+   我们的业务需要一个丰富的用户界面。

+   新的机会需要一个响应式的 Web 应用程序。

# 需求

经过几次会议和与管理层、业务分析师（BAs）和售前人员的讨论后，管理层决定着手处理以下高级需求：**业务需求**和**技术需求**。

# 业务需求

业务团队最终提出了以下业务需求：

+   **产品分类**：有多种产品，但如果用户想要搜索特定产品，他们可以通过按类别筛选所有产品来实现。例如，像芒果、香蕉等产品应该属于名为“水果”的类别。

+   **产品添加**：应该有一个界面，提供给我们添加新产品的功能。这个功能只能提供给具有“添加产品”权限的用户。

+   **产品更新**：应该有一个新的界面，可以进行产品更新。

+   **产品删除**：管理员需要删除产品。

# 技术要求

满足业务需求的实际需求现在已经准备好进行开发。经过与业务人员的多次讨论，我们得出以下需求：

+   **应该有一个着陆页或主页**：

+   应该有一个包含各种小部件的仪表板

+   应该显示商店的一览图片

+   **应该有一个产品页面**：

+   应该具备添加、更新和删除产品的能力

+   应该具备添加、更新和删除产品类别的能力

FlixOne 库存管理 Web 应用程序是一个虚构的产品。我们正在创建此应用程序来讨论 Web 项目中所需/使用的各种设计模式。

# 挑战

尽管我们已将现有的控制台应用程序扩展为新的 Web 应用程序，但对开发人员和企业来说都存在各种挑战。在本节中，我们将讨论这些挑战，然后找出克服这些挑战的解决方案。

# 开发人员面临的挑战

由于应用程序发生了重大变化而出现的挑战。这也是将控制台应用程序升级为 Web 应用程序的主要扩展的结果：

+   **不支持 TDD**：目前解决方案中没有包含测试项目。因此，开发人员无法遵循 TDD 方法，这可能会导致应用程序中出现更多的错误。

+   **安全性**：在当前应用程序中，没有机制来限制或允许用户访问特定屏幕或模块。也没有与身份验证和授权相关的内容。

+   **UI 和用户体验（UX）**：我们的应用程序是从基于控制台的应用程序推广而来，因此 UI 并不是非常丰富。

# 企业面临的挑战

实现最终输出需要时间，这延迟了产品，导致业务损失。在我们采用新技术栈并对代码进行大量更改时，出现了以下挑战：

+   **客户流失**：在这里，我们仍处于开发阶段，但对我们业务的需求非常高；然而，开发团队花费的时间比预期的要长，以交付产品。

+   **生产更新需要更多时间**：目前开发工作非常耗时，这延迟了后续活动，并导致生产延迟。

# 找到解决问题/挑战的解决方案

经过数次会议和头脑风暴后，开发团队得出结论，我们必须稳定我们的基于 Web 的解决方案。为了克服这些挑战并提供解决方案，技术团队和业务团队联合起来确定了各种解决方案和要点。

解决方案支持以下要点：

+   实施身份验证和授权

+   遵循 TDD

+   重新设计 UI 以满足 UX

# 身份验证和授权

在上一章中，我们开始将控制台应用程序升级为 Web 应用程序，我们添加了**创建、读取、更新和删除**（CRUD）操作，这些操作对任何能够执行它们的用户都是公开可用的。没有编写任何代码来限制特定用户执行这些操作的权限。这样做的风险是，不应执行这些操作的用户可以轻易执行。其后果如下：

+   无人值守访问

+   黑客/攻击者的开放大门

+   数据泄漏问题

现在，如果我们渴望保护我们的应用程序并将操作限制为允许的用户，那么我们必须实施一个设计，只允许这些用户执行操作。可能有一些情况下，我们可以允许一些操作的开放访问。在我们的情况下，大多数操作仅限于受限访问。简而言之，我们可以尝试一些方法，告诉我们的应用程序，传入的用户是属于我们的应用程序并且可以执行指定的任务。

**身份验证**只是一个系统通过凭据（通常是用户 ID 和密码）验证或识别传入请求的过程。如果系统发现提供的凭据错误，那么它会通知用户（通常通过 GUI 屏幕上的消息）并终止授权过程。

**授权**始终在身份验证之后。这是一个过程，允许经过验证的用户在验证其对特定资源或数据的访问权限后访问资源或数据。

在前面的段落中，我们已经讨论了一些机制，阻止了对我们应用程序操作的无人值守访问。让我们参考下图并讨论它显示了什么：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/00ea38bd-deaf-44bf-ae88-d05a91e2597e.png)

上图描述了一个场景，即系统不允许无人值守访问。这简单地定义为：接收到一个请求，内部系统（身份验证机制）检查请求是否经过身份验证。如果请求经过身份验证，那么用户被允许执行他们被授权的操作。这不仅是单一的检查，但对于典型的系统来说，授权在身份验证之后生效。我们将在接下来的章节中讨论这一点。

为了更好地理解这一点，让我们编写一个简单的登录应用程序。让我们按照这里给出的步骤进行：

1.  打开 Visual Studio 2018。

1.  打开文件 | 新建 | 新项目。

1.  从项目窗口，为您的项目命名。

1.  选择 ASP.NET Core 2.2 的 Web 应用程序（模型-视图-控制器）模板：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e1b73f2c-6bb3-472c-83fa-148167c195de.png)

1.  您可以选择所选模板的各种身份验证。

1.  默认情况下，模板提供了一个名为无身份验证的选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/56f9fe22-d905-4a1c-aaa3-9967f6e3011f.png)

1.  按下*F5*并运行应用程序。从这里，您将看到默认的主页：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/36015566-2dc3-4f85-a9a6-5479287ae8ef.png)

现在你会注意到你可以在没有任何限制的情况下浏览每个页面。这是显而易见的，并且有道理，因为这些页面是作为开放访问的。主页和隐私页面是开放访问的，不需要任何身份验证，这意味着任何人都可以访问/查看这些页面。另一方面，我们可能有一些页面是为无人值守访问而设计的，比如用户资料和管理员页面。

请参阅 GitHub 存储库，了解该章节的应用程序，网址为[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter6`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter6)，并浏览我们使用 ASP.NET Core MVC 构建的整个应用程序。

继续使用我们的 SimpleLogin 应用程序，让我们添加一个专门用于受限访问的屏幕：Products 屏幕。在本章中，我们不会讨论如何向现有项目添加新的控制器或视图。如果您想知道如何将这些添加到我们的项目中，请重新访问第六章，*实现 Web 应用程序的设计模式-第一部分*。

我们已经为我们的项目添加了新功能，以展示具有 CRUD 操作的产品。现在，按下*F5*并检查输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e1323798-b41f-4647-91e2-9b02aee64b03.png)

您将得到前面截图中显示的输出。您可能会注意到我们现在有一个名为 Products 的新菜单。

让我们浏览一下新的菜单选项。点击 Products 菜单：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e4d9a790-7ca3-413c-953e-c7ffd7085696.png)

前面的截图显示了我们的产品页面。这个页面对所有人都是可用的，任何人都可以在没有任何限制的情况下查看它。您可以看一看并观察到这个页面具有创建新产品、编辑和删除现有产品的功能。现在，想象一个情景，一个未知的用户来了并删除了一个非常重要并吸引高销量的特定产品。您可以想象这种情景以及这对业务造成了多大的影响。甚至可能会有顾客流失。

在我们的情景中，我们可以通过两种方式保护我们的产品页面：

+   **先前认证**：在这个页面上，产品的链接对所有人都不可用；它只对经过身份验证的请求/用户可用。

+   **后续认证**：在这个页面上，产品的链接对所有人都是可用的。但是，一旦有人请求访问页面，系统就会进行身份验证检查。

# 身份验证进行中。

在这一部分，我们将看到如何实现身份验证，并使我们的网页对未经身份验证的请求受限。

为了实现身份验证，我们应该采用某种机制，为我们提供一种验证用户的方式。一般情况下，如果用户已登录，那就意味着他们已经经过身份验证。

在我们的 Web 应用程序中，我们也会遵循相同的方法，并确保用户在访问受限页面、视图和操作之前已登录：

```cs
public class User
{
    public Guid Id { get; set; }
    public string UserName { get; set; }
    public string EmailId { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public byte[] PasswordHash { get; set; }
    public byte[] PasswordSalt { get; set; }
    public string SecretKey { get; set; }
    public string Mobile { get; set; }
    public string EmailToken { get; set; }
    public DateTime EmailTokenDateTime { get; set; }
    public string OTP { get; set; }
    public DateTime OtpDateTime { get; set; }
    public bool IsMobileVerified { get; set; }
    public bool IsEmailVerified { get; set; }
    public bool IsActive { get; set; }
    public string Image { get; set; }
}
```

前面的类是一个典型的`User`模型/实体，代表我们的数据库`User`表。这个表将保存关于`User`的所有信息。每个字段的样子如下：

+   `Id` 是一个**全局唯一标识符**（**GUID**）和表中的主键。

+   `UserName` 通常在登录和其他相关操作中使用。它是一个程序生成的字段。

+   `FirstName` 和 `LastName` 组合了用户的全名。

+   `Emailid` 是用户的有效电子邮件地址。它应该是一个有效的电子邮件，因为我们将在注册过程中/之后验证它。

+   `PasswordHash` 和 `PasswordSalt` 是基于**哈希消息认证码，安全哈希算法**（**HMAC****SHA**）512 的字节数组。`PasswordHash`属性的值为 64 字节，`PasswordSalt`为 128 字节。

+   `SecretKey` 是一个 Base64 编码的字符串。

+   `Mobilie` 是一个有效的手机号码，取决于系统的有效性检查。

+   `EmailToken` 和 `OTP` 是随机生成的**一次性密码**（**OTPs**），用于验证`emailId`和`Mobile number`。

+   `EmailTokenDateTime` 和 `OtpDateTime` 是`datetime`数据类型的属性；它们表示为用户发出`EmailToken`和`OTP`的日期和时间。

+   `IsMobileVerified`和`IsEmailverified`是布尔值（`true`/`false`），告诉系统手机号和/或电子邮件 ID 是否已验证。

+   `IsActive`是布尔值（`true`/`false`），告诉系统`User`模型是否处于活动状态。

+   `Image`是图像的 Base64 编码字符串。它代表用户的个人资料图片。

我们需要将我们的新类/实体添加到我们的`Context`类中。让我们添加我们在下面截图中看到的内容：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e66ab985-bf29-4c24-a451-510908e88c54.png)

通过在我们的`Context`类中添加上一行，我们可以直接使用**Entity Framework**（**EF**）功能访问我们的`User`表：

```cs
public class LoginViewModel
{
    [Required]
    public string Username { get; set; }
    [Required]
    [DataType(DataType.Password)]
    public string Password { get; set; }
    [Display(Name = "Remember Me")]
    public bool RememberMe { get; set; }
    public string ReturnUrl { get; set; }
}
```

`LoginViewModel`用于验证用户。这个`viewmodel`的值来自登录页面（我们将在接下来的部分讨论和创建此页面）。它包含以下内容：

+   `UserName`：这是用于识别用户的唯一名称。这是一个易于识别的人类可读值。它不像 GUID 值。

+   `Password`：这是任何用户的秘密和敏感值。

+   `RememberMe`：这告诉我们用户是否希望允许当前系统持久化存储在客户端浏览器的 cookie 中的值。

执行 CRUD 操作，让我们将以下代码添加到`UserManager`类中：

```cs
public class UserManager : IUserManager
{
    private readonly InventoryContext _context;

    public UserManager(InventoryContext context) => _context = context;

    public bool Add(User user, string userPassword)
    {
        var newUser = CreateUser(user, userPassword);
        _context.Users.Add(newUser);
        return _context.SaveChanges() > 0;
    }

    public bool Login(LoginViewModel authRequest) => FindBy(authRequest) != null;

    public User GetBy(string userId) => _context.Users.Find(userId);
```

以下是`UserManager`类其余方法的代码片段：

```cs
   public User FindBy(LoginViewModel authRequest)
    {
        var user = Get(authRequest.Username).FirstOrDefault();
        if (user == null) throw new ArgumentException("You are not registered with us.");
        if (VerifyPasswordHash(authRequest.Password, user.PasswordHash, user.PasswordSalt)) return user;
        throw new ArgumentException("Incorrect username or password.");
    }
    public IEnumerable<User> Get(string searchTerm, bool isActive = true)
    {
        return _context.Users.Where(x =>
            x.UserName == searchTerm.ToLower() || x.Mobile == searchTerm ||
            x.EmailId == searchTerm.ToLower() && x.IsActive == isActive);
    }

    ...
}
```

上述代码是`UserManager`类，它使我们能够使用 EF 与我们的`User`表进行交互：

以下代码显示了登录屏幕的视图：

```cs
<form asp-action="Login" asp-route-returnurl="@Model.ReturnUrl">
    <div asp-validation-summary="ModelOnly" class="text-danger"></div>

    <div class="form-group">
        <label asp-for="Username" class="control-label"></label>
        <input asp-for="Username" class="form-control" />
        <span asp-validation-for="Username" class="text-danger"></span>
    </div>

    <div class="form-group">
        <label asp-for="Password" class="control-label"></label>
        <input asp-for="Password" class="form-control"/>
        <span asp-validation-for="Password" class="text-danger"></span>
    </div>

    <div class="form-group">
        <label asp-for="RememberMe" ></label>
        <input asp-for="RememberMe" />
        <span asp-validation-for="RememberMe"></span>
    </div>
    <div class="form-group">
        <input type="submit" value="Login" class="btn btn-primary" />
    </div>
</form>
```

上述代码片段来自我们的`Login.cshtml`页面/视图。该页面提供了一个表单来输入`Login`详细信息。这些详细信息传递到我们的`Account`控制器，然后进行验证以认证用户：

以下是`Login`操作方法：

```cs
[HttpGet]
public IActionResult Login(string returnUrl = "")
{
    var model = new LoginViewModel { ReturnUrl = returnUrl };
    return View(model);
}
```

上述代码片段是一个`Get /Account/Login`请求，显示空的登录页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/49b3bb00-4948-47d3-a661-8124331d513d.png)

用户点击登录菜单选项后立即出现上一个截图。这是一个用于输入登录详细信息的简单表单。

以下代码显示了处理应用程序`Login`功能的`Login`操作方法：

```cs
[HttpPost]
public IActionResult Login(LoginViewModel model)
{
    if (ModelState.IsValid)
    {
        var result = _authManager.Login(model);

        if (result)
        {
           return !string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl)
                ? (IActionResult)Redirect(model.ReturnUrl)
                : RedirectToAction("Index", "Home");
        }
    }
    ModelState.AddModelError("", "Invalid login attempt");
    return View(model);
}
```

上述代码片段是从登录页面发出的`Post /Account/Login`请求，发布整个`LoginViewModel`类：

以下是我们登录视图的截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f6723286-de50-440c-8d2b-5a2dafc67aa9.png)

在上一个截图中，我们尝试使用默认用户凭据（用户名：`aroraG`和密码：`test123`）登录。与此登录相关的信息将被持久化在 cookie 中，但仅当用户勾选了“记住我”复选框时。系统会在当前计算机上记住用户登录会话，直到用户点击“注销”按钮。

用户一点击登录按钮，系统就会验证他们的登录详细信息，并将他们重定向到主页，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/dd11bc73-c8d1-4c6b-b7bc-7e33fd058cd7.png)

您可能会在菜单中看到文本，例如`欢迎 Gaurav`。这个欢迎文本不是自动显示的，而是我们通过添加几行代码来指示系统显示这个文本，如下面的代码所示：

```cs
<li class="nav-item">
    @{
        if (AuthManager.IsAuthenticated)
        {
            <a class="nav-link text-dark" asp-area="" asp-controller="Account" asp-action="Logout"><strong>Welcome @AuthManager.Name</strong>, Logout</a>

        }
        else
        {
            <a class="nav-link text-dark" asp-area="" asp-controller="Account" asp-action="Login">Login</a>
        }
    }
</li>
```

上一个代码片段来自`_Layout.cshtml`视图/页面。在上一个代码片段中，我们正在检查`IsAuthenticated`是否返回 true。如果是，那么欢迎消息将被显示。这个欢迎消息伴随着“注销”选项，但当`IsAuthenticated`返回`false`值时，它显示`Login`菜单：

```cs
public bool IsAuthenticated
{
    get { return User.Identities.Any(u => u.IsAuthenticated); }
}
```

`IsAuthenticated`是`AuthManager`类的`ReadOnly`属性，用于检查请求是否已经认证。在我们继续之前，让我们重新审视一下我们的`Login`方法：

```cs
public IActionResult Login(LoginViewModel model)
{
    if (ModelState.IsValid)
    {
        var result = _authManager.Login(model);

        if (result)
        {
           return !string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl)
                ? (IActionResult)Redirect(model.ReturnUrl)
                : RedirectToAction("Index", "Home");
        }
    }
    ModelState.AddModelError("", "Invalid login attempt");
    return View(model);
}
```

前面的`Login`方法只是简单地验证用户。看看这个声明——`var result = _authManager.Login(model);`。这调用了`AuthManager`中的`Login`方法：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/dde59675-3690-45ac-8590-ca3a459137f8.png)

如果`Login`方法返回`true`，那么它将当前的登录页面重定向到主页。否则，它将保持在相同的登录页面上，抱怨登录尝试无效。以下是`Login`方法的代码：

```cs
public bool Login(LoginViewModel model)
{
    var user = _userManager.FindBy(model);
    if (user == null) return false;
    SignInCookie(model, user);
    return true;
}
```

`Login`方法是`AuthManager`类的典型方法，它调用`UserManager`的`FindBy(model)`方法并检查是否存在。如果存在，那么它进一步调用`AuthManager`类的`SignInCookie(model,user)`方法，否则，它简单地返回`false`，意味着登录不成功：

```cs
private void SignInCookie(LoginViewModel model, User user)
{
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.FirstName),
        new Claim(ClaimTypes.Email, user.EmailId),
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
    };

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
    var principal = new ClaimsPrincipal(identity);
    var props = new AuthenticationProperties { IsPersistent = model.RememberMe };
    _httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props).Wait();
}
```

以下代码片段确保如果用户经过身份验证，那么他们的详细信息应该被持久化在`HttpContext`中，这样系统就可以对来自用户的每个传入请求进行身份验证。你可能会注意到`_httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props).Wait();`语句实际上签署并启用了 cookie 身份验证：

```cs
//Cookie authentication
services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie();
//For claims
services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
services.AddTransient<IAuthManager, AuthManager>();
```

前面的声明帮助我们为我们的应用程序启用 cookie 身份验证和声明的传入请求。最后，`app.UseAuthentication();`语句将身份验证机制能力添加到我们的应用程序中。这些语句应该添加到`Startup.cs`类中。

# 这有什么区别吗？

我们已经在我们的 Web 应用程序中添加了大量代码，但这真的有助于我们限制我们的页面/视图免受未经许可的请求吗？**产品**页面/视图仍然是开放的；因此，我可以从产品页面/视图执行任何可用的操作：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/503ea6e8-df37-4c0b-b2bd-d0ae1a348a07.png)

作为用户，我无论是否登录都可以看到产品选项：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/5e25140c-009d-4976-8bee-da343dc28458.png)

前面的截图显示了登录后与登录前相同的产品菜单选项。

我们可以像这样限制对产品页面的访问：

```cs
<li class="nav-item">
    @{
        if (AuthManager.IsAuthenticated)
        {
            <a class="nav-link text-dark" asp-area="" asp-controller="Product" asp-action="Index">Products</a>
        }
    }
</li>
```

以下是应用程序的主屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/bf5954af-e1af-4505-958e-413ae4cfd1bd.png)

前面的代码帮助系统只在用户登录/经过身份验证后显示产品菜单选项。产品菜单选项将不会显示在屏幕上。像这样，我们可以限制未经许可的访问。然而，这种方法也有其缺点。最大的缺点是，如果有人知道产品页面的 URL——它将引导您到`/Product/Index`——那么他们可以执行受限制的操作。这些操作是受限制的，因为它们不是供未登录用户使用的。

# 授权的实际应用

在前一节中，我们讨论了如何避免对特定或受限制的屏幕/页面的未经许可访问。我们已经看到登录实际上对用户进行身份验证，并允许他们向系统发出请求。另一方面，身份验证并不意味着如果用户经过身份验证，那么他们就被授权访问特定的部分、页面或屏幕。

以下描述了典型的授权和身份验证过程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/8ce628c8-963b-4240-a461-128fba886d7e.png)

在这个过程中，第一个请求/用户得到了身份验证（通常是登录表单），然后授权请求执行特定/请求的操作。可能有许多情况，其中请求经过身份验证，但未经授权访问特定资源或执行特定操作。

在我们的应用程序（在上一节中创建）中，我们有一个带有 CRUD 操作的`Products`页面。`Products`页面不是公共页面，这意味着这个页面不是所有人都可以访问的；它是受限访问的。

我们回到了前一节中留下的主要问题：“如果用户经过身份验证，但未被授权访问特定页面/资源怎么办？无论我们是否将页面从未经授权的用户隐藏起来，因为他们可以通过输入其 URL 轻松访问或查看它。”为了克服这一挑战/问题，我们可以实施以下步骤：

1.  检查对受限资源的每次访问的授权，这意味着每当用户尝试访问资源（通过在浏览器中输入直接 URL），系统都会检查授权，以便授权来访的请求。如果用户的来访请求未经授权，则他们将无法执行指定的操作。

1.  在受限资源的每次操作上检查授权意味着如果用户经过身份验证，他们将能够访问受限页面/视图，但只有在用户经过授权时才能访问此页面/视图的操作。

`Microsoft.AspNetCore.Authorization`命名空间提供了授权特定资源的内置功能。

为了限制访问并避免对特定资源的未经监控的访问，我们可以使用`Authorize`属性：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/4d449cc2-19f6-4522-8811-b1b9a59ef4af.png)

前面的截图显示我们将`Authorize`属性放入了我们的`ProductController`中。现在，按下*F5*并运行应用程序。

如果用户未登录到系统，则他们将无法看到产品页面，因为我们已经添加了条件。如果用户经过验证，则在菜单栏中显示产品。

不要登录到系统并直接在浏览器中输入产品 URL，`http://localhost:56229/Product`。这将重定向用户到登录屏幕。请查看以下截图并检查 URL；您可能会注意到 URL 包含一个`ReturnUrl`部分，该部分将指示系统在成功登录尝试后重定向到何处。

请参阅以下截图；请注意 URL 包含`ReturnUrl`部分。一旦用户登录，系统将重定向应用程序到此 URL：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/c7be2aef-4be7-4eb3-acbc-ff8900abfcf1.png)

以下截图显示了产品列表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/ecde544b-f171-4a84-ab26-ccb3fda4cb3b.png)

我们的产品列表屏幕提供了诸如创建新产品、编辑、删除和详细信息等操作。当前应用程序允许用户执行这些操作。因此，是否有意义让任何访问和经过身份验证的用户都可以创建、更新和删除产品？如果我们允许每个用户这样做，后果可能如下：

+   我们可以有许多已经添加到系统中的产品。

+   产品的不可避免的移除/删除。

+   产品的不可避免的更新。

我们是否可以有一些用户类型，可以将`Admin`类型的所有用户与普通用户区分开来，只允许具有管理员权限的用户而不是普通用户执行这些操作？更好的想法是为用户添加角色；因此，我们需要使特定类型的用户成为用户。

让我们在项目中添加一个新的实体并命名为`Role`：

```cs
public class Role
{
    public Guid Id { get; set; }
    public string Name { get; set; }
    public string ShortName { get; set; }
}
```

定义用户的`Role`类的前面的代码片段具有以下列表中解释的属性：

+   `Id`：这使用`GUID`作为主键。

+   `Name`：`string`类型的`Role`名称。

+   `ShortName`：`string`类型的角色的简短或缩写名称。

我们需要将我们的新类/实体添加到我们的`Context`类中。让我们按照以下方式添加：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/41ec1447-9387-4dad-900d-b7264329c630.png)

前面的代码提供了使用 EF 进行各种 DB 操作的能力：

```cs
public IEnumerable<Role> GetRoles() => _context.Roles.ToList();

public IEnumerable<Role> GetRolesBy(string userId) => _context.Roles.Where(x => x.UserId.ToString().Equals(userId));

public string RoleNamesBy(string userId)
{
    var listofRoleNames = GetRolesBy(userId).Select(x=>x.ShortName).ToList();
    return string.Join(",", listofRoleNames);
}
```

在前面的代码片段中出现的`UserManager`类的三种方法为我们提供了从数据库中获取`Roles`的能力：

```cs
private void SignInCookie(LoginViewModel model, User user)
{
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, user.FirstName),
        new Claim(ClaimTypes.Email, user.EmailId),
        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
    };

    if (user.Roles != null)
    {
        string[] roles = user.Roles.Split(",");

        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));
    }

    var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

    var principal = new ClaimsPrincipal(identity);
    var props = new AuthenticationProperties { IsPersistent = model.RememberMe };
    _httpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal, props).Wait();
}
```

我们通过修改`AuthManager`类的`SigningCookie`方法，将`Roles`添加到我们的`Claims`中：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b2f40509-4128-4d60-864b-84b5bc9fc064.png)

上一张截图显示了一个名为`Gaurav`的用户有两个角色：`Admin`和`Manager`：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/7dff3042-7c28-4700-a762-c9d3dbab96ac.png)

我们限制`ProductController`仅供具有`Admin`和`Manager`角色的用户使用。现在，尝试使用用户`aroraG`登录，您将看到`Product Listing`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f3bb9f93-2966-43f8-a046-9632d5670f63.png)

现在，让我们尝试用第二个用户`aroraG1`登录，该用户具有`Editor`角色。这将引发`AccessDenied`错误。请参见以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/edba9b44-843e-42d3-8a6b-ea4845d3e9e3.png)

通过这种方式，我们可以保护我们的受限资源。有很多方法可以实现这一点。.NET Core MVC 提供了内置功能来实现这一点，您也可以以可定制的方式实现。如果您不想使用这些可用的内置功能，您可以通过添加到现有代码中来轻松起草所需功能的自己的功能。如果您想这样做，您需要从头开始。此外，如果某样东西已经存在，那么再次创建类似的东西就没有意义。如果您找不到可用组件的功能，那么您应该定制现有的功能/特性，而不是从头开始编写整个代码。

**开发人员应该实现一个不可篡改的身份验证机制。**在本节中，我们已经讨论了很多关于身份验证和授权，以及编写代码和创建我们的 Web 应用程序。关于身份验证，我们应该使用一个良好的身份验证机制，这样就不会有人篡改或绕过它。您可以从以下两种设计开始：

+   身份验证过滤器

+   验证个别请求/端点

在实施了前面的步骤之后，每个通过任何模式发出的请求在系统响应给用户或发出调用的客户端之前都应经过身份验证和授权。这个过程主要包括以下内容：

+   **保密性**：安全系统确保任何敏感数据不会暴露给未经身份验证和未经授权的访问请求。

+   **可用性**：系统中的安全措施确保系统对通过系统的身份验证和授权机制确认为真实用户的用户可用。

+   **完整性**：在一个安全的系统中，数据篡改是不可能的，因此数据是安全的。

# 创建一个 Web 测试项目

单元测试是检查代码健康的一种方法。这意味着如果代码有错误（不健康），那么这将成为应用程序中许多未知和不需要的问题的基础。为了克服这种方法，我们可以遵循 TDD 方法。

您可以通过 Katas 练习 TDD。您可以参考[`www.codeproject.com/Articles/886492/Learning-Test-Driven-Development-with-TDD-Katas`](https://www.codeproject.com/Articles/886492/Learning-Test-Driven-Development-with-TDD-Katas)了解更多关于 TDD katas 的信息。如果您想要练习这种方法，请使用这个存储库：[`github.com/garora/TDD-Katas`](https://github.com/garora/TDD-Katas)。

我们已经在前几章讨论了很多关于 TDD，所以我们不打算在这里详细讨论。相反，让我们按照以下步骤创建一个测试项目：

1.  打开我们的 Web 应用程序。

1.  在 Visual Studio 的解决方案资源管理器中，右键单击解决方案，然后单击添加 | 新建项目...，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/7fce068c-4813-4bfd-b558-c91398c93cfb.png)

1.  从添加新项目模板中，选择.NET Core 和 xUnit 测试项目（.NET Core），并提供一个有意义的名称：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/68d046c1-29af-4cb9-a4c1-c6a62a091e86.png)

您将得到一个默认的单元`test`类，其中包含空的测试代码，如下代码片段所示：

```cs
namespace Product_Test
{
    public class UnitTest1
    {
        [Fact]
        public void Test1()
        {
        }
    }
}
```

您可以更改此类的名称，或者如果您想编写自己的`test`类，可以放弃此类：

```cs
public class ProductData
{
    public IEnumerable<ProductViewModel> GetProducts()
    {
        var productVm = new List<ProductViewModel>
        {
            new ProductViewModel
            {
                CategoryId = Guid.NewGuid(),
                CategoryDescription = "Category Description",
                CategoryName = "Category Name",
                ProductDescription = "Product Description",
                ProductId = Guid.NewGuid(),
                ProductImage = "Image full path",
                ProductName = "Product Name",
                ProductPrice = 112M
            },
           ... 
        };

        return productVm;
    }
```

1.  先前的代码来自我们新添加的`ProductDate`类。请将其添加到名为`Fake`的新文件夹中。这个类只是创建虚拟数据，以便我们可以测试产品的 Web 应用程序：

```cs
public class ProductTests
{
    [Fact]
    public void Get_Returns_ActionResults()
    {
        // Arrange
        var mockRepo = new Mock<IProductRepository>();
        mockRepo.Setup(repo => repo.GetAll()).Returns(new ProductData().GetProductList());
        var controller = new ProductController(mockRepo.Object);

        // Act
        var result = controller.GetList();

        // Assert
        var viewResult = Assert.IsType<OkObjectResult>(result);
        var model = Assert.IsAssignableFrom<IEnumerable<ProductViewModel>>(viewResult.Value);
        Assert.NotNull(model);
        Assert.Equal(2, model.Count());
    }
}
```

1.  在`Services`文件夹中添加一个名为`ProductTests`的新文件。请注意，我们在这段代码中使用了`Stubs`和`Mocks`。

我们的先前代码将通过红色波浪线抱怨错误，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/de3be8e2-682c-40e9-a3ac-2c5f2bc64507.png)

1.  先前的代码存在错误，因为我们没有添加一些必需的包来执行测试。为了克服这些错误，我们应该在我们的`test`项目中安装`moq`支持。在您的包管理器控制台中输入以下命令：

```cs
install-package moq 
```

1.  上述命令将在测试项目中安装`moq`框架。请注意，在执行上述命令时，您应该选择我们创建的测试项目：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/0f6d860c-70f3-447d-b6a2-e3bdd6e3ec46.png)

一旦安装了`moq`，您就可以开始测试了。

在使用`xUnit`测试项目时需要注意的重要点如下：

+   **Fact**是一个属性，用于没有参数的普通测试方法。

+   **Theory**是一个属性，用于带参数的测试方法。

1.  一切准备就绪。现在，点击“测试资源管理器”并运行您的测试：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f0688d2c-d36b-46e4-9c3f-a397ad044b51.png)

最后，我们的测试通过了！这意味着我们的控制器方法很好，我们的代码中没有任何问题或错误，可以破坏应用程序/系统的功能。

# 总结

本章的主要目标是使我们的 Web 应用程序能够防范未经授权的请求。本章介绍了使用 Visual Studio 逐步创建 Web 应用程序，并讨论了身份验证和授权。我们还讨论了 TDD，并创建了一个新的 xUnit Web 测试项目，其中我们使用了`Stubs`和`Mocks`。

在下一章中，我们将讨论在.NET Core 中使用并发编程时的最佳实践和模式。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  什么是身份验证和授权？

1.  在第一级请求中使用身份验证然后允许受限区域的传入请求是否安全？

1.  您如何证明授权始终在身份验证之后进行？

1.  什么是 TDD，为什么开发人员关心它？

1.  定义 TDD katas。它们如何帮助我们改进 TDD 方法？

# 进一步阅读

恭喜，您已经完成了本章！要了解本章涵盖的主题，请参考以下书籍：

+   *使用.NET Core 构建 RESTful Web 服务*，作者*Gaurav Aroraa, Tadit Dash*，由*Packt Publishing*出版：[`www.packtpub.com/application-development/building-restful-web-services-net-core`](https://www.packtpub.com/application-development/building-restful-web-services-net-core)

+   *C#和.NET Core 测试驱动开发*，作者*Ayobami Adewole*，由*Packt Publishing*出版：[`www.packtpub.com/in/application-development/c-and-net-core-test-driven-development`](https://www.packtpub.com/in/application-development/c-and-net-core-test-driven-development)


# 第三部分：函数式编程、响应式编程和云编程

这是本书中最重要的部分。在这一部分中，熟悉.NET Framework 的读者可以将他们的学习与.NET Core 联系起来，而熟悉.NET Core 的读者可以通过实际示例增进他们的知识。我们将使用模式来解决一些现代软件开发中更具挑战性的方面。

本节包括以下章节：

+   第八章，《.NET Core 并发编程》

+   第九章，《函数式编程实践-一种方法》

+   第十章，《响应式编程模式和技术》

+   第十一章，《高级数据库设计和应用技术》

+   第十二章，《云编程》


# 第八章：.NET Core 中的并发编程

在上一章（第七章，*为 Web 应用程序实现设计模式 - 第二部分*）中，我们使用各种模式创建了一个示例 Web 应用程序。我们调整了授权和认证机制以保护 Web 应用程序，并讨论了**测试驱动开发**（**TDD**）以确保我们的代码已经经过测试并且可以正常工作。

本章将讨论在.NET Core 中执行并发编程时采用的最佳实践。在本章的后续部分中，我们将学习与 C#和.NET Core 应用程序中良好组织的并发相关的设计模式。

本章将涵盖以下主题：

+   Async/Await - 为什么阻塞是不好的？

+   多线程和异步编程

+   并发集合

+   模式和实践 - TDD 和并行 LINQ

# 技术要求

本章包含各种代码示例来解释概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

完整的源代码可在以下链接找到：[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter8`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter8)。

要运行和执行代码，您需要以下内容：

+   Visual Studio 2019（您也可以使用 Visual Studio 2017）

+   .NET Core 的设置

+   SQL Server（本章中使用 Express Edition）

# 安装 Visual Studio

要运行代码示例，您需要安装 Visual Studio（首选 IDE）。要做到这一点，您可以按照以下说明进行操作：

1.  从安装说明中提到的下载链接下载 Visual Studio：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照提到的安装说明进行操作。

1.  Visual Studio 安装有多个选项可供选择。在这里，我们使用 Windows 的 Visual Studio。

# 设置.NET Core

如果您没有安装.NET Core，您需要按照以下说明进行操作：

1.  在[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)下载 Windows 的.NET Core。

1.  有关多个版本和相关库，请访问[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

# 安装 SQL Server

如果您没有安装 SQL Server，可以按照以下说明进行操作：

1.  从以下链接下载 SQL Server：[`www.microsoft.com/en-in/download/details.aspx?id=1695`](https://www.microsoft.com/en-in/download/details.aspx?id=1695)。

1.  您可以在这里找到安装说明：[`docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017`](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017)。

有关故障排除和更多信息，请参考以下链接：[`www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm`](https://www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm)。

# 现实世界中的并发

**并发**是我们生活的一部分：它存在于现实世界中。当我们讨论并发时，我们指的是多任务处理。

在现实世界中，我们经常进行多任务处理。例如，我们可以在使用手机通话时编写程序，我们可以在吃饭时看电影，我们可以在阅读乐谱时唱歌。有很多例子说明我们作为人类可以进行多任务处理。不用深入科学细节，我们可以看到我们的大脑试图掌握新事物的同时，也指挥身体的其他器官工作，比如心脏或我们的嗅觉，这是一种多任务处理。

同样的方法也适用于我们的系统（计算机）。如果我们考虑今天的计算机，每台可用的计算机都有多核 CPU（多个核心）。这是为了允许同时执行多个指令，让我们能够同时执行多个任务。

在单个 CPU 机器上真正的并行是不可能的，因为任务是不可切换的，因为 CPU 只有一个核心。这只有在具有多个 CPU（多个核心）的机器上才可能。简而言之，并发编程涉及两件事：

+   **任务管理**：将工作单元分配给可用线程。

+   **通信**：设置任务的初始参数并获取结果。

每当有多个事情/任务同时发生时，我们称之为*并发*。在我们的编程语言中，每当程序的任何部分同时运行时，这被称为并发编程。您也可以将**并行编程**用作并发编程的同义词。

举个例子，想象一下一个需要门票才能进入特定会议厅的大型会议。在会议厅的门口，您必须购买门票，用现金或信用卡付款。当您付款时，柜台助理可能会将您的详细信息输入系统，打印发票，并为您提供门票。现在假设还有更多人想要购买门票。每个人都必须执行必要的活动才能从售票处领取门票。在这种情况下，每次只能有一个人从一个柜台接受服务，其他人则等待他们的轮到。假设一个人从柜台领取门票需要两分钟；因此，下一个人需要等待两分钟才能轮到他们。如果排队的人数是 50 人，那么最后一个人的等待时间可以改变。如果有两个以上的售票柜台，每个柜台都在两分钟内执行任务，这意味着每两分钟，三个人将能够领取三张门票——或者三个柜台每两分钟卖出两张门票。换句话说，每个售票柜台都在同一时间执行相同的任务（即售票）。这意味着所有柜台都是并行服务的；因此，它们是并发的。这在下图中有所体现：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/3375a9cf-5b1e-4100-bbe2-078e2b0da4a3.png)

在上图中，清楚地显示了排队的每个人都处于等待位置或者在柜台上活动，而且有三个队列，任务是按顺序进行的。所有三个柜台（`CounterA`、`CounterB`和`CounterC`）在同一时间执行任务——它们在并行进行活动。

**并发**是指两个或更多任务在重叠的时间段内开始、运行和完成。

**并行性**是指两个或更多任务同时运行。

这些是并发活动，但想象一下一个巨大的人群在排队（例如，10,000 人）；在这里进行并行处理是没有用的，因为这不会解决这个操作中可能出现的瓶颈问题。另一方面，您可以将柜台数量增加到 50 个。它们会解决这个问题吗？在我们使用任何软件时，这种问题会发生。这是一个与阻塞相关的问题。在接下来的章节中，我们将更详细地讨论并发编程。

# 多线程和异步编程

简而言之，我们可以说多线程意味着程序在多个线程上并行运行。在异步编程中，一个工作单元与主应用程序线程分开运行，并告诉调用线程任务已完成、失败或正在进行中。在异步编程周围需要考虑的有趣问题是何时使用它以及它的好处是什么。

更多线程访问相同的共享数据并以不可预测的结果更新它的潜力可以称为**竞争条件**。我们已经在第四章中讨论了竞争条件，*实现设计模式 - 基础部分 2*。

考虑我们在上一节讨论的场景，即排队的人们正在领取他们的票。让我们尝试在一个多线程程序中捕捉这种情况：

```cs
internal class TicketCounter
{
    public static void CounterA() => Console.WriteLine("Person A is collecting ticket from Counter A");
    public static void CounterB() => Console.WriteLine("Person B is collecting ticket from Counter B");
    public static void CounterC() => Console.WriteLine("Person C is collecting ticket from Counter C");
}
```

在这里，我们有一个代表我们整个领取柜台设置的`TicketCounter`类（我们在上一节中讨论过这些）。三个方法：`CounterA()`，`CounterB()`和`CounterC()`代表一个单独的领取柜台。这些方法只是向控制台输出一条消息，如下面的代码所示：

```cs
internal class Program
{
    private static void Main(string[] args)
    {
        var counterA = new Thread(TicketCounter.CounterA);
        var counterB = new Thread(TicketCounter.CounterB);
        var counterC = new Thread(TicketCounter.CounterC);
        Console.WriteLine("3-counters are serving...");
        counterA.Start();
        counterB.Start();
        counterC.Start();
        Console.WriteLine("Next person from row");
        Console.ReadLine();
    }
}
```

上面的代码是我们的`Program`类，它从`Main`方法中启动活动。在这里，我们为所有柜台声明并启动了三个线程。请注意，我们按顺序启动了这些线程。由于我们期望这些线程将按照相同的顺序执行，让我们运行程序并查看输出，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/fa77cf94-ea4a-42d7-bc79-a195f4d235f4.png)

根据代码，上面的程序没有按照给定的顺序执行。根据我们的代码，执行顺序应该如下：

```cs
3-counters are serving...
Next person from row
Person A is collecting ticket from Counter A
Person B is collecting ticket from Counter B
Person C is collecting ticket from Counter C
```

这是由于线程，这些线程在没有保证按照它们被声明/启动的顺序/序列执行的情况下同时工作。

再次运行程序，看看我们是否得到相同的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/90eeaf02-4eb6-48ac-9280-ebae4931624c.png)

上面的快照显示了与先前结果不同的输出，所以现在我们按顺序得到了输出：

```cs
3-counters are serving...
Person A is collecting ticket from Counter A
Person B is collecting ticket from Counter B
Next person from row
Person C is collecting ticket from Counter C
```

因此，线程正在工作，但不是按照我们定义的顺序。

您可以像这样设置线程的优先级：`counterC.Priority = ThreadPriority.Highest;`，`counterB.Priority = ThreadPriority.Normal;`，和`counterA.Priority = ThreadPriority.Lowest;`。

为了以同步的方式运行线程，让我们修改我们的代码如下：

```cs
internal class SynchronizedTicketCounter
{
    public void ShowMessage()
    {
        int personsInQueue = 5; //assume maximum persons in queue
 lock (this)
        {
            Thread thread = Thread.CurrentThread;
            for (int personCount = 0; personCount < personsInQueue; personCount++)
            {
                Console.WriteLine($"\tPerson {personCount + 1} is collecting ticket from counter {thread.Name}.");
            }
        }
    }
}
```

我们创建了一个新的`SynchronizedTicketCounter`类，其中包含`ShowMessage()`方法；请注意前面代码中的`lock(this){...}`。运行程序并检查输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/485977ff-b745-40fa-9d36-b62b53858573.png)

我们得到了我们期望的输出，现在我们的柜台按照正确的顺序服务。

# 异步/等待 - 为什么阻塞是不好的？

异步编程在我们期望在同一时间点进行各种活动的情况下非常有帮助。通过`async`关键字，我们将方法/操作定义为异步的。考虑以下代码片段：

```cs
internal class AsyncAwait
{
    public async Task ShowMessage()
    {
        Console.WriteLine("\tServing messages!");
        await Task.Delay(1000);
    }
}
```

在这里，我们有一个带有`async`方法`ShowMessage()`的`AsyncAwait`类。这个方法只是打印一个消息，会显示在控制台窗口中。现在，每当我们在另一个代码中调用/使用这个方法时，该部分代码可能会等待/阻塞操作，直到`ShowMessage()`方法执行并完成其任务。参考以下快照：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/664b9a37-4b9d-492a-9c5c-5bf10071d809.png)

我们之前的屏幕截图显示，我们为我们的`ShowMessage()`方法设置了 1,000 毫秒的延迟。在这里，我们指示程序在 1,000 毫秒后完成。如果我们尝试从先前的代码中删除`await`，Visual Studio 将立即发出警告，要求将`await`放回去；参考以下快照：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/90f87239-59f6-4cac-9693-651c66c8facd.png)

通过`await`运算符的帮助，我们正在使用非阻塞 API 调用。运行程序并查看以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/773d415b-b503-4812-b93d-36d7d3aeb4ed.png)

我们将得到如前面快照中所示的输出。

# 并发集合

.NET Core 框架提供了各种集合，我们可以使用 LINQ 查询。作为开发人员，在寻找线程安全集合时，选择余地要少得多。没有线程安全的集合，开发人员在执行多个操作时可能会变得困难。在这种情况下，我们将遇到我们已经在第四章中讨论过的竞争条件。为了克服这种情况，我们需要使用`lock`语句，就像我们在前一节中使用的那样。例如，我们可以编写一个简化的`lock`语句的实现代码-参考以下代码片段，我们在其中使用了`lock`语句和集合类`Dictionary`：

```cs
public bool UpdateQuantity(string name, int quantity)
{
    lock (_lock)
    {
        _books[name].Quantity += quantity;
    }

    return true;
}
```

前面的代码来自`InventoryContext`；在这段代码中，我们正在阻止其他线程锁定我们正在尝试更新数量的操作。

`Dictionary`集合类的主要缺点是它不是线程安全的。当我们在多个线程中使用`Dictionary`时，我们必须在`lock`语句中使用它。为了使我们的代码线程安全，我们可以使用`ConcurrentDictionary`集合类。

`ConcurrentDictionary`是一个线程安全的集合类，它存储键值对。这个类有`lock`语句的实现，并提供了一个线程安全的类。考虑以下代码：

```cs
private readonly IDictionary<string, Book> _books;
protected InventoryContext()
{
    _books = new ConcurrentDictionary<string, Book>();
}
```

前面的代码片段来自我们的 FlixOne 控制台应用程序的`InventoryContext`类。在这段代码中，我们有`_books`字段，并且它被初始化为`ConcurrentDictionary`集合类。

由于我们在多线程中使用`InventoryContext`类的`UpdateQuantity()`方法，有一种可能性是一个线程增加数量，而另一个线程将数量重置为其初始水平。这是因为我们的对象来自单个集合，对集合的任何更改在一个线程中对其他线程不可见。所有线程都引用原始未修改的集合，简单来说，我们的方法不是线程安全的，除非我们使用`lock`语句或`ConcurretDictionary`集合类。

# 模式和实践- TDD 和并行 LINQ

当我们使用多线程时，我们应该遵循最佳实践来编写**流畅的代码**。流畅的代码是指开发人员不会面临死锁的代码。换句话说，在编写过程中，多线程需要非常小心。

当多个线程在一个类/程序中运行时，当每个线程接近在`lock`语句下编写的对象或资源时，死锁就会发生。实际的死锁发生在每个线程都试图锁定另一个线程已经锁定的对象/资源时。

一个小错误可能导致开发人员不得不处理由于被阻塞的线程而发生的未知错误。除此之外，代码中几个字的错误实现可能会影响 100 行代码。

让我们回到本章开头讨论的会议门票的例子。如果售票处无法履行其职责并分发门票会发生什么？在这种情况下，每个人都会尝试到达售票处并获取门票，这可能会导致售票处被堵塞。这可能会导致售票处被阻塞。相同的逻辑适用于我们的程序。我们将遇到多个线程尝试锁定我们的对象/资源的死锁情况。避免这种情况的最佳做法是使用一种同步访问对象/资源的机制。.NET Core 框架提供了`Monitor`类来实现这一点。我已经重新编写了我们的旧代码以避免死锁情况-请参阅以下代码：

```cs
private static void ProcessTickets()
{
    var ticketCounter = new TicketCounter();
    var counterA = new Thread(ticketCounter.ShowMessage);
    var counterB = new Thread(ticketCounter.ShowMessage);
    var counterC = new Thread(ticketCounter.ShowMessage);
    counterA.Name = "A";
    counterB.Name = "B";
    counterC.Name = "C";
    counterA.Start();
    counterB.Start();
    counterC.Start();
}
```

在这里，我们有`ProcessTicket`方法；它启动了三个线程（每个线程代表一个售票处）。每个线程都会到达`TicketCounter`类的`ShowMessage`。如果我们的`ShowMessage`方法没有很好地编写来处理这种情况，就会出现死锁问题。所有三个线程都将尝试为与`ShowMessage`方法相关的各自对象/资源获取锁。

以下代码是`ShowMessage`方法的实现，我编写了这段代码来处理死锁情况：

```cs
private static readonly object Object = new object();
public void ShowMessage()
{
    const int personsInQueue = 5;
    if (Monitor.TryEnter(Object, 300))
    {
        try
        {
            var thread = Thread.CurrentThread;
            for (var personCount = 0; personCount < personsInQueue; personCount++)
                Console.WriteLine(
                    $"\tPerson {personCount + 1} is collecting ticket from counter {thread.Name}.");
        }
        finally
        {
            Monitor.Exit(Object);
        }
    }
}
```

上述是我们`TicketCounter`类的`ShowMessage()`方法。在这个方法中，每当一个线程尝试锁定`Object`时，如果`Object`已经被锁定，它会尝试 300 毫秒。`Monitor`类会自动处理这种情况。使用`Monitor`类时，开发人员不需要担心多个线程正在运行的情况，每个线程都在尝试获取锁。运行程序以查看以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b5992517-e5e5-490e-bb0a-ef9d708e0994.png)

在上面的快照中，您会注意到在`counterA`之后，`counterC`正在服务，然后是`counter B`。这意味着在`thread A`之后，`thread C`被启动，然后是`thread B`。换句话说，`thread A`首先获取锁，然后在 300 毫秒后，`thread C`尝试获取锁，然后`thread B`尝试锁定对象。如果要设置线程的顺序或优先级，可以添加以下代码行：

```cs
counterC.Priority = ThreadPriority.Highest
counterB.Priority = ThreadPriority.Normal;
counterA.Priority = ThreadPriority.Lowest;
```

当您将上述行添加到`ProcessTickets`方法时，所有线程将按顺序工作：首先是`Thread C`，然后是`Thread B`，最后是`Thread A`。

线程优先级是一个枚举，告诉我们如何调度线程和`System.Threading.ThreadPriority`具有以下值：

+   **Lowest**：这是最低的优先级，意味着具有`Lowest`优先级的线程可以在任何其他优先级的线程之后进行调度。

+   **BelowNormal**：具有`BelowNormal`优先级的线程可以在具有`Normal`优先级的线程之后，但在具有`Lowest`优先级的线程之前进行调度。

+   **Normal**：所有线程都具有默认优先级`Normal`。具有`Normal`优先级的线程可以在具有`AboveNormal`优先级的线程之后，但在具有`BelowNormal`优先级的线程之前进行调度。

+   **AboveNormal**：具有`AboveNormal`优先级的线程可以在具有`Normal`优先级的线程之前，但在具有`Highest`优先级的线程之后进行调度。

+   **Highest**：这是线程的最高优先级级别。具有`Highest`优先级的线程可以在具有任何其他优先级的线程之前进行调度。

在为线程设置优先级级别后，执行程序并查看以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/ceaf2e4f-1185-4ac0-aa88-bf90055500bf.png)

根据上面的快照，在设置了优先级后，计数器按顺序为`C`，`B`和`A`提供服务。通过小心和简单的实现，我们可以处理死锁情况，并安排我们的线程按特定顺序/优先级提供服务。

.NET Core 框架还提供了**任务并行库**（**TPL**），它是属于`System.Threading`和`System.Threading.Tasks`命名空间的一组公共 API。借助 TPL，开发人员可以通过简化实现使应用程序并发运行。

考虑以下代码，我们可以看到 TPL 的最简单实现：

```cs
public void PallelVersion()
{
    var books = GetBooks();
    Parallel.ForEach(books, Process);
}
```

上面是一个简单的使用`Parallel`关键字的`ForEach`循环。在上面的代码中，我们只是遍历了一个`books`集合，并使用`Process`方法进行处理：

```cs
private void Process(Book book)
{
    Console.WriteLine($"\t{book.Id}\t{book.Name}\t{book.Quantity}");
}
```

前面的代码是我们的`Process`方法（再次强调，这是最简单的方法），它打印了`books`的细节。根据他们的要求，用户可以执行尽可能多的操作：

```cs
private static void ParallelismExample()
{
    var parallelism = new Parallelism();
    parallelism.GenerateBooks(19);
    Console.WriteLine("\n\tId\tName\tQty\n");
    parallelism.PallelVersion();
    Console.WriteLine($"\n\tTotal Processes Running on the machine:{Environment.ProcessorCount}\n");
    Console.WriteLine("\tProcessing complete. Press any key to exit.");
    Console.ReadKey();
}
```

如您所见，我们有`ParallelismExample`方法，它生成书籍列表并通过执行`PallelVersion`方法处理书籍。

在执行程序以查看以下输出之前，首先考虑顺序实现的以下代码片段：

```cs
public void Sequential()
{
    var books = GetBooks();
    foreach (var book in books) { Process(book); }
}
```

上面的代码是一个`Sequential`方法；它使用简单的`foreach`循环来处理书籍集合。执行程序并查看以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/fcc24a14-5414-42e8-b803-a9dc83c0429f.png)

注意上面的快照。首先，在我运行此演示的系统上有四个进程正在运行。第二个迭代的集合是按顺序从 1 到 19。程序不会将任务分成在机器上运行的不同进程。按任意键退出当前进程，执行`ParallelismVersion`方法的程序，并查看以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/a2119c1f-765c-4c1f-8350-971f9b585cab.png)

上面的截图是并行代码的输出；您可能会注意到代码没有按顺序处理，ID 也没有按顺序出现，我们可以看到`Id` `13`在`9`之后但在`10`之前。如果这些是按顺序运行的，那么`Id`的顺序将是`9`，`10`，然后是`13`。

在.NET Core 诞生之前，LINQ 就已经存在于.NET 世界中。`LINQ-to-Objects`允许我们使用任意对象序列执行内存中的查询操作。`LINQ-to-Objects`是建立在`IEnumerable<T>`之上的一组扩展方法。

**延迟执行**意味着数据枚举后才执行。

PLINQ 可以作为 TPL 的替代方案。它是 LINQ 的并行实现。PLINQ 查询操作在内存中的`IEnumerable`或`IEnumerable<T>`数据源上执行。此外，它具有延迟执行。LINQ 查询按顺序执行操作，而 PLINQ 并行执行操作，并充分利用机器上的所有处理器。考虑以下代码以查看 PLINQ 的实现：

```cs
public void Process()
{
    var bookCount = 50000;
    _parallelism.GenerateBooks(bookCount);
    var books = _parallelism.GetBooks();
    var query = from book in books.AsParallel()
        where book.Quantity > 12250
        select book;
    Console.WriteLine($"\n\t{query.Count()} books out of {bookCount} total books," +
                      "having Qty in stock more than 12250.");
    Console.ReadKey();
}
```

上面的代码是我们的 PLINQ 类的处理方法。在这里，我们使用 PLINQ 查询库存中数量超过`12250`的任何书籍。执行代码以查看此输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e1c27ddb-a490-46ce-8df1-1ade2ec4f248.png)

PLINQ 使用机器的所有处理器，但我们可以通过使用`WithDegreeOfParallelism()`方法来限制 PLINQ 中的处理器。我们可以在`Linq`类的`Process()`方法中使用以下代码：

```cs
var query = from book in books.AsParallel().WithDegreeOfParallelism(3)
    where book.Quantity > 12250
    select book;
return query;
```

上面的代码将只使用机器的三个处理器。执行它们，您会发现您得到与前面代码相同的输出。

# 总结

在本章中，我们讨论了并发编程和现实世界中的并发性。我们看了看如何处理与我们日常生活中的并发相关的各种情景。我们看了看如何从服务柜台收集会议门票，并了解了并行编程和并发编程是什么。我们还涵盖了多线程、`Async`/`Await`、`Concurrent`集合和 PLINQ。

在接下来的章节中，我们将尝试使用 C#语言进行函数式编程。我们将深入探讨这些概念，以展示如何在.NET Core 中使用 C#进行函数式编程。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  什么是并发编程？

1.  真正的并行性是如何发生的？

1.  什么是竞争条件？

1.  为什么我们应该使用并发字典？

# 进一步阅读

以下书籍将帮助您更多地了解本章涉及的主题：

+   *Concurrent Patterns and Best Practices*，作者*Atul S Khot*，由*Packt Publishing*出版：[`www.packtpub.com/in/application-development/concurrent-patterns-and-best-practices`](https://www.packtpub.com/in/application-development/concurrent-patterns-and-best-practices)


# 第九章：函数式编程实践

上一章（第八章，* .NET Core 中的并发编程*）介绍了.NET Core 中的并发编程，本章的目的是利用`async`/`await`和并行性，使我们的程序更加高效。

在本章中，我们将品尝使用 C#语言的函数式编程。我们还将深入探讨这些概念，向您展示如何利用.NET Core 中的 C#来执行函数式编程。本章的目的是帮助您了解函数式编程是什么，以及我们如何使用 C#语言来实现它。

函数式编程受数学启发，以函数式方式解决问题。在数学中，我们有公式，在函数式编程中，我们使用各种函数的数学形式。函数式编程的最大优点是它有助于无缝实现并发。

本章将涵盖以下主题：

+   理解函数式编程

+   库存应用程序

+   策略模式和函数式编程

# 技术要求

本章包含各种代码示例，以解释函数式编程的概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

完整的源代码可在以下链接找到：[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter9`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter9)。

要运行和执行代码，先决条件如下：

+   Visual Studio 2019（也可以使用 Visual Studio 2017 更新 3 或更高版本来运行应用程序）。

+   设置.NET Core

+   SQL Server（本章中使用 Express Edition）

# 安装 Visual Studio

要运行这些代码示例，您需要安装 Visual Studio 2017（或更新版本，如 2019）。要执行此操作，请按照以下说明操作：

1.  从以下下载链接下载 Visual Studio，其中包括安装说明：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照安装说明操作。

1.  Visual Studio 安装有多个版本可供选择。在这里，我们使用 Windows 的 Visual Studio。

# 设置.NET Core

如果您尚未安装.NET Core，需要按照以下说明操作：

1.  在[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)下载 Windows 的.NET Core。

1.  访问[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)获取多个版本和相关库。

# 安装 SQL Server

如果您尚未安装 SQL Server，需要按照以下说明操作：

1.  从以下链接下载 SQL Server：[`www.microsoft.com/en-in/download/details.aspx?id=1695`](https://www.microsoft.com/en-in/download/details.aspx?id=1695)。

1.  在此处找到安装说明：[`docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017`](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017)。

有关故障排除和更多信息，请参阅以下链接：[`www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm`](https://www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm)。

# 理解函数式编程

简而言之，**函数式编程**是一种符号计算的方法，它与解决数学问题的方式相同。任何函数式编程都是基于数学函数及其编码风格的。任何支持函数式编程的语言都可以解决以下两个问题：

+   它需要解决什么问题？

+   它是如何解决的？

函数式编程并不是一个新的发明。这种语言在行业中已经存在很长时间了。以下是一些支持函数式编程的知名编程语言：

+   Haskell

+   Scala

+   Erlang

+   Clojure

+   Lisp

+   OCaml

2005 年，微软发布了 F#的第一个版本（发音为*EffSharp—*[`fsharp.org/`](https://fsharp.org/)）。这是一种具有许多良好特性的函数式编程语言。在本章中，我们不会讨论太多关于 F#，但我们将讨论函数式编程及其在 C#语言中的实现。

纯函数是通过说它们是纯的来加强函数式编程的函数。这些函数在两个层面上工作：

+   最终结果/输出对于提供的参数始终保持不变。

+   它们不会影响程序的行为或应用程序的执行路径，即使它们被调用了一百次。

考虑一下我们 FlixOne 库存应用程序中的例子：

```cs
public static class PriceCalc
{
    public static decimal Discount(this decimal price, decimal discount) => 
        price * discount / 100;

    public static decimal PriceAfterDiscount(this decimal price, decimal discount) =>
        decimal.Round(price - Discount(price, discount));
}
```

正如你所看到的，我们有一个`PriceCalc`类，其中有两个扩展方法：`Discount`和`PriceAfterDiscount`。这些函数可以被称为纯函数；`PriceCalc`函数和`PriceAfterDiscount`函数都符合`纯`函数的标准；`Discount`方法将根据当前价格和折扣计算折扣。在这种情况下，该方法的输出对于提供的参数值永远不会改变。这样，价格为`190.00`且折扣为`10.00`的产品将以这种方式计算：`190.00 * 10.00 /100`，并返回`19.00`。我们的下一个方法—`PriceAfterDiscount`—使用相同的参数值将计算`190.00 - 19.00`并返回`171.00`的值。

函数式编程中另一个重要的点是函数是纯的，并传达完整的信息（也称为**函数诚实**）。考虑前面代码中的`Discount`方法；这是一个纯函数，也是诚实的。那么，如果有人意外地提供了负折扣或超过实际价格的折扣（超过 100%），这个函数还会保持纯和诚实吗？为了处理这种情况，我们的数学函数应该这样编写，如果有人输入`discount <= 0 or discount > 100`，那么系统将不予考虑。考虑以下代码以此方法编写：

```cs
public static decimal Discount(this decimal price, ValidDiscount validDiscount)
{
    return price * validDiscount.Discount / 100;
}
```

正如你所看到的，我们的`Discount`函数有一个名为`ValidDiscount`的参数类型，用于验证我们讨论的输入。这样，我们的函数现在是一个诚实的函数。

这些函数就像函数式编程一样简单，但是要想使用函数式编程仍然需要大量的实践。在接下来的章节中，我们将讨论函数式编程的高级概念，包括函数式编程原则。

考虑以下代码，我们正在检查折扣值是否有效：

```cs
private readonly Func<decimal, bool> _vallidDiscount = d => d > 0 || d % 100 <= 1;
```

在上面的代码片段中，我们有一个名为`_validDiscount`的字段。让我们看看它的作用：`Func`接受`decimal`作为输入，并返回`bool`作为输出。从它的名称可以看出，`field`只存储有效的折扣。

`Func`是一种委托类型，指向一个或多个参数的方法，并返回一个值。`Func`的一般声明是`Func<TParameter, TOutput>`，其中`TParameter`是任何有效数据类型的输入参数，`TOutput`是任何有效数据类型的返回值。

考虑以下代码片段，我们在一个方法中使用了`_validDiscount`字段：

```cs
public IEnumerable<DiscountViewModel> FilterOutInvalidDiscountRates(
    IEnumerable<DiscountViewModel> discountViewModels)
{
    var viewModels = discountViewModels.ToList();
    var res = viewModels.Select(x => x.Discount).Where(_vallidDiscount);
    return viewModels.Where(x => res.Contains(x.Discount));
}
```

在上述代码中，我们有`FilterOutInvalidDiscountRates`方法。这个方法不言自明，表明我们正在过滤掉无效的折扣率。现在让我们分析一下代码。

`FilterOutInvalidDiscountRates`方法返回一个具有有效折扣的产品的`DiscountViewModel`类的集合。以下代码是我们的`DiscountViewModel`类的代码：

```cs
public class DiscountViewModel
{
    public Guid ProductId { get; set; }
    public string ProductName { get; set; }
    public decimal Price { get; set; }
    public decimal Discount { get; set; }
    public decimal Amount { get; set; }
}
```

我们的`DiscountViewModel`类包含以下内容：

+   `ProductId`：这代表一个产品的 ID。

+   `ProductName`：这代表一个产品的名称。

+   `Price`：这包含产品的实际价格。实际价格是在任何折扣、税收等之前。

+   `Discount`：这包含折扣的百分比，如 10 或 3。有效的折扣率不应为负数，等于零或超过 100%（换句话说，不应超过产品的实际成本）。

+   `Amount`：这包含任何折扣、税收等之后的产品价值。

现在，让我们回到我们的`FilterOutInavlidDiscountRates`方法，看一下`viewModels.Select(x => x.Discount).Where(_vallidDiscount)`。在这里，您可能会注意到我们正在从我们的`viewModels`列表中选择折扣率。这个列表包含根据`_validDiscount`字段有效的折扣率。在下一行，我们的方法返回具有有效折扣率的记录。

在函数式编程中，这些函数也被称为**一等函数**。这些函数的值可以作为任何其他函数的输入或输出使用。它们也可以被分配给变量或存储在集合中。

转到 Visual Studio 并打开`FlixOne`库存应用程序。从这里运行应用程序，您将看到以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/a92e6211-c9db-44ae-8dde-6c0cff7213f5.png)

上一张屏幕截图是产品列表页面，显示了所有可用的产品。这是一个简单的页面；您也可以称之为产品列表仪表板，在这里您将找到所有产品。从创建新产品，您可以添加一个新产品，编辑将为您提供更新现有产品的功能。此外，详细页面将显示特定产品的完整详细信息。通过单击删除，您可以从列表中删除现有产品。

请参考我们的`DiscountViewModel`类。我们有多个产品的折扣率选项，业务规则规定一次只能激活一个折扣率。要查看产品的所有折扣率，请从前一屏幕（产品列表）中单击折扣率。这将显示以下屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/70619b88-ea6e-4cbd-814b-22c43ab44ae0.png)

上述屏幕是产品折扣列表，显示了产品名称 Mango 的折扣列表。这有两个折扣率，但只有季节性折扣率是活动的。您可能已经注意到备注栏；这被标记为无效的折扣率，因为根据前一节讨论的`_validDiscount`，这个折扣率不符合有效折扣率的标准。

`Predicate`也是一种委托类型，类似于`Func`委托。这代表一个验证一组标准的方法。换句话说，`Predicate`返回`Predicate <T>`类型，其中`T`是有效的数据类型。如果标准匹配并返回`T`类型的值，则它起作用。

考虑以下代码，我们在其中验证产品名称是否有效为句子大小写：

```cs
private static readonly TextInfo TextInfo = new CultureInfo("en-US", false).TextInfo;
private readonly Predicate<string> _isProductNameTitleCase = s => s.Equals(TextInfo.ToTitleCase(s));
```

在上述代码中，我们使用了`Predicate`关键字，这分析了使用`TitleCase`关键字验证`ProductName`的条件。如果标准匹配，结果将是`true`。如果不匹配，结果将是`false`。考虑以下代码片段，我们在其中使用了`_isProductNameTitleCase`：

```cs
public IEnumerable<ProductViewModel> FilterOutInvalidProductNames(
    IEnumerable<ProductViewModel> productViewModels) => productViewModels.ToList()
    .Where(p => _isProductNameTitleCase(p.ProductName));
```

在前面的代码中，我们有`FilterOutInvalidProductNames`方法。该方法的目的是选择具有有效产品名称（仅`TitleCase`产品名称）的产品。

# 增强我们的库存应用程序

该项目是针对一个假设情况，即一家名为 FlixOne 的公司希望增强一个库存管理应用程序，以管理其不断增长的产品收藏。这不是一个新的应用程序，因为我们已经开始开发这个应用程序，并在第三章中讨论了初始阶段，即*实施设计模式 - 基础部分 1*，在那里我们已经开始开发基于控制台的库存系统。利益相关者将不时审查应用程序，并尝试满足最终用户的需求。增强非常重要，因为这个应用程序将被员工（用于管理库存）和客户（用于浏览和创建新订单）使用。该应用程序需要具有可扩展性，并且是业务的重要系统。

由于这是一本技术书，我们将主要从开发团队的角度讨论各种技术观察，并讨论用于实现库存管理应用的模式和实践。

# 要求

有必要增强应用程序，这不可能在一天内完成。这将需要大量的会议和讨论。在几次会议的过程中，业务和开发团队讨论了对库存管理系统的新增强的要求。定义一组清晰的要求的进展缓慢，最终产品的愿景也不清晰。开发团队决定将庞大的需求列表精简到足够的功能，以便一个关键人物可以开始记录一些库存信息。这将允许简单的库存管理，并为业务提供一个可以扩展的基础。我们将按照需求进行工作，并采取**最小可行产品**（**MVP**）的方法。

MVP 是一个应用程序的最小功能集，仍然可以发布并为用户群体提供足够的价值。

在管理层和业务分析师之间进行了几次会议和讨论后，产生了一系列要求的清单，以增强我们的`FlixOne` web 应用程序。高级要求如下：

+   **分页实现**：目前，所有页面列表都没有分页。通过向下滚动或向上滚动屏幕来查看具有大页数的项目是非常具有挑战性的。

+   **折扣率**：目前，没有提供添加或查看产品的各种折扣率。折扣率的业务规则如下：

+   一个产品可以有多个折扣率。

+   一个产品只能有一个活动的折扣率。

+   有效的折扣率不应为负值，也不应超过 100%。

# 回到 FlixOne

在前一节中，我们讨论了增强应用程序所需的内容。在本节中，我们将实现这些要求。让我们首先重新审视一下我们项目的文件结构。看一下下面的快照：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/fb23aa69-1daf-4775-b51f-5afe3c7d9bc9.png)

之前的快照描述了我们的 FlixOne web 应用程序，其文件夹结构如下：

+   **wwwroot**：这是一个带有静态内容的文件夹，例如 CSS 和 jQuery 文件，这些文件是 UI 项目所需的。该文件夹带有 Visual Studio 提供的默认模板。

+   **公共**：这包含所有与业务规则和更多相关的公共文件和操作。

+   **上下文**：这包含`InventoryContext`，这是一个提供`Entity Framework Core`功能的`DBContext`类。

+   **控制器**：这包含我们`FlixOne`应用程序的所有控制器类。

+   **迁移**：这包含了`InventoryModel`的快照和最初创建的实体。

+   **模型**：这包含了我们应用程序所需的数据模型、`ViewModels`。

+   **持久性**：这包含了`InventoryRepository`及其操作。

+   **视图**：这包含了应用程序的所有视图/屏幕。

考虑以下代码：

```cs
public interface IHelper
{
    IEnumerable<DiscountViewModel> FilterOutInvalidDiscountRates(
        IEnumerable<DiscountViewModel> discountViewModels);

    IEnumerable<ProductViewModel> FilterOutInvalidProductNames(
        IEnumerable<ProductViewModel> productViewModels);
}
```

上面的代码包含一个`IHelper`接口，其中包含两个方法。我们将在下面的代码片段中实现这个接口：

```cs
public class Helper : IHelper
{
    private static readonly TextInfo TextInfo = new CultureInfo("en-US", false).TextInfo;
    private readonly Predicate<string> _isProductNameTitleCase = s => s.Equals(TextInfo.ToTitleCase(s));
    private readonly Func<decimal, bool> _vallidDiscount = d => d == 0 || d - 100 <= 1;

    public IEnumerable<DiscountViewModel> FilterOutInvalidDiscountRates(
        IEnumerable<DiscountViewModel> discountViewModels)
    {
        var viewModels = discountViewModels.ToList();
        var res = viewModels.Select(x => x.ProductDiscountRate).Where(_vallidDiscount);
        return viewModels.Where(x => res.Contains(x.ProductDiscountRate));
    }

    public IEnumerable<ProductViewModel> FilterOutInvalidProductNames(
        IEnumerable<ProductViewModel> productViewModels) => productViewModels.ToList()
        .Where(p => _isProductNameTitleCase(p.ProductName));
}
```

`Helper`类实现了`IHelper`接口。在这个类中，我们有两个主要且重要的方法：一个是检查有效折扣，另一个是检查有效的`ProductName`属性。

在我们的应用程序中使用这个功能之前，我们应该将它添加到我们的`Startup.cs`文件中，如下面的代码所示：

```cs
public void ConfigureServices(IServiceCollection services)
{
    services.AddTransient<IInventoryRepositry, InventoryRepositry>();
    services.AddTransient<IHelper, Helper>();
    services.AddDbContext<InventoryContext>(o => o.UseSqlServer(Configuration.GetConnectionString("FlixOneDbConnection")));
    services.Configure<CookiePolicyOptions>(options =>
    {
        // This lambda determines whether user consent for non-essential cookies is needed for a given request.
        options.CheckConsentNeeded = context => true;
        options.MinimumSameSitePolicy = SameSiteMode.None;
    });
}
```

在上面的代码片段中，我们有一个写入语句，`services.AddTransient<IHelper, Helper>();`。通过这样做，我们向我们的应用程序添加了一个瞬态服务。我们已经在第五章中讨论了*控制反转*部分，*实现设计模式-.Net Core*。

考虑以下代码，我们在这里使用`IHelper`类，利用了控制反转：

```cs
public class InventoryRepositry : IInventoryRepositry
{
    private readonly IHelper _helper;
    private readonly InventoryContext _inventoryContext;

    public InventoryRepositry(InventoryContext inventoryContext, IHelper helper)
    {
        _inventoryContext = inventoryContext;
        _helper = helper;
    }

... 
}
```

上面的代码包含了`InventoryRepository`类，我们可以看到适当使用了**依赖注入**（**DI**）：

```cs
    public IEnumerable<Discount> GetDiscountBy(Guid productId, bool activeOnly = false)
        {
            var discounts = activeOnly
                ? GetDiscounts().Where(d => d.ProductId == productId && d.Active)
                : GetDiscounts().Where(d => d.ProductId == productId);
            var product = _inventoryContext.Products.FirstOrDefault(p => p.Id == productId);
            var listDis = new List<Discount>();
            foreach (var discount in discounts)
            {
                if (product != null)
                {
                    discount.ProductName = product.Name;
                    discount.ProductPrice = product.Price;
                }

                listDis.Add(discount);
            }

            return listDis;
        }
```

上面的代码是`InventoryRepository`类的`GetDiscountBy`方法，它返回了`active`或`de-active`记录的折扣模型集合。考虑以下用于`DiscountViewModel`集合的代码片段：

```cs
    public IEnumerable<DiscountViewModel> GetValidDiscoutedProducts(
        IEnumerable<DiscountViewModel> discountViewModels)
    {
        return _helper.FilterOutInvalidDiscountRates(discountViewModels);
    }
}
```

上面的代码使用了一个`DiscountViewModel`集合，过滤掉了根据我们之前讨论的业务规则没有有效折扣的产品。`GetValidDiscountProducts`方法返回`DiscountViewModel`的集合。

如果我们忘记在项目的`startup.cs`文件中定义`IHelper`，我们将会遇到一个异常，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/18dae3fc-bf2b-4296-be43-c0447ffc8d47.png)

上面的截图清楚地表明`IHelper`服务没有被解析。在我们的情况下，我们不会遇到这个异常，因为我们已经将`IHelper`添加到了`Startup`类中。

到目前为止，我们已经添加了辅助方法来满足我们对折扣率的新要求，并对其进行验证。现在，让我们添加一个控制器和随后的操作方法。为此，从解决方案资源管理器中添加一个新的`DiscountController`控制器。之后，我们的`FlixOne` web 解决方案将看起来类似于以下快照：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/8c9cb2fd-c823-4cd2-bcac-143a3fd6ff2c.png)

在上面的快照中，我们可以看到我们的`Controller`文件夹现在有一个额外的控制器，即`DiscountController`。以下代码来自`DiscountController`：

```cs
public class DiscountController : Controller
{
    private readonly IInventoryRepositry _repositry;

    public DiscountController(IInventoryRepositry inventoryRepositry)
    {
        _repositry = inventoryRepositry;
    }

    public IActionResult Index()
    {
        return View(_repositry.GetDiscounts().ToDiscountViewModel());
    }

    public IActionResult Details(Guid id)
    {
        return View("Index", _repositry.GetDiscountBy(id).ToDiscountViewModel());
    }
}
```

执行应用程序，并从主屏幕上点击产品，然后点击产品折扣清单。从这里，你将得到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b228c14a-47b4-427b-9f13-b4bff9507521.png)

上面的快照描述了所有可用产品的产品折扣清单。产品折扣清单有很多记录，因此需要向上或向下滚动以查看屏幕上的项目。为了处理这种困难的情况，我们应该实现分页。

# 策略模式和函数式编程

在本书的前四章中，我们讨论了很多模式和实践。策略模式是**四人帮**模式中的重要模式之一。这属于行为模式类别，也被称为策略模式。这通常是使用类来实现的模式。这也是一个更容易使用函数式编程实现的模式。

回到本章的*理解函数式编程*部分，重新考虑函数式编程的范式。高阶函数是函数式编程的重要范式之一；使用它，我们可以轻松地以函数式的方式实现策略模式。

**高阶函数**（**HOFs**）是接受函数作为参数的函数。它们也可以返回函数。

考虑以下代码，展示了函数式编程中 HOFs 的实现：

```cs
public static IEnumerable<T> Where<T>
    (this IEnumerable<T> source, Func<T, bool> criteria)
{
    foreach (var item in source)
        if (criteria(item))
            yield return item;
}
```

上述代码是`Where`子句的简单实现，我们在其中使用了`LINQ 查询`。在这里，我们正在迭代一个集合，并在满足条件时返回一个项。上述代码可以进一步简化。考虑以下更简化版本的代码：

```cs
public static IEnumerable<T> SimplifiedWhere<T>
    (this IEnumerable<T> source, Func<T, bool> criteria) => 
    Enumerable.Where(source, criteria);
```

正如你所看到的，`SimplifiedWhere`方法产生了与之前讨论的`Where`方法相同的结果。这个方法是基于条件的，并且有一个返回结果的策略，这个条件在运行时执行。我们可以轻松地在后续方法中调用上述函数，以利用函数式编程。考虑以下代码：

```cs
public IEnumerable<ProductViewModel>
    GetProductsAbovePrice(IEnumerable<ProductViewModel> productViewModels, decimal price) =>
    productViewModels.SimplifiedWhere(p => p.ProductPrice > price);
```

我们有一个名为`GetProductsAbovePrice`的方法。在这个方法中，我们提供了价格。这个方法很容易理解，它在一个`ProductViewModel`的集合上工作，并根据条件列出产品价格高于参数价格的产品。在我们的`FlixOne`库存应用中，你可以找到更多实现函数式编程的范围。

# 总结

函数式编程关注的是函数，主要是数学函数。任何支持函数式编程的语言都会通过两个主要问题来解决问题：需要解决什么，以及如何解决？我们看到了函数式编程及其在 C#编程语言中的简单实现。

我们还学习了`Func`、`Predicate`、LINQ、`Lambda`、匿名函数、闭包、表达式树、柯里化、闭包和递归。最后，我们研究了使用函数式编程实现策略模式。

在下一章（第十章，*响应式编程模式和技术*）中，我们将讨论响应式编程以及其模型和原则。我们还将讨论**响应式扩展**。

# 问题

以下问题将帮助你巩固本章中包含的信息：

1.  什么是函数式编程？

1.  函数式编程中的引用透明是什么？

1.  什么是纯函数？


# 第十章：响应式编程模式和技术

在上一章（第九章，*函数式编程实践*）中，我们深入研究了函数式编程，并了解了**Func**，**Predicate**，**LINQ**，**Lambda**，**匿名函数**，**表达式树**和**递归**。我们还看了使用函数式编程实现策略模式。

本章将探讨响应式编程的使用，并提供使用 C#语言进行响应式编程的实际演示。我们将深入探讨响应式编程的原理和模型，并讨论`IObservable`和`IObserver`提供程序。

库存应用程序将通过对变化的反应和讨论**Model-View-ViewModel**（**MVVM**）模式来进行扩展。

本章将涵盖以下主题：

+   响应式编程的原则

+   响应式和 IObservable

+   响应式扩展 - .NET Rx 扩展

+   库存应用程序用例 - 使用过滤器、分页和排序获取库存

+   模式和实践 - MVVM

# 技术要求

本章包含各种代码示例，以解释响应式编程的概念。代码保持简单，仅用于演示目的。大多数示例涉及使用 C#编写的.NET Core 控制台应用程序。

完整的源代码可在以下链接找到：[`github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter10`](https://github.com/PacktPublishing/Hands-On-Design-Patterns-with-C-and-.NET-Core/tree/master/Chapter10)。

运行和执行代码将需要以下内容：

+   Visual Studio 2019（也可以使用 Visual Studio 2017）

+   设置.NET Core

+   SQL Server（本章中使用 Express Edition）

# 安装 Visual Studio

要运行代码示例，您需要安装 Visual Studio（首选 IDE）。要做到这一点，您可以按照以下说明进行操作：

1.  从安装说明中提到的下载链接下载 Visual Studio 2017 或更高版本（2019）：[`docs.microsoft.com/en-us/visualstudio/install/install-visual-studio`](https://docs.microsoft.com/en-us/visualstudio/install/install-visual-studio)。

1.  按照安装说明进行操作。

1.  Visual Studio 安装有多个选项可用。在这里，我们使用 Windows 的 Visual Studio。

# 设置.NET Core

如果您尚未安装.NET Core，则需要按照以下步骤进行操作：

1.  下载 Windows 的.NET Core：[`www.microsoft.com/net/download/windows`](https://www.microsoft.com/net/download/windows)。

1.  对于多个版本和相关库，请访问[`dotnet.microsoft.com/download/dotnet-core/2.2`](https://dotnet.microsoft.com/download/dotnet-core/2.2)。

# 安装 SQL Server

如果您尚未安装 SQL Server，则可以按照以下说明进行操作：

1.  从以下链接下载 SQL Server：[`www.microsoft.com/en-in/download/details.aspx?id=1695`](https://www.microsoft.com/en-in/download/details.aspx?id=1695)。

1.  您可以在此处找到安装说明：[`docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017`](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017)。

有关故障排除和更多信息，请参考以下链接：[`www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm`](https://www.blackbaud.com/files/support/infinityinstaller/content/installermaster/tkinstallsqlserver2008r2.htm)。

# 响应式编程的原则

如今，每个人都在谈论**异步编程**。各种应用程序都建立在使用异步编程的 RESTful 服务之上。术语*异步*与响应式编程相关。响应式编程关乎数据流，而响应式编程是围绕异步数据流构建的模型结构。响应式编程也被称为*变化传播的艺术*。让我们回到第八章中的例子，*在.NET Core 中进行并发编程*，我们当时正在讨论大型会议上的取票柜台。

除了三个取票柜台，我们还有一个名为计算柜台的柜台。这第四个柜台专注于计算收集，它计算从三个柜台中分发了多少张票。考虑以下图表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/747ea7b4-c8c3-4740-a44a-fb4986c84231.png)

在上图中，A+B+C 的总和是剩下三列的总和；即 1+1+1=3。**总计**列总是显示剩下三列的总和，它永远不会显示实际站在队列中等待领取票的人。**总计**列的值取决于剩下的列的数量。如果**A 柜台**中有两个人在队列中，那么**总计**列将是 2+1+1=4。你也可以把**总计**列称为计算列。这一列在其他行/列移动其计数（排队等候的人）时计算总和。如果我们要用 C#编写**总计**列，我们会选择计算属性，代码如下：`public int TotalColumn { get { return ColumnA + ColumnB + ColumnC; } }`。

在上图中，数据从一列流向另一列。你可以把这看作是一个数据流。你可以为任何事物创建一个流，比如点击事件和悬停事件。任何东西都可以是一个流变量：用户输入、属性、缓存、数据结构等等。在流世界中，你可以监听流并做出相应的反应。

一系列事件被称为**流**。流可以发出三种东西：一个值，一个错误和一个完成的信号。

你可以轻松地使用流进行工作：

+   一个流可以作为另一个流的输入。

+   多个流可以作为另一个流的输入。

+   流可以合并。

+   数据值可以从一个流映射到另一个流。

+   流可以用你需要的数据/事件进行过滤。

要更近距离地了解流，看看下面代表流（事件序列）的图表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e147faca-305d-440c-87b6-0ba924c39f34.png)

上图是一个流（事件序列）的表示，其中我们有一到四个事件。任何这些事件都可以被触发，或者有人可以点击它们中的任何一个。这些事件可以用值来表示，这些值可以是字符串。X 符号表示在合并流或映射它们的数据过程中发生了错误。最后，|符号表示一个流（或一个操作）已经完成。

# 用响应式编程来实现响应式

显然，我们在前一节中讨论的计算属性不能是响应式的，也不能代表响应式编程。响应式编程具有特定的设计和技术。要体验响应式编程或成为响应式，你可以从[`reactivex.io/`](http://reactivex.io/)上获取文档，并通过阅读响应式宣言([`www.reactivemanifesto.org/`](https://www.reactivemanifesto.org/))来体验它[.](https://www.reactivemanifesto.org/)

简单来说，响应式属性是绑定属性，当事件触发时会做出反应。

如今，当我们处理各种大型系统/应用程序时，我们发现它们太大，无法一次处理。这些大型系统被分割或组成较小的系统。这些较小的单元/系统依赖于反应性属性。为了遵循反应式编程，反应式系统应用设计原则，使这些属性可以应用于所有方法。借助这种设计/方法，我们可以构建一个可组合的系统。

根据宣言，反应式编程和反应式系统是**不同**的。

根据反应式宣言，我们可以得出反应式系统如下：

+   **响应式**：反应式系统是基于事件的设计系统；这些系统能够在短时间内快速响应任何请求。

+   **可扩展**：反应式系统天生具有反应性。这些系统可以通过扩展或减少分配的资源来对可扩展性变化做出反应。

+   **弹性**：弹性系统是指即使出现故障/异常也不会停止的系统。反应式系统设计成这样，以便在任何异常或故障中，系统都不会崩溃；它会继续工作。

+   **基于消息的**：任何数据项都代表可以发送到特定目的地的消息。当消息或数据项到达给定状态时，事件会发出信号通知订阅者消息已到达。反应式系统依赖于这种消息传递。

下图显示了反应式系统的图形视图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/2e361032-d61e-429f-a4f8-9745429379ec.png)

在这个图表中，反应式系统由具有弹性、可扩展、响应式和基于消息的小系统组成。

# 反应式流的操作

到目前为止，我们已经讨论了反应式编程是数据流的事实。在前面的部分中，我们还讨论了流的工作方式以及这些流如何及时传输。我们已经看到了事件的一个例子，并讨论了反应式程序中的数据流。现在，让我们继续使用相同的示例，看看两个流如何与各种操作一起工作。

在下一个示例中，我们有两个整数数据类型集合的可观察流。请注意，我们在本节中使用伪代码来解释这些数据流的行为和工作方式。

下图表示了两个可观察流。第一个流`Observer1`包含数字 1、2 和 4，而第二个流`Observer2`包含数字 3 和 5：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/35ab0fbd-3968-400c-9032-08126e65ac7a.png)

合并两个流涉及将它们的序列元素合并成一个新流。下图显示了当`Observer1`和`Observer2`合并时产生的新流：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d4aeb61d-ed6b-4fcf-9a24-8562bed48a92.png)

前面的图表只是流的表示，不是流中元素顺序的实际表示。在这个图表中，我们看到元素（数字）的顺序是 1、2、3、4、5，但在实际例子中并非如此。顺序可能会变化；它可以是 1、2、4、3、5，或者任何其他顺序。

过滤流就像跳过元素/记录一样。你可以想象 LINQ 中的`Where`子句，看起来像这样：`myCollection.Where(num => num <= 3);`。

下图说明了标准的图形视图，我们试图仅选择符合特定标准的元素：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/1a2965f1-b4a3-4034-82f1-7119a41fad65.png)

我们正在过滤我们的流，并只选择那些*<=3*的元素。这意味着我们跳过元素 4 和 5。在这种情况下，我们可以说过滤器是用来跳过元素或符合标准的。

要理解映射流，您可以想象任何数学运算，例如通过添加一些常数值来计数序列或递增数字。例如，如果我们有一个整数值为*3*，而我们的映射流是*+3*，那意味着我们正在计算一个序列，如*3 + 3 = 6*。您还可以将其与 LINQ 和选择以及像这样投影输出进行关联：`return myCollection.Select(num => num+3);`。

以下图表表示了流的映射：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/031e8a71-9f81-475c-ac46-ae15cd06bc7c.png)

在应用条件为*<= 3*的过滤器后，我们的流具有元素**1**、**2**和**3**。此外，我们对过滤后的流应用了`Map (+3)`，其中包含元素**1**、**2**和**3**，最后，我们的流具有元素**4**、**5**、**6**（1+3, 2+3, 3+3）。

在现实世界中，这些操作将按顺序或按需发生。我们已经按顺序执行了这些序列操作，以便我们可以按顺序应用合并、过滤和映射操作。以下图表表示我们想象中例子的流程：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/c3bfc2c2-2d3a-484f-a99f-8f8c3082316c.png)

因此，我们尝试通过图表来表示我们的例子，并且我们已经经历了各种操作，其中两个流相互交谈，我们得到了一个新的流，然后我们过滤和映射了这个流。

要更好地理解这一点，请参考[`rxmarbles.com/`](https://rxmarbles.com/)。

现在让我们创建一个简单的代码来完成这个真实世界的例子。首先，我们将学习实现示例的代码，然后我们将讨论流的输出。

考虑以下代码片段作为`IObservable`接口的示例：

`public static IObservable<T> From<T>(this T[] source) => source.ToObservable();`

这段代码表示了`T`类型数组的扩展方法。我们创建了一个通用方法，并命名为`From`。这个方法返回一个`Observable`序列。

您可以访问官方文档了解更多关于扩展方法的信息：[`docs.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/extension-methods`](https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/classes-and-structs/extension-methods)。

在我们的代码中，我们有`TicketCounter`类。这个类有两个观察者，实际上是整数数据类型的数组。以下代码显示了两个可观察对象：

```cs
public IObservable<int> Observable1 => Counter1.From();
public IObservable<int> Observable2 => Counter2.From();
```

在这段代码中，我们将`From()`扩展方法应用于`Counter1`和`Counter2`。这些计数器实际上代表我们的售票处，并回顾了我们在第八章中的例子，*在.NET Core 中进行并发编程*。

以下代码片段表示`Counter1`和`Counter2`：

```cs
internal class TicketCounter
{
    private IObservable<int> _observable;
    public int[] Counter1;
    public int[] Counter2;
    public TicketCounter(int[] counter1, int[] counter2)
    {
        Counter1 = counter1;
        Counter2 = counter2;
    }
...
}
```

在这段代码中，我们有两个字段，`Counter1`和`Counter2`，它们是从构造函数中初始化的。当初始化`TicketCounter`类时，这些字段从类的构造函数中获取值，如下面的代码所定义的：

```cs
TicketCounter ticketCounter = new TicketCounter(new int[]{1,3,4}, new int[]{2,5});
```

要理解完整的代码，请转到 Visual Studio 并按下*F5*执行代码。从这里，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/7ca5c074-4bcc-4994-bb14-27c1f6df5946.png)

这是控制台输出，在这个控制台窗口中，用户被要求输入一个从`0`到`9`的逗号分隔数字。继续并在这里输入一个逗号分隔的数字。请注意，这里，我们试图创建一个代码，描述我们之前在本节中讨论的数据流表示的图表。

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d898ad73-55f7-4510-8b2b-b860bce2c9cf.png)

根据前面的图表，我们输入了两个不同的逗号分隔数字。第一个是`1,2,4`，第二个是`3,5`。现在考虑我们的`Merge`方法：

```cs
public IObservable<int> Merge() => _observable = Observable1.Merge(Observable2);
```

`Merge`方法将数据流的两个序列合并为`_observable`。`Merge`操作是通过以下代码启动的：

```cs
Console.Write("\n\tEnter comma separated number (0-9): ");
var num1 = Console.ReadLine();
Console.Write("\tEnter comma separated number (0-9): ");
var num2 = Console.ReadLine();
var counter1 = num1.ToInts(',');
var counter2 = num2.ToInts(',');
TicketCounter ticketCounter = new TicketCounter(counter1, counter2);
```

在这段代码中，用户被提示输入逗号分隔的数字，然后程序通过`ToInts`方法将这些数字存储到`counter1`和`counter2`中。以下是我们`ToInts`方法的代码：

```cs
public static int[] ToInts(this string commaseparatedStringofInt, char separator) =>
    Array.ConvertAll(commaseparatedStringofInt.Split(separator), int.Parse);
```

这段代码是`string`的扩展方法。目标变量是一个包含由`separator`分隔的整数的`string`类型。在这个方法中，我们使用了.NET Core 提供的内置`ConvertAll`方法。它首先分割字符串，并检查分割值是否为`integer`类型。然后返回整数的`Array`。这个方法产生的输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/481c8752-3a12-4265-86d3-05dd0b57ceca.png)

以下是我们`merge`操作的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b45912b4-2e62-4a21-8fad-4ea7d1524d85.png)

上述输出显示，我们现在有了一个最终合并的观察者流，其中包含了按顺序排列的元素。让我们对这个流应用一个筛选器。以下是我们的`Filter`方法的代码：

```cs
public IObservable<int> Filter() => _observable = from num in _observable
    where num <= 3
    select num;
```

我们有数字`<= 3`的筛选条件，这意味着我们只会选择值小于或等于`3`的元素。这个方法将以以下代码开始：

```cs
ticketCounter.Print(ticketCounter.Filter());
```

当执行上述代码时，会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/22aede10-aae2-4fee-9e9d-8d549af5ea7d.png)

最后，我们得到了一个按顺序排列的筛选流，其中包含了元素 1,3,2。现在我们需要在这个流上进行映射。我们需要一个通过`num + 3`得到的映射元素，这意味着我们需要通过给这个数字加上`3`来输出一个整数。以下是我们的`Map`方法：

```cs
public IObservable<int> Map() => _observable = from num in _observable
    select num + 3;
```

上述方法将以以下代码初始化：

```cs
Console.Write("\n\tMap (+ 3):");
ticketCounter.Print(ticketCounter.Map());
```

执行上述方法后，我们将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/b1f0aa3c-79ef-48d4-98e2-c178c079b892.png)

应用`Map`方法后，我们得到了一个按顺序排列的元素流 4,6,5。我们已经讨论了响应式如何与一个虚构的例子一起工作。我们创建了一个小的.NET Core 控制台应用程序，以查看`Merge`，`Filter`和`Map`操作对可观察对象的影响。以下是我们控制台应用程序的输出：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/8ed54e75-5467-4282-ab32-9dbf41194cfa.png)

前面的快照讲述了我们示例应用程序的执行过程；`Counter1`和`Counter2`是包含数据序列 1,2,4 和 3,5 的数据流。我们有了`Merge`的输出结果是`1,3,2,5,4 Filter (<=3)`，结果是 1,3,2 和`Map (+3)`的数据是 4,6,5。

# 响应式和 IObservable

在前面的部分，我们讨论了响应式编程并了解了它的模型。在这一部分，我们将讨论微软对响应式编程的实现。针对.NET Core 中的响应式编程，我们有各种接口，提供了在我们的应用程序中实现响应式编程的方法。

`IObservable<T>`是一个泛型接口，定义在`System`命名空间中，声明为`public interface IObservable<out T>`。在这里，`T`代表提供通知信息的泛型参数类型。简单来说，这个接口帮助我们定义了一个通知的提供者，这些通知可以被推送出去。在你的应用程序中实现`IObservable<T>`接口时，可以使用观察者模式。

# 观察者模式 - 使用 IObservable<T>进行实现

简单来说，订阅者注册到提供者，以便订阅者可以得到与消息信息相关的通知。这些通知通知提供者消息已经被传递给订阅者。这些信息也可能与操作的变化或方法或对象本身的任何其他变化相关。这也被称为**状态变化**。

观察者模式指定了两个术语：观察者和可观察对象。可观察对象也称为提供者或主题。观察者注册在`Observable`/`Subject`/`Provider`类型上，并且当由于预定义的标准/条件、更改或事件等发生任何变化时，提供者会自动通知观察者。

下面的图表是观察者模式的简单表示，其中主题通知了两个不同的观察者：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/4d2b83fd-d913-4456-bf7a-b587b7e12da5.png)

从第九章的`FlixOne`库存 Web 应用程序返回，*功能编程实践*，启动你的 Visual Studio，并打开`FlixOne.sln`解决方案。

打开解决方案资源管理器。从这里，你会看到我们的项目看起来类似于以下快照：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/6c18ba34-8fb5-4905-b012-8d55995ca8fc.png)

在解决方案资源管理器下展开`Common`文件夹，并添加两个文件：`ProductRecorder.cs`和`ProductReporter.cs`。这些文件是`IObservable<T>`和`IObserver<T>`接口的实现。我们还需要添加一个新的 ViewModel，以便向用户报告实际的消息。为此，展开`Models`文件夹并添加`MessageViewModel.cs`文件。

以下代码展示了我们的`MessageViewModel`类：

```cs
public class MessageViewModel
{
    public string MsgId { get; set; }
    public bool IsSuccess { get; set; }
    public string Message { get; set; }

    public override string ToString() => $"Id:{MsgId}, Success:{IsSuccess}, Message:{Message}";
}
```

`MessageViewModel`包含以下内容：

+   `MsgId`：唯一标识符

+   `IsSuccess`：显示操作是失败还是成功。

+   `Message`：根据`IsSuccess`的值而定的成功消息或错误消息

+   `ToString()`：一个重写方法，在连接所有信息后返回一个字符串

现在让我们讨论我们的两个类；以下代码来自`ProductRecorder`类：

```cs
public class ProductRecorder : IObservable<Product>
{
    private readonly List<IObserver<Product>> _observers;

    public ProductRecorder() => _observers = new List<IObserver<Product>>();

    public IDisposable Subscribe(IObserver<Product> observer)
    {
        if (!_observers.Contains(observer))
            _observers.Add(observer);
        return new Unsubscriber(_observers, observer);
    }
...
}
```

我们的`ProductRecorder`类实现了`IObservable<Product>`接口。如果你回忆一下我们关于观察者模式的讨论，你会知道这个类实际上是一个提供者、主题或可观察对象。`IObservable<T>`接口有一个`Subscribe`方法，我们需要用它来订阅我们的订阅者或观察者（我们将在本节后面讨论观察者）。

应该有一个标准或条件，以便订阅者可以收到通知。在我们的情况下，我们有一个`Record`方法来实现这个目的。考虑以下代码：

```cs
public void Record(Product product)
{
    var discountRate = product.Discount.FirstOrDefault(x => x.ProductId == product.Id)?.DiscountRate;
    foreach (var observer in _observers)
    {
        if (discountRate == 0 || discountRate - 100 <= 1)
            observer.OnError(
                new Exception($"Product:{product.Name} has invalid discount rate {discountRate}"));
        else
            observer.OnNext(product);
    }
}
```

前面是一个`Record`方法。我们创建这个方法来展示模式的强大之处。这个方法只是检查有效的折扣率。如果根据标准/条件，`折扣率`无效，这个方法将引发异常并与无效的`折扣率`一起分享产品名称。

前面的方法根据标准验证折扣率，并在标准失败时向订阅者发送关于引发异常的通知。看一下迭代块（`foreach`循环）并想象一种情况，我们没有任何东西可以迭代，所有订阅者都已经收到通知。我们能想象在这种情况下会发生什么吗？同样的情况可能会发生在无限循环中。为了阻止这种情况，我们需要一些终止循环的东西。为此，我们有以下的`EndRecording`方法：

```cs
public void EndRecording()
{
    foreach (var observer in _observers.ToArray())
        if (_observers.Contains(observer))
            observer.OnCompleted();
    _observers.Clear();
}
```

我们的`EndRecoding`方法正在循环遍历`_observers`集合，并显式触发`OnCompleted()`方法。最后，它清除了`_observers`集合。

现在，让我们讨论`ProductReporter`类。这个类是`IObserver<T>`接口实现的一个例子。考虑以下代码：

```cs
public void OnCompleted()
{
    PrepReportData(true, $"Report has completed: {Name}");
    Unsubscribe();
}

public void OnError(Exception error) => PrepReportData(false, $"Error ocurred with instance: {Name}");

public void OnNext(Product value)
{
    var msg =
        $"Reporter:{Name}. Product - Name: {value.Name}, Price:{value.Price},Desc: {value.Description}";
    PrepReportData(true, msg);
}
```

`IObserver<T>`接口有`OnComplete`、`OnError`和`OnNext`方法，我们需要在`ProductReporter`类中实现这些方法。`OnComplete`方法的目的是通知订阅者工作已经完成，然后清除代码。此外，`OnError`在执行过程中发生错误时被调用，而`OnNext`提供了流序列中下一个元素的信息。

在以下代码中，`PrepReportData`是一个增值，它为用户提供了有关过程的所有操作的格式化报告：

```cs
private void PrepReportData(bool isSuccess, string message)
{
    var model = new MessageViewModel
    {
        MsgId = Guid.NewGuid().ToString(),
        IsSuccess = isSuccess,
        Message = message
    };

    Reporter.Add(model);
}
```

上述方法只是向我们的`Reporter`集合添加了一些内容，这是`MessageViewModel`类的集合。请注意，出于简单起见，您还可以使用我们在`MessageViewModel`类中实现的`ToString()`方法。

以下代码片段显示了`Subcribe`和`Unsubscribe`方法：

```cs
public virtual void Subscribe(IObservable<Product> provider)
{
    if (provider != null)
        _unsubscriber = provider.Subscribe(this);
}

private void Unsubscribe() => _unsubscriber.Dispose();
```

前两种方法告诉系统有一个提供者。订阅者可以订阅该提供者，或在操作完成后取消订阅/处理它。

现在是展示我们的实现并看到一些好结果的时候了。为此，我们需要对现有的`Product Listing`页面进行一些更改，并向项目添加一个新的 View 页面。

在我们的`Index.cshtml`页面中添加以下链接，以便我们可以看到查看审计报告的新链接：

```cs
<a asp-action="Report">Audit Report</a>
```

在上述代码片段中，我们添加了一个新链接，以显示基于我们在`ProductConstroller`类中定义的`Report Action`方法的审计报告。

添加此代码后，我们的产品列表页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/8ef8a83f-a7a4-4df1-85cc-96b6ed21a54c.png)

首先，让我们讨论`Report action`方法。为此，请考虑以下代码：

```cs
var mango = _repositry.GetProduct(new Guid("09C2599E-652A-4807-A0F8-390A146F459B"));
var apple = _repositry.GetProduct(new Guid("7AF8C5C2-FA98-42A0-B4E0-6D6A22FC3D52"));
var orange = _repositry.GetProduct(new Guid("E2A8D6B3-A1F9-46DD-90BD-7F797E5C3986"));
var model = new List<MessageViewModel>();
//provider
ProductRecorder productProvider = new ProductRecorder();
//observer1
ProductReporter productObserver1 = new ProductReporter(nameof(mango));
//observer2
ProductReporter productObserver2 = new ProductReporter(nameof(apple));
//observer3
ProductReporter productObserver3 = new ProductReporter(nameof(orange));
```

在上述代码中，我们只取前三个产品进行演示。请注意，您可以根据自己的实现修改代码。在代码中，我们创建了一个`productProvider`类和三个观察者来订阅我们的`productProvider`类。

以下图表是我们讨论过的`IObservable<T>`和`IObserver<T>`接口的所有活动的图形视图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/846c2b3f-d4ee-49c8-b5d5-106160ff4a5f.png)

以下代码用于订阅`productrovider`：

```cs
//subscribe
productObserver1.Subscribe(productProvider);
productObserver2.Subscribe(productProvider);
productObserver3.Subscribe(productProvider);
```

最后，我们需要记录报告，然后取消订阅：

```cs
//Report and Unsubscribe
productProvider.Record(mango);
model.AddRange(productObserver1.Reporter);
productObserver1.Unsubscribe();
productProvider.Record(apple);
model.AddRange(productObserver2.Reporter);
productObserver2.Unsubscribe();
productProvider.Record(orange);
model.AddRange(productObserver3.Reporter);
productObserver3.Unsubscribe();
```

让我们回到我们的屏幕，并将`Report.cshtml`文件添加到 Views | Product。以下代码是我们报告页面的一部分。您可以在`Product`文件夹中找到完整的代码：

```cs
@model IEnumerable<MessageViewModel>

    <thead>
    <tr>
        <th>
            @Html.DisplayNameFor(model => model.IsSuccess)
        </th>
        <th>
            @Html.DisplayNameFor(model => model.Message)
        </th>
    </tr>
    </thead>
```

此代码将为表格的列创建标题，显示审计报告。

以下代码将完成表格并向`IsSuccess`和`Message`列添加值：

```cs
    <tbody>
    @foreach (var item in Model)
    {
        <tr>
            <td>
                @Html.HiddenFor(modelItem => item.MsgId)
                @Html.DisplayFor(modelItem => item.IsSuccess)
            </td>
            <td>
                @Html.DisplayFor(modelItem => item.Message)
            </td>

        </tr>
    }
    </tbody>
</table>
```

在这一点上，我们已经使用`IObservable<T>`和`IObserver<T>`接口实现了观察者模式。在 Visual Studio 中按下*F5*运行项目，在主页上点击 Product，然后点击审计报告链接。从这里，您将看到我们选择的产品的审计报告，如下图所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/078bcd2a-09a4-484c-8d76-95933be89587.png)

上述屏幕截图显示了一个简单的列表页面，显示了来自`MessageViewModel`类的数据。您可以根据需要进行更改和修改。一般来说，审计报告来自我们在上述屏幕中看到的许多操作活动。您还可以将审计数据保存在数据库中，然后根据需要为不同目的提供这些数据，例如向管理员报告等。

# 响应式扩展 - .NET Rx 扩展

上一节讨论的是响应式编程以及使用`IObservable<T>`和`IObserver<T>`接口作为观察者模式实现响应式编程。在本节中，我们将借助**Rx 扩展**扩展我们的学习。如果您想了解有关 Rx 扩展开发的更多信息，可以关注官方存储库[`github.com/dotnet/reactive`](https://github.com/dotnet/reactive)。

请注意，Rx 扩展现在已与`System`命名空间合并，您可以在`System.Reactive`命名空间中找到所有内容。如果您有 Rx 扩展的经验，您应该知道这些扩展的命名空间已更改，如下所示：

+   `Rx.Main`已更改为`System.Reactive`。

+   `Rx.Core`已更改为`System.Reactive.Core`。

+   `Rx.Interfaces`已更改为`System.Reactive.Interfaces`。

+   `Rx.Linq`已更改为`System.Reactive.Linq`。

+   `Rx.PlatformServices`已更改为`System.Reactive.PlatformServices`。

+   `Rx.Testing`已更改为`Microsoft.Reactive.Testing`。

要启动 Visual Studio，请打开在上一节中讨论的`SimplyReactive`项目，并打开 NuGet 包管理器。点击浏览，输入搜索词`System.Reactive`。从这里，您将看到以下结果：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f1de57f4-7e26-4caa-9028-33a6d4e13cd5.png)

本节的目的是让您了解响应式扩展，而不深入其内部开发。这些扩展受 Apache2.0 许可证管辖，并由.NET 基金会维护。我们已经在我们的`SimplyReactive`应用程序中实现了响应式扩展。

# 库存应用用例

在本节中，我们将继续讨论我们的 FlixOne 库存应用程序。在本节中，我们将讨论 Web 应用程序模式，并扩展我们在第四章中开发的 Web 应用程序，*实现设计模式-基础知识第二部分*。

本章继续讨论了上一章中讨论的 Web 应用程序。如果您跳过了上一章（第九章，*函数式编程实践*），请重新阅读以便跟上当前章节。

在本节中，我们将介绍需求收集的过程，然后讨论我们之前开发的 Web 应用程序的开发和业务的各种挑战。

# 启动项目

在第七章，*为 Web 应用程序实现设计模式-第二部分*中，我们为 FlixOne 库存 Web 应用程序添加了功能。在考虑以下几点后，我们扩展了应用程序：

+   业务需要一个丰富的用户界面。

+   新的机会需要一个响应式 Web 应用程序。

# 需求

经过几次会议和与管理层、**业务分析师**（**BA**）和售前人员的讨论后，组织的管理层决定处理以下高层需求。

# 业务需求

我们的业务团队列出了以下要求：

+   **项目过滤**：目前，用户无法按类别筛选项目。为了扩展列表视图功能，用户应该能够根据其各自的类别筛选产品项目。

+   **项目排序**：目前，项目按照它们添加到数据库的顺序显示。没有机制可以让用户根据项目的名称、价格等对项目进行排序。

FlixOne 库存管理 Web 应用程序是一个虚构的产品。我们正在创建此应用程序来讨论 Web 项目中所需/使用的各种设计模式。

# 使用过滤器、分页和排序获取库存

根据我们的业务需求，我们需要对我们的 FlixOne 库存应用程序应用过滤、分页和排序。首先，让我们开始实现排序。为此，我创建了一个项目并将该项目放在`FlixOneWebExtended`文件夹中。启动 Visual Studio 并打开 FlixOne 解决方案。我们将对我们的产品清单表应用排序，包括这些列：`类别`、`产品名称`、`描述`和`价格`。请注意，我们不会使用任何外部组件进行排序，而是将创建我们自己的登录。

打开“解决方案资源管理器”，并打开`ProductController`，该文件位于`Controllers`文件夹中。向`Index`方法添加`[FromQuery]Sort sort`参数。请注意，`[FromQuery]`属性表示此参数是一个查询参数。我们将使用此参数来维护我们的排序顺序。

以下代码显示了`Sort`类：

```cs
public class Sort
{
    public SortOrder Order { get; set; } = SortOrder.A;
    public string ColName { get; set; }
    public ColumnType ColType { get; set; } = ColumnType.Text;
}
```

`Sort`类包含以下三个公共属性：

+   `Order`：表示排序顺序。`SortOrder`是一个枚举，定义为`public enum SortOrder { D, A, N }`。

+   `ColName`：表示列名。

+   `ColType`：表示列的类型；`ColumnType`是一个枚举，定义为`public enum ColumnType { Text, Date, Number }`。

打开`IInventoryRepositry`接口，并添加`IEnumerable<Product> GetProducts(Sort sort)`方法。此方法负责对结果进行排序。请注意，我们将使用 LINQ 查询来应用排序。实现这个`InventoryRepository`类的方法，并添加以下代码：

```cs
public IEnumerable<Product> GetProducts(Sort sort)
{
    if(sort.ColName == null)
        sort.ColName = "";
    switch (sort.ColName.ToLower())
    {
        case "categoryname":
        {
            var products = sort.Order == SortOrder.A
                ? ListProducts().OrderBy(x => x.Category.Name)
                : ListProducts().OrderByDescending(x => x.Category.Name);
            return PDiscounts(products);

        }
```

以下代码处理了`sort.ColName`为`productname`的情况：

```cs

       case "productname":
        {
            var products = sort.Order == SortOrder.A
                ? ListProducts().OrderBy(x => x.Name)
                : ListProducts().OrderByDescending(x => x.Name);
            return PDiscounts(products);
        }
```

以下代码处理了`sort.ColName`为`productprice`的情况：

```cs

        case "productprice":
        {
            var products = sort.Order == SortOrder.A
                ? ListProducts().OrderBy(x => x.Price)
                : ListProducts().OrderByDescending(x => x.Price);
            return PDiscounts(products);
        }
        default:
            return PDiscounts(ListProducts().OrderBy(x => x.Name));
    }
}
```

在上面的代码中，如果`sort`参数包含空值，则将其值设置为空，并使用`switch..case`在`sort.ColName.ToLower()`中进行处理。

以下是我们的`ListProducts()`方法，它给我们`IIncludeIQuerable<Product,Category>`类型的结果：

```cs
private IIncludableQueryable<Product, Category> ListProducts() =>
    _inventoryContext.Products.Include(c => c.Category);
```

上面的代码简单地通过包含每个产品的`Categories`来给我们`Products`。排序顺序将来自我们的用户，因此我们需要修改我们的`Index.cshtml`页面。我们还需要在表的标题列中添加一个锚标记。为此，请考虑以下代码：

```cs
 <thead>
        <tr>
            <th>
                @Html.ActionLink(Html.DisplayNameFor(model => model.CategoryName), "Index", new Sort { ColName = "CategoryName", ColType = ColumnType.Text, Order = SortOrder.A })
            </th>
            <th>
                @Html.ActionLink(Html.DisplayNameFor(model => model.ProductName), "Index", new Sort { ColName = "ProductName", ColType = ColumnType.Text, Order = SortOrder.A })

            </th>
            <th>
                @Html.ActionLink(Html.DisplayNameFor(model => model.ProductDescription), "Index", new Sort { ColName = "ProductDescription", ColType = ColumnType.Text, Order = SortOrder.A })
            </th>
        </tr>
    </thead>
```

上面的代码显示了表的标题列；`new Sort { ColName = "ProductName", ColType = ColumnType.Text, Order = SortOrder.A }` 是我们实现`SorOrder`的主要方式。

运行应用程序，您将看到产品列表页面的以下快照，其中包含排序功能：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/c72b4b9f-358a-41d8-9ff6-6f5c30f075af.png)

现在，打开`Index.cshtml`页面，并将以下代码添加到页面中：

```cs
@using (Html.BeginForm())
{
    <p>
        Search by: @Html.TextBox("searchTerm")
        <input type="submit" value="Search" class="btn-sm btn-success" />
    </p>
}
```

在上面的代码中，我们在`Form`下添加了一个文本框。在这里，用户输入数据/值，并且当用户点击提交按钮时，这些数据会立即提交到服务器。在服务器端，过滤后的数据将返回并显示产品列表。在实现上述代码之后，我们的产品列表页面将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/dcf4ab01-e7d0-46b5-be17-6a942f083335.png)

转到`ProductController`中的`Index`方法并更改参数。现在`Index`方法看起来像这样：

```cs
public IActionResult Index([FromQuery]Sort sort, string searchTerm)
{
    var products = _repositry.GetProducts(sort, searchTerm);
    return View(products.ToProductvm());
}
```

同样，我们需要更新`InventoryRepository`和`InventoryRepository`中`GetProducts()`方法的参数。以下是`InventoryRepository`类的代码：

```cs
private IEnumerable<Product> ListProducts(string searchTerm = "")
{
    var includableQueryable = _inventoryContext.Products.Include(c => c.Category).ToList();
    if (!string.IsNullOrEmpty(searchTerm))
    {
        includableQueryable = includableQueryable.Where(x =>
            x.Name.Contains(searchTerm) || x.Description.Contains(searchTerm) ||
            x.Category.Name.Contains(searchTerm)).ToList();
    }

    return includableQueryable;
}
```

现在通过从 Visual Studio 按下*F5*并导航到产品列表中的过滤/搜索选项来运行项目。为此，请参阅此快照：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/802ed721-1eb2-4afc-8b51-3be146702b5b.png)

输入搜索词后，单击搜索按钮，这将给您结果，如下快照所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/a6f32b34-7662-4b1d-be5f-6d5a7c0c1bec.png)

在上述产品列表截图中，我们正在使用`searchTerm` `mango`过滤我们的产品记录，并且它产生了单个结果，如前面的快照所示。在搜索数据的这种方法中存在一个问题：将`fruit`作为搜索词添加，然后看看会发生什么。它将产生零结果。这在以下快照中得到了证明：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/06ac51ab-3dfb-47e7-9e2a-8aeea1d0f932.png)

我们没有得到任何结果，这意味着当我们将`searchTerm`转换为小写时，我们的搜索不起作用。这意味着我们的搜索是区分大小写的。我们需要更改我们的代码以使其起作用。

这是我们修改后的代码：

```cs
var includableQueryable = _inventoryContext.Products.Include(c => c.Category).ToList();
if (!string.IsNullOrEmpty(searchTerm))
{
    includableQueryable = includableQueryable.Where(x =>
        x.Name.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase) ||
        x.Description.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase) ||
        x.Category.Name.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase)).ToList();
}
```

我们忽略大小写以使我们的搜索不区分大小写。我们使用了`StringComparison.InvariantCultureIgnoreCase`并忽略了大小写。现在我们的搜索将使用大写或小写字母。以下是使用小写`fruit`产生结果的快照：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/80ddb52c-00e6-4041-b490-377f78e502a6.png)

在之前的 FlixOne 应用程序扩展讨论中，我们应用了`Sort`和`Filter`；现在我们需要添加`paging`。为此，我们添加了一个名为`PagedList`的新类，如下所示：

```cs
public class PagedList<T> : List<T>
{
    public PagedList(List<T> list, int totalRecords, int currentPage, int recordPerPage)
    {
        CurrentPage = currentPage;
        TotalPages = (int) Math.Ceiling(totalRecords / (double) recordPerPage);

        AddRange(list);
    }
}
```

现在，将`ProductController`的`Index`方法的参数更改如下：

```cs
public IActionResult Index([FromQuery] Sort sort, string searchTerm, 
    string currentSearchTerm,
    int? pagenumber,
    int? pagesize)
```

将以下代码添加到`Index.cshtml`页面：

```cs
@{
    var prevDisabled = !Model.HasPreviousPage ? "disabled" : "";
    var nextDisabled = !Model.HasNextPage ? "disabled" : "";
}

<a asp-action="Index"
   asp-route-sortOrder="@ViewData["CurrentSort"]"
   asp-route-pageNumber="@(Model.CurrentPage - 1)"
   asp-route-currentFilter="@ViewData["currentSearchTerm"]"
   class="btn btn-sm btn-success @prevDisabled">
    Previous
</a>
<a asp-action="Index"
   asp-route-sortOrder="@ViewData["CurrentSort"]"
   asp-route-pageNumber="@(Model.CurrentPage + 1)"
   asp-route-currentFilter="@ViewData["currentSearchTerm"]"
   class="btn btn-sm btn-success @nextDisabled">
    Next
</a>
```

前面的代码使我们能够将屏幕移动到下一页或上一页。我们的最终屏幕将如下所示：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d2e1909c-873b-4285-b592-2c69ed0d6667.png)

在本节中，我们讨论并扩展了我们的 FlixOne 应用程序的功能，通过实现`Sorting`，`Paging`和`Filter`。本节的目的是让您亲身体验一个工作中的应用程序。我们已经编写了我们的应用程序，以便它可以直接满足实际应用程序的需求。通过前面的增强，我们的应用程序现在能够提供可以排序、分页和过滤的产品列表。

# 模式和实践-MVVM

在第六章中，*为 Web 应用程序实现设计模式-第一部分*，我们讨论了 MVC 模式，并创建了一个基于此模式的应用程序。

肯·库珀（Ken Cooper）和泰德·彼得斯（Ted Peters）是 MVVM 模式背后的名字。在这一发明时，肯和泰德都是微软公司的架构师。他们制定了这一模式，以简化基于事件驱动的编程的用户界面。后来，它被实现在 Windows Presentation Foundation（WPF）和 Silverlight 中。

MVVM 模式是由 John Gossman 于 2005 年宣布的。John 在博客中讨论了这一模式，与构建 WPF 应用程序有关。链接在这里：[`blogs.msdn.microsoft.com/johngossman/2005/10/08/introduction-to-modelviewviewmodel-pattern-for-building-wpf-apps/`](https://blogs.msdn.microsoft.com/johngossman/2005/10/08/introduction-to-modelviewviewmodel-pattern-for-building-wpf-apps/)。

MVVM 被认为是 MVC 的变体之一，以满足现代用户界面（UI）开发方法，其中 UI 开发是设计师/UI 开发人员的核心责任，而不是应用程序开发人员。在这种开发方法中，一个专注于使 UI 更具吸引力的图形爱好者的设计师可能会或可能不会关心应用程序的开发部分。通常，设计师（UI 人员）使用各种工具来使 UI 更具吸引力。UI 可以使用简单的 HTML、CSS 等，使用 WPF 或 Silverlight 的丰富控件来制作。

Microsoft Silverlight 是一个帮助开发具有丰富用户界面的应用程序的框架。许多开发人员将其称为 Adobe Flash 的替代品。2015 年 7 月，微软宣布不再支持 Silverlight。微软宣布在其构建期间支持.NET Core 3.0 中的 WPF（[`developer.microsoft.com/en-us/events/build`](https://developer.microsoft.com/en-us/events/build)）。这里还有一个关于支持 WPF 计划更多见解的博客：[`devblogs.microsoft.com/dotnet/net-core-3-and-support-for-windows-desktop-applications/`](https://devblogs.microsoft.com/dotnet/net-core-3-and-support-for-windows-desktop-applications/)。

MVVM 模式可以通过其各个组件进行详细说明，如下所示：

+   **Model**：保存数据，不关心应用程序中的任何业务逻辑。我更喜欢将其称为领域对象，因为它保存了我们正在处理的应用程序的实际数据。换句话说，我们可以说模型不负责使数据变得美观。例如，在我们的 FlixOne 应用程序的产品模型中，产品模型保存各种属性的值，并通过名称、描述、类别名称、价格等描述产品。这些属性包含产品的实际数据，但模型不负责对任何数据进行行为更改。例如，产品模型不负责将产品描述格式化为在 UI 上看起来完美。另一方面，我们的许多模型包含验证和其他计算属性。主要挑战是保持纯净的模型，这意味着模型应该类似于真实世界的模型。在我们的情况下，我们的`product`模型被称为**clean model**。干净的模型是类似于真实产品属性的模型。例如，如果`Product`模型存储水果的数据，那么它应该显示水果的颜色等属性。以下代码来自我们虚构应用程序的一个模型：

```cs
export class Product {
  name: string;
  cat: string; 
  desc: string;
}
```

请注意，上述代码是用 Angular 编写的。我们将在接下来的*实现 MVVM*部分详细讨论 Angular 代码。

+   **View**：这是最终用户通过 UI 访问的数据表示。它只是显示数据的值，这个值可能已经格式化，也可能没有。例如，我们可以在 UI 上显示折扣率为 18%，而在模型中它可能存储为 18.00。视图还可以负责行为变化。视图接受用户输入；例如，可能会有一个提供添加新产品的表单/屏幕的视图。此外，视图可以管理用户输入，比如按键、检测关键字等。它也可以是主动视图或被动视图。接受用户输入并根据用户输入操纵数据模型（属性）的视图是主动视图。被动视图是什么都不做的视图。换句话说，与模型无关的视图是被动视图，这种视图由控制器操纵。

+   **ViewModel**：它在 View 和 Model 之间充当中间人。它的责任是使呈现更好。在我们之前的例子中，View 显示折扣率为 18%，但 Model 的折扣率为 18.00，这是 ViewModel 的责任，将 18.00 格式化为 18%，以便 View 可以显示格式化的折扣率。

如果我们结合讨论的所有要点，我们可以将整个 MVVM 模式可视化，看起来像下面的图表：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/61f3a6af-ade5-4d96-88d1-4d959db0bc1c.png)

上述图表是 MVVM 的图形视图，它向我们展示了**View Model**如何将**View**和**Model**分开。**ViewModel**还维护`state`和`perform`操作。这有助于**View**向最终用户呈现最终输出。视图是 UI，它获取数据并将其呈现给最终用户。在下一节中，我们将使用 Angular 实现 MVVM 模式。

# MVVM 的实现

在上一节中，我们了解了 MVVM 模式是什么以及它是如何工作的。在本节中，我们将使用我们的 FlixOne 应用程序并使用 Angular 构建一个应用程序。为了演示 MVVM 模式，我们将使用基于 ASP.NET Core 2.2 构建的 API。

启动 Visual Studio 并打开`FlixOneMVVM`文件夹中的 FlixOne Solution。运行`FlixOne.API`项目，您将看到以下 Swagger 文档页面：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/9cc95489-4408-41f9-81a0-393b2ae85317.png)

上述截图是我们的产品 API 文档的快照，我们已经整合了 Swagger 来进行 API 文档编制。如果您愿意，您可以从此屏幕测试 API。如果 API 返回结果，则您的项目已成功设置。如果没有，请检查此项目的先决条件，并检查本章的 Git 存储库中的`README.md`文件。我们拥有构建新 UI 所需的一切；正如之前讨论的，我们将创建一个 Angular 应用程序，该应用程序将使用我们的产品 API。要开始，请按照以下步骤进行：

1.  打开解决方案资源管理器。

1.  右键单击 FlixOne Solution。

1.  点击添加新项目。

1.  从`添加新项目`窗口中，选择 ASP.NET Core Web 应用程序。将其命名为 FlixOne.Web，然后单击确定。这样做后，请参考此截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/e9f81475-6de0-46c7-bfe0-fb72a917416f.png)

1.  从下一个窗口中，选择 Angular，确保您已选择了 ASP.NET Core 2.2，然后单击确定，并参考此截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/798ace74-dc36-45d9-aebd-c958464837c1.png)

1.  打开解决方案资源管理器，您将找到新的`FlixOne.Web`项目和文件夹层次结构，看起来像这样：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/afcc2e76-f48c-4abf-910f-9e7382731283.png)

1.  从解决方案资源管理器中，右键单击`FlixOne.Web`项目，然后单击`设置为启动项目`，然后参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/a4bac5f7-1e4f-447a-bd53-ee09dcf3a150.png)

1.  运行`FlixOne.Web`项目并查看输出，将看起来像以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/f4643910-9a24-4f31-9102-f27f812cacf8.png)

我们已成功设置了我们的 Angular 应用程序。返回到您的 Visual Studio 并打开`输出`窗口。请参考以下截图：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/5f215bcf-3786-4f4d-95aa-1737550c1192.png)

您将在输出窗口中找到`ng serve "--port" "60672"`；这是一个命令，告诉 Angular 应用程序监听和提供服务。从`解决方案资源管理器`中打开`package.json`文件；这个文件属于`ClientApp`文件夹。您会注意到`"@angular/core": "6.1.10"`，这意味着我们的应用是基于`angular6`构建的。

以下是我们的`product.component.html`的代码（这是一个视图）：

```cs
<table class='table table-striped' *ngIf="forecasts">
  <thead>
    <tr>
      <th>Name</th>
      <th>Cat. Name (C)</th>
      <th>Price(F)</th>
      <th>Desc</th>
    </tr>
  </thead>
  <tbody>
    <tr *ngFor="let forecast of forecasts">
      <td>{{ forecast.productName }}</td>
      <td>{{ forecast.categoryName }}</td>
      <td>{{ forecast.productPrice }}</td>
      <td>{{ forecast.productDescription }}</td>
    </tr>
  </tbody>
</table>
```

从 Visual Studio 运行应用程序，并单击产品，您将获得一个类似于此的产品列表屏幕：

![](https://github.com/OpenDocCN/freelearn-csharp-zh/raw/master/docs/hsn-dsn-ptn-cs-dncore/img/d2388694-3340-4811-bf69-d26781422dfa.png)

在本节中，我们在 Angular 中创建了一个小型演示应用程序。

# 总结

本章的目的是通过讨论其原则和反应式编程模型来使您了解反应式编程。反应式是关于数据流的，我们通过示例进行了讨论。我们从第八章扩展了我们的示例，*在.NET Core 中进行并发编程*，在那里我们讨论了会议上的票务收集柜台的用例。

在我们讨论反应式宣言时，我们探讨了反应式系统。我们通过展示`merge`、`filter`和`map`操作以及流如何通过示例工作来讨论了反应式系统。此外，我们使用示例讨论了`IObservable`接口和 Rx 扩展。

我们继续进行了`FlixOne`库存应用程序，并讨论了实现产品库存数据的分页和排序的用例。最后，我们讨论了 MVVM 模式，并在 MVVM 架构上创建了一个小应用程序。

在下一章（第十一章，*高级数据库设计和应用技术*）中，将探讨高级数据库和应用技术，包括应用**命令查询职责分离**（**CQRS**）和分类账式数据库。

# 问题

以下问题将帮助您巩固本章中包含的信息：

1.  什么是流？

1.  什么是反应式属性？

1.  什么是反应式系统？

1.  什么是合并两个反应式流？

1.  什么是 MVVM 模式？

# 进一步阅读

要了解本章涵盖的主题，请参考以下书籍。本书将为您提供各种深入和实践性的响应式编程练习：

+   《.NET 开发人员的响应式编程》，Antonio Esposito 和 Michael Ciceri，Packt Publishing：[`www.packtpub.com/web-development/reactive-programming-net-developers`](https://www.packtpub.com/web-development/reactive-programming-net-developers)
