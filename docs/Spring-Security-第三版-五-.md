# Spring Security 第三版（五）

> 原文：[`zh.annas-archive.org/md5/3E3DF87F330D174DBAF9E13DAE6DC0C5`](https://zh.annas-archive.org/md5/3E3DF87F330D174DBAF9E13DAE6DC0C5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：会话管理

本章讨论 Spring Security 的会话管理功能。它从举例说明 Spring Security 如何防御会话固定开始。然后我们将讨论并发控制如何被利用来限制按用户许可的软件的访问。我们还将看到会话管理如何被利用进行管理功能。最后，我们将探讨`HttpSession`在 Spring Security 中的使用以及我们如何控制其创建。

以下是在本章中将会讨论的主题列表：

+   会话管理/会话固定

+   并发控制

+   管理已登录用户

+   如何使用`HttpSession`在 Spring Security 中以及如何控制其创建

+   如何使用`DebugFilter`类发现`HttpSession`的创建位置

# 配置会话固定保护

因为我们正在使用配置命名空间的风格，会话固定保护已经为我们配置好了。如果我们想要显式配置它以反映默认设置，我们会这样做：

```java
    http.sessionManagement()
    .sessionFixation().migrateSession();
```

**会话固定保护**是框架的一个特性，除非你试图充当恶意用户，否则你很可能会注意到它。我们将向你展示如何模拟一个会话窃取攻击；在我们这样做之前，了解会话固定做什么以及它防止的攻击类型是很重要的。

# 理解会话固定攻击

会话固定是一种攻击方式，恶意用户试图窃取系统的未经验证用户的会话。这可以通过使用各种技术来完成，这些技术使攻击者获得用户的唯一会话标识（例如，`JSESSIONID`）。如果攻击者创建一个包含用户`JSESSIONID`标识的 cookie 或 URL 参数，他们就可以访问用户的会话。

尽管这显然是一个问题，但通常情况下，如果一个用户未经验证，他们还没有输入任何敏感信息。如果用户验证后仍然使用相同的会话标识，这个问题变得更加严重。如果验证后仍然使用相同的标识，攻击者可能现在甚至不需要知道用户的用户名或密码就能访问到验证用户的会话！

到此为止，你可能会不屑一顾，认为这在现实世界中极不可能发生。实际上，会话窃取攻击经常发生。我们建议你花些时间阅读一下由**开放网络应用安全项目**（**OWASP**）组织发布的关于这个主题的非常有益的文章和案例研究([`www.owasp.org/`](http://www.owasp.org/)）。特别是，你可能想要阅读 OWASP top 10 列表。攻击者和恶意用户是真实存在的，如果你不了解他们常用的技术，也不知道如何避免它们，他们可能会对你用户、应用程序或公司造成真正的损害。

以下图表说明了会话固定攻击是如何工作的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/62110072-4014-450b-a589-12bea83aa974.png)

既然我们已经了解了这种攻击是如何工作的，我们将看看 Spring Security 能做些什么来防止它。

# 使用 Spring Security 预防会话固定攻击

如果我们能够防止用户在认证前拥有的相同会话在认证后被使用，我们就可以有效地使攻击者对会话 ID 的了解变得无用。Spring Security 会话固定保护通过在用户认证时明确创建新会话并使他们的旧会话失效来解决此问题。

让我们来看一下以下的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/d3dc9885-dfc0-4b62-a3c8-433a59efde1e.png)

我们可以看到一个新的过滤器`o.s.s.web.session.SessionManagementFilter`负责评估特定用户是否新认证。如果用户是新的认证，一个配置的`o.s.s.web.authentication.session.SessionAuthenticationStrategy`接口决定了要做什么。`o.s.s.web.authentication.session.SessionFixationProtectionStrategy`将创建一个新会话（如果用户已经有一个），并将现有会话的内容复制到新会话中。这就差不多结束了——看起来很简单。然而，正如我们之前看到的图表所示，它有效地阻止了恶意用户在未知用户认证后重新使用会话 ID。

# 模拟会话固定攻击

此时，你可能想了解模拟会话固定攻击涉及什么：

1.  你首先需要在`SecurityConfig.java`文件中禁用会话固定保护，通过将`sessionManagement()`方法作为`http`元素的子项添加。

你应该从`chapter14.00-calendar`的代码开始。

让我们来看一下以下的代码片段：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    SecurityConfig.java

    http.sessionManagement().sessionFixation().none();
```

你的代码现在应该看起来像`chapter14.01-calendar`。

1.  接下来，你需要打开两个浏览器。我们将在 Google Chrome 中初始化会话，从中窃取它，然后我们的攻击者将在 Firefox 中使用窃取的会话登录。我们将使用 Google Chrome 和 Firefox 的 Web 开发者插件来查看和操作 Cookie。Firefox 的 Web 开发者插件可以从[`addons.mozilla.org/en-US/firefox/addon/web-developer/`](https://addons.mozilla.org/en-US/firefox/addon/web-developer/)下载。Google Chrome 的 Web 开发者工具是内置的。

1.  在 Google Chrome 中打开 JBCP 日历主页。

1.  接下来，从主菜单中，导航到编辑 | 首选项 | 底层设置。在隐私类别下，点击内容设置...按钮。接下来，在 Cookie 设置中，点击所有 Cookie 和站点数据...按钮。最后，在搜索框中输入`localhost`，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/ab82311f-9925-4cfb-a44e-9a37668d2ce5.png)

1.  选择 `JSESSIONID` cookie，将内容值复制到剪贴板，并登录 JBCP 日历应用程序。如果您重复查看 Cookie 信息命令，您会发现您登录后 `JSESSIONID` 没有改变，使您容易受到会话固定攻击！

1.  在 Firefox 中，打开 JBCP 日历网站。您会被分配一个会话 cookie，您可以通过按 *Ctrl* + *F2* 打开底部的 Cookie 控制台来查看，然后输入 `cookie list [enter]` 以显示当前页面的 cookie。

1.  为了完成我们的黑客攻击，我们将点击编辑 Cookie 选项，并粘贴我们从 Google Chrome 复制到剪贴板的 `JSESSIONID` cookie，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/f6a22fcb-2b58-4f24-803c-a0c306aae717.png)

1.  请记住，最新版本的 Firefox 也包括网络开发者工具。但是，您需要确保您使用的是扩展程序，而不是内置的，因为它提供了额外的功能。

我们的会话固定黑客攻击完成了！如果您现在在 Firefox 中重新加载页面，您将看到您以使用 Google Chrome 登录的同一用户身份登录，但不知道用户名和密码。您担心恶意用户了吗？

现在，重新启用会话固定保护并再次尝试此练习。您将看到，在这种情况下，用户登录后 `JSESSIONID` 发生了变化。根据我们对会话固定攻击发生方式的理解，这意味着我们已将不知情的用户成为这种攻击受害者的可能性降低。干得好！

谨慎的开发人员应该注意，窃取会话 cookie 有很多方法，其中一些（如 XSS）可能会使即使启用了会话固定保护的网站也变得脆弱。请咨询 OWASP 网站，以获取有关预防这类攻击的额外资源。

# 比较会话固定保护选项

`session-fixation-protection` 属性的以下三个选项允许您更改其行为，如下所示：

| **属性值** | **描述** |
| --- | --- |
| `none()` | 此选项禁用会话固定保护（除非其他 `sessionManagement()` 属性非默认），并且不配置 `SessionManagementFilter`。 |
| `migrateSession()` | 当用户认证并分配新会话时，确保将旧会话的所有属性移动到新会话。 |
| `newSession()` | 当用户认证成功后，将创建一个新会话，不会迁移旧会话（未认证）的任何属性。 |

在大多数情况下，`migrateSession()` 的默认行为对于希望在用户认证后保留用户会话重要属性（如点击兴趣和购物车）的网站将是适当的。

# 限制每个用户的并发会话数

在软件行业，软件通常按用户数出售。这意味着，作为软件开发者，我们有兴趣确保每个用户只存在一个会话，以防止账户共享。Spring Security 的并发会话控制确保单一用户不能同时拥有超过固定数量的活跃会话（通常是 1 个）。确保这个最大限制得到执行涉及几个组件协同工作，以准确追踪用户会话活动的变化。

让我们配置这个特性，回顾一下它如何工作，然后测试它！

# 配置并发会话控制

既然我们已经理解了并发会话控制中涉及的不同组件，那么设置它应该更有意义。让我们查看以下步骤来配置并发会话控制：

1.  首先，你按照如下方式更新你的`security.xml`文件：

```java
        // src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        http.sessionManagement().maximumSessions(1)
```

1.  接下来，我们需要在`SecurityConfig.java`部署描述符中启用`o.s.s.web.session.HttpSessionEventPublisher`，以便 Servlet 容器将通过`HttpSessionEventPublisher`通知 Spring Security 关于会话生命周期事件，如下所示：

```java
        // src/main/java/com/packtpub/springsecurity/configuration/ 
        SecurityConfig.java

        @Bean
        public HttpSessionEventPublisher httpSessionEventPublisher() {
            return new HttpSessionEventPublisher();
        }
```

有了这两个配置项，并发会话控制现在将被激活。让我们看看它实际做了什么，然后我们将展示如何测试它。

# 理解并发会话控制

并发会话控制使用`o.s.s.core.session.SessionRegistry`来维护一个活跃 HTTP 会话列表以及与之关联的认证用户。当会话被创建和过期时，注册表会根据`HttpSessionEventPublisher`发布的会话生命周期事件实时更新，以跟踪每个认证用户的活跃会话数量。

请参考以下图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/cd90434e-cc5a-4032-8764-fb2d1e4af99f.png)

`SessionAuthenticationStrategy`的扩展`o.s.s.web.authentication.session.ConcurrentSessionControlStrategy`是跟踪新会话和实施并发控制的方法。每当用户访问受保护的网站时，`SessionManagementFilter`用来检查活跃会话与`SessionRegistry`。如果用户的活跃会话不在`SessionRegistry`跟踪的活跃会话列表中，那么最不常使用的会话将被立即过期。

修改后的并发会话控制过滤器链中的第二个参与者是`o.s.s.web.session.ConcurrentSessionFilter`。此过滤器将识别已过期的会话（通常是已被 Servlet 容器过期或被`ConcurrentSessionControlStrategy`接口强制过期的会话）并通知用户他们的会话已过期。

既然我们已经理解了并发会话控制是如何工作的，那么复现一个实施该控制的情景应该对我们来说很容易。

你的代码现在应该看起来像`chapter14.02-calendar`。

# 测试并发会话控制

正如我们在验证会话固定保护时所做的那样，我们需要通过执行以下步骤来访问两个网络浏览器：

1.  在 Google Chrome 中，以`user1@example.com/user1`的身份登录网站。

1.  现在，在 Firefox 中，以同一用户身份登录网站。

1.  最后，回到 Google Chrome 中执行任何操作。你会看到一个指示你的会话已过期的消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/f71d8539-cbd5-446c-802c-4ca17abcd3f2.png)

如果你在使用这个应用程序时收到这条消息，你可能会感到困惑。这是因为显然这并不是一种友好的方式，用来通知一次只能有一个用户访问应用程序。然而，它确实说明会话已被软件强制过期。

并发会话控制对于新接触 Spring Security 的用户来说通常是一个很难理解的概念。许多用户试图在不真正理解它如何工作以及它的好处的情况下实现它。如果你正在尝试启用这个强大的功能，但它似乎并没有像你期望的那样工作，请确保你已经正确配置了所有内容，然后回顾本节中的理论解释-希望它们能帮助你理解可能出错了什么！

当会话过期事件发生时，我们可能需要将用户重定向到登录页面，并给他们一个消息来指出出了什么问题。

# 配置过期会话重定向

幸运的是，有一个简单的方法可以将用户重定向到一个友好的页面（通常是登录页面），当他们在并发会话控制中被标记时-只需指定`expired-url`属性，并将其设置为应用程序中的有效页面。如下更新你的`security.xml`文件：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    http.sessionManagement()
    .maximumSessions(1)
 .expiredUrl("/login/form?expired")    ;
```

在我们的应用程序的情况下，这将把用户重定向到标准的登录表单。然后我们将使用查询参数来显示一个友好的消息，表明我们确定他们有多个活动会话，应该重新登录。更新你的`login.html`页面，使用此参数来显示我们的消息：

```java
    //src/main/resources/templates/login.html

    ...
    <div th:if="${param.expired != null}" class="alert alert-success">
    <strong>Session Expired</strong>
   <span>You have been forcibly logged out due to multiplesessions 
   on the same account (only one activesession per user is allowed).</span>
   </div>
    <label for="username">Username</label>
```

然后尝试通过在 Google Chrome 和 Firefox 中分别以`admin1@example.com`/`admin1`的身份登录用户。这次，你应该会看到一个带有自定义错误消息的登录页面。

你的代码现在应该看起来像`chapter14.03-calendar`。

# 并发控制常见问题

登录同一用户时不会触发登出事件的原因有几个。第一个原因是在使用自定义`UserDetails`（如我们在第三章，*自定义认证*中做的那样）时，而`equals`和`hashCode`方法没有得到正确实现。这是因为默认的`SessionRegistry`实现使用内存映射来存储`UserDetails`。为了解决这个问题，你必须确保你已经正确实现了`hashCode`和 equals 方法。

第二个问题发生在重启应用程序容器时，而用户会话被持久化到磁盘上。当容器重新启动后，已经使用有效会话登录的用户将登录。然而，用于确定用户是否已经登录的`SessionRegistry`内存映射将会是空的。这意味着 Spring Security 会报告用户没有登录，尽管用户实际上已经登录了。为了解决这个问题，需要一个自定义的`SessionRegistry`，同时禁用容器内的会话持久化，或者你必须实现一个特定于容器的解决方案，以确保在启动时将持久化的会话填充到内存映射中。

另一个原因是，在撰写本文时，对于记住我功能还没有实现并发控制。如果用户使用记住我功能进行身份验证，那么这种并发控制将不会被强制执行。有一个 JIRA 问题是用来实现这个功能的，如果你的应用程序需要记住我功能和并发控制，那么请参考它以获取任何更新：[`jira.springsource.org/browse/SEC-2028`](https://jira.springsource.org/browse/SEC-2028)。

我们将要讨论的最后一个常见原因是，在默认的`SessionRegistry`实现下，并发控制在集群环境中将无法工作。如前所述，默认实现使用一个内存映射。这意味着如果`user1`登录到应用程序服务器 A，他们登录的事实将与该服务器相关联。因此，如果`user1`然后认证到应用程序服务器 B，之前关联的认证对应用程序服务器 B 来说是未知的。

# 阻止认证，而不是强制登出

Spring Security 还可以阻止用户如果已经有一个会话的情况下登录到应用程序。这意味着，Spring Security 不是强制原始用户登出，而是阻止第二个用户登录。配置更改如下所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    http.sessionManagement()
    .maximumSessions(1)
    .expiredUrl("/login/form?expired")
 .maxSessionsPreventsLogin(true);
```

进行更新后，使用 Google Chrome 登录日历应用程序。现在，尝试使用相同的用户名尝试使用 Firefox 登录日历应用程序。你应该会看到我们自定义的错误信息，来自我们的`login.html`文件。

你的代码现在应该看起来像`chapter14.04-calendar`。

这种方法的缺点可能不经过深思熟虑不容易看出。试着在不登出的情况下关闭 Google Chrome，然后再次打开它。现在，尝试再次登录应用程序。你会观察到无法登录。这是因为当浏览器关闭时，`JSESSIONID` cookie 被删除。然而，应用程序并不知道这一点，所以用户仍然被认为是认证的。你可以把这看作是一种内存泄漏，因为`HttpSession`仍然存在，但是没有指向它（`JSESSIONID` cookie 已经消失了）。直到会话超时，我们的用户才能再次认证。幸运的是，一旦会话超时，我们的`SessionEventPublisher`接口将把用户从我们的`SessionRegistry`接口中移除。我们从这一点可以得出的结论是，如果用户忘记登出并关闭浏览器，他们将无法再次登录应用程序，直到会话超时。

就像在第七章 *记住我服务* 中一样，这个实验如果浏览器在关闭后决定记住一个会话，可能就不会工作。通常，如果插件或浏览器被配置为恢复会话，这种情况会发生。在这种情况下，你可能想手动删除`JSESSIONID` cookie 来模拟浏览器被关闭。

# 并发会话控制的其他好处

并发会话控制的一个好处是`SessionRegistry`存在用以跟踪活动（可选地，已过期）会话。这意味着我们可以通过执行以下步骤来获取关于我们系统中的用户活动（至少是认证用户）的运行时信息：

1.  即使你不想启用并发会话控制，你也可以这样做。只需将`maximumSessions`设置为`-1`，会话跟踪将保持启用，尽管不会强制执行最大值。相反，我们将使用本章`SessionConfig.java`文件中提供的显式 bean 配置，如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SessionConfig.java

        @Bean
        public SessionRegistry sessionRegistry(){
         return new SessionRegistryImpl();
        }
```

1.  我们已经将`SessionConfig.java`文件的导入添加到了`SecurityConfig.java`文件中。所以，我们只需要在我们的`SecurityConfig.java`文件中引用自定义配置。用以下代码片段替换当前的`sessionManagement`和`maximumSessions`配置：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

        http.sessionManagement()
        .maximumSessions(-1)
        .sessionRegistry(sessionRegistry)
        .expiredUrl("/login/form?expired")
        .maxSessionsPreventsLogin(true);
```

你的代码现在应该看起来像`chapter14.05-calendar`。

现在，我们的应用程序将允许同一用户进行无限次数的认证。然而，我们可以使用`SessionRegistry`强制登出用户。让我们看看如何使用这些信息来增强我们用户的安全性。

# 为用户显示活动会话

你可能已经看到过许多网站允许用户查看和强制登出他们账户的会话。我们可以很容易地利用这个强制登出功能来完成同样的操作。我们已经提供了`UserSessionController`，它获取当前登录用户的活动会话。你可以看到实现如下：

```java
    //src/main/java/com/packtpub/springsecurity/web/controllers/
    UserSessionController.java

    @Controller
    public class UserSessionController {
     private final SessionRegistry sessionRegistry;
    @Autowired
     public UserSessionController(SessionRegistry sessionRegistry) {
      this.sessionRegistry = sessionRegistry;
    }
      @GetMapping("/user/sessions/")
    public String sessions(Authentication authentication, ModelMap model) {
    List<SessionInformation> sessions = sessionRegistry.getAllSessions
    (authentication.getPrincipal(), false);
    model.put("sessions", sessions);
      return "user/sessions";
     }
      @DeleteMapping(value="/user/sessions/{sessionId}")
     public String removeSession(@PathVariable String sessionId,
      RedirectAttributes redirectAttrs) {
    SessionInformation sessionInformation = sessionRegistry.
    getSessionInformation(sessionId);
    if(sessionInformation != null) {
       sessionInformation.expireNow();
    }
```

```java
       redirectAttrs.addFlashAttribute("message", "Session was removed");
       return "redirect:/user/sessions/";
       }
    }
```

我们的会话方法将使用 Spring MVC 自动获取当前的 Spring Security `Authentication`。如果我们没有使用 Spring MVC，我们也可以从`SecurityContextHolder`获取当前的`Authentication`，如在第三章中*自定义认证*所讨论的。然后使用主体来获取当前用户的所有`SessionInformation`对象。通过遍历我们`sessions.html`文件中的`SessionInformation`对象，如下所示，轻松显示信息：

```java
//src/main/resources/templates/sessions.html

...
<tr th:each="session : ${sessions}">
<td th:text="${#calendars.format(session.lastRequest, 'yyyy-MM-dd HH:mm')}">
</td>
<td th:text="${session.sessionId}"></td>
<td>
<form action="#" th:action="@{'/user/sessions/{id}'(id=${session.sessionId})}"
th:method="delete" cssClass="form-horizontal">
<input type="submit" value="Delete" class="btn"/>
</form>
</td>
</tr>
...
```

现在你可以安全地启动 JBCP 日历应用程序，并使用`user1@example.com`/`user1`在 Google Chrome 中登录。然后，使用 Firefox 登录，并点击右上角的`user1@example.com`链接。接下来，您将在显示上看到两个会话列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/95fdedc1-34b3-4227-904f-11c392939ffb.png)

在 Firefox 中，点击第一个会话的删除按钮。这会将请求发送到我们`UserSessionsController`的`deleteSession`方法。这表示会话应该被终止。现在，在 Google Chrome 内导航到任何页面。您将看到自定义消息，称会话已被强制终止。虽然消息可以更新，但我们看到这对于用户终止其他活动会话是一个很好的功能。

其他可能的用途包括允许管理员列出和管理所有活动会话，显示网站上的活动用户数，甚至扩展信息以包括诸如 IP 地址或位置信息之类的内容。

# Spring Security 如何使用 HttpSession 方法？

我们已经讨论过 Spring Security 如何使用`SecurityContextHolder`来确定当前登录的用户。然而，我们还没有解释 Spring Security 是如何自动填充`SecurityContextHolder`的。这个秘密在于`o.s.s.web.context.SecurityContextPersistenceFilter`过滤器和`o.s.s.web.context.SecurityContextRepository`接口。让我们来看看下面的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/f242c0b7-dcdd-425a-916b-59dc18d70a0d.png)

下面是对前述图表中每个步骤的解释：

1.  在每次网络请求的开始，`SecurityContextPersistenceFilter`负责通过`SecurityContextRepository`获取当前的`SecurityContext`实现。

1.  紧接着，它在`SecurityContextHolder`上设置了`SecurityContext`。

1.  对于随后的网络请求，`SecurityContext`可以通过`SecurityContextHolder`获得。例如，如果一个 Spring MVC 控制器或`CalendarService`想要访问`SecurityContext`，它可以通过`SecurityContextHolder`来访问。

1.  然后，在每个请求的末尾，`SecurityContextPersistenceFilter`从`SecurityContextHolder`中获取`SecurityContext`。

1.  紧接着，`SecurityContextPersistenceFilter`在每次请求结束时将`SecurityContext`保存到`SecurityContextRepository`中。这确保了如果在 web 请求期间的任何时刻更新了`SecurityContext`（也就是说，如在[第三章](https://cdp.packtpub.com/spring_security__third_edition/wp-admin/post.php?post=42&action=edit) *自定义认证*中用户创建新账户时），`SecurityContext`会被保存。

1.  最后，`SecurityContextPersistenceFilter`清除了`SecurityContextHolder`。

现在产生的问题是这与`HttpSession`有什么关系？这一切都是通过默认的`SecurityContextRepository`实现联系在一起的，该实现使用`HttpSession`。

# HttpSessionSecurityContextRepository 接口

默认实现的`SecurityContextRepository`，`o.s.s.web.context.HttpSessionSecurityContextRepository`，使用`HttpSession`来检索和存储当前的`SecurityContext`实现。并没有提供其他`SecurityContextRepository`的实现。然而，由于`HttpSession`的使用被`SecurityContextRepository`接口抽象了，如果我们愿意，可以很容易地编写自己的实现。

# 配置 Spring Security 如何使用 HttpSession

Spring Security 有能力配置何时由 Spring Security 创建会话。这可以通过`http`元素的`create-session`属性来完成。下面表格总结了选项的概要：

| **属性值** | **描述** |
| --- | --- |
| `ifRequired` | 如果需要（默认值），Spring Security 将创建一个会话。 |
| `always` | 如果不存在会话，Spring Security 将主动创建一个会话。 |
| `never` | Spring Security 永远不会创建会话，但如果应用程序创建了会话，它将利用该会话。这意味着如果存在`HttpSession`方法，`SecurityContext`将被持久化或从中检索。 |
| `stateless` | Spring Security 不会创建会话，并将忽略会话以获取 Spring `Authentication`。在这种情况下，总是使用`NullSecurityContextRepository`，它总是声明当前的`SecurityContext`为`null`。 |

在实践中，控制会话的创建可能比最初看起来要困难。这是因为属性只控制了 Spring Security 对`HttpSession`使用的一部分。它不适用于应用程序中的其他组件，比如 JSP。为了帮助找出`HttpSession`方法是在何时创建的，我们可以在 Spring Security 中添加`DebugFilter`。

# 使用 Spring Security 的 DebugFilter 进行调试

让我们来看看以下步骤，学习如何使用 Spring Security 的`DebugFilter`进行调试：

1.  更新你的`SecurityConfig.java`文件，使其会话策略为`NEVER`。同时，在`@EnableWebSecurity`注解上添加`debug`标志为`true`，这样我们就可以追踪会话是在何时创建的。更新如下所示：

```java
        //src/main/java/com/packtpub/springsecurity/configuration/
        SecurityConfig.java

       @Configuration
        @Enable WebSecurity(debug = true)
        public class SecurityConfig extends WebSecurityConfigurerAdapter {
           ...
          http.sessionManagement()
         .sessionCreationPolicy(SessionCreationPolicy.NEVER);
```

1.  启动应用程序时，你应该会看到类似以下代码写入标准输出。如果你还没有做，确保你已经为 Spring Security 调试器类别启用日志记录：

```java
            ********************************************************************  
            **********       Security debugging is enabled.             *************
            **********   This may include sensitive information.     *************
            **********     Do not use in a production system!         *************
            ********************************************************************
```

1.  现在，清除你的 cookies（这可以在 Firefox 中通过*Shift* + *Ctrl* + *Delete*完成），启动应用程序，直接导航到`http://localhost:8080`。当我们像章节早期那样查看 cookies 时，我们可以看到尽管我们声明 Spring Security 不应该创建`HttpSession`，但`JSESSIONID`仍然被创建了。再次查看日志，你会看到创建`HttpSession`的代码调用栈如下：

```java
            ************************************************************
            2017-07-25 18:02:31.802 INFO 71368 --- [nio-8080-exec-1] 
            Spring Security Debugger                 :
            ************************************************************
            New HTTP session created: 2A708D1C3AAD508160E6189B69D716DB
```

1.  在这个实例中，我们的 JSP 页面负责创建新的`HttpSession`方法。实际上，所有 JSP 默认都会创建新的`HttpSession`方法，除非你在每个 JSP 文件的顶部包含以下代码：

```java
        <%@ page session="false" %>
```

`DebugFilter`还有许多其他用途，我们鼓励你自己去探索，例如，确定一个请求将匹配特定的 URL，哪些 Spring Security 过滤器被调用等等。

# 总结

阅读本章后，你应该熟悉 Spring Security 如何管理会话以及如何防范会话固定攻击。我们也知道如何使用 Spring Security 的并发控制来防止同一个用户多次认证。

我们还探索了并发控制的使用，以允许用户终止与他们账户相关的会话。同时，我们看到了如何配置 Spring Security 的会话创建。我们还介绍了如何使用 Spring Security 的`DebugFilter`过滤器来解决与 Spring 相关的问题。

我们还学习了安全性，包括确定`HttpSession`方法何时被创建以及是什么原因导致了它的创建。

这结束了我们关于 Spring Security 会话管理的讨论。在下一章，我们将讨论一些关于将 Spring Security 与其他框架集成的具体内容。


# 第十四章：额外的 Spring Security 特性

在这一章中，我们将探讨一些到目前为止本书中尚未涵盖的 Spring Security 特性，包括以下主题：

+   **跨站脚本攻击**（**XSS**）

+   **跨站请求伪造**（**CSRF**）

+   同步器令牌

+   **点击劫持**

我们将了解如何使用以下方法包含各种 HTTP 头以保护常见安全漏洞：

+   `Cache-Control`

+   `Content-Type Options`

+   **HTTP 严格传输安全**（**HSTS**）

+   `X-Frame-Options`

+   `X-XSS-Protection`

在阅读这一章之前，你应该已经对 Spring Security 的工作原理有了了解。这意味着你应该已经能够在一个简单的 web 应用程序中设置身份验证和授权。如果你还不能做到这一点，你需要在继续学习这一章之前确保你已经阅读了 第三章，*自定义身份验证*。如果你牢记 Spring Security 的基本概念并且理解你正在集成的框架，那么集成其他框架就相对简单了。

# 安全漏洞

在互联网时代，有很多可能被利用的漏洞。要了解更多关于基于 web 的漏洞，一个很好的资源是**开放网络应用安全项目**（**OWASP**），它的网址是 [`www.owasp.org`](https://www.owasp.org/).

除了是一个了解各种漏洞的伟大资源外，OWASP 还根据行业趋势对最 10 个漏洞进行了分类。

# 跨站脚本攻击

跨站脚本攻击涉及已经被注入到信任网站的恶意脚本。

XSS 攻击发生在一个攻击者利用一个允许未经审查的输入发送到网站的给定 web 应用程序时，通常以基于浏览器的脚本的形式，然后由网站的不同用户执行。

基于向网站提供验证过的或未编码的信息，攻击者可以利用很多形式。

这个问题核心在于期望用户信任网站发送的信息。最终用户的浏览器没有办法知道这个脚本不应该被信任，因为它来自一个它们正在浏览的网站。因为它认为脚本来自一个信任的来源，恶意脚本就可以访问浏览器中保留的与该网站一起使用的任何 cookie、会话令牌或其他敏感信息。

XSS 攻击可以通过以下序列图来描述：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/da789fd6-805c-4ab2-bcc8-ec95e763c00a.png)

# 跨站请求伪造

CSRF 攻击通过诱骗受害者提交恶意请求来攻击受害者。这种攻击继承或劫持受害者的身份和特权，并在受害者的名义上执行未经授权的功能和访问。

对于网络应用程序，大多数浏览器会自动包含与该网站关联的凭据，这包括用户会话、Cookie、IP 地址、Windows 域凭据等等。

因此，如果一个用户当前在一个网站上已认证，那么该网站将无法区分由受害者发送的伪造请求和合法的法院请求。

CSRF 攻击针对的是在服务器上引起状态变化的功能，比如更改受害者的电子邮件地址或密码，或者进行金融交易。

这迫使受害者获取对攻击者不利的数据，因为攻击者不会收到响应；受害者会。因此，CSRF 攻击针对的是状态更改请求。

以下序列图详细说明了 CSRF 攻击是如何发生的：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/c0a2cc8f-d6c0-4d2e-85cc-55c6ee3fcb83.png)

为了尝试防止 CSRF，可以采取几种不同的设计措施，然而，诸如秘密 Cookie、HTTP POST 请求、多步骤交易、URL 重写和 HTTPS 等措施，绝不可能防止此类攻击。

OWASP 的前 10 大安全漏洞列表详细介绍了 CSRF，作为第八常见的攻击，详情请见[`www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)`](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF))。

# 同步器令牌

解决这个问题的一种方法是使用同步器令牌模式。这个解决方案要求每个请求除了我们的会话 Cookie 外，还需要一个作为 HTTP 参数的随机生成的令牌。当提交一个请求时，服务器必须查找参数的预期值并将其与请求中的实际值进行比较。如果值不匹配，请求应该失败。

《跨站请求伪造（CSRF）预防速查表》建议使用同步器令牌模式作为防止 CSRF 攻击的可行解决方案：[`www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#General_Recommendation:_Synchronizer_Token_Pattern`](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)_Prevention_Cheat_Sheet#General_Recommendation:_Synchronizer_Token_Pattern)

放宽期望值意味着只要求每个更新状态的 HTTP 请求中包含令牌。由于同源策略可以确保恶意网站无法读取响应，因此这样做是安全的。另外，我们不希望在每个 HTTP `GET`请求中包含随机令牌，因为这可能导致令牌泄露。

让我们看看例子会如何改变。假设生成的随机令牌以 HTTP 参数`named _csrf`的形式存在。例如，转账请求如下所示：

```java
POST /transfer HTTP/1.1
Host: bank.example.com
Cookie: JSESSIONID=randomid; Domain=bank.example.com; Secure; HttpOnly
Content-Type: application/x-www-form-urlencoded
amount=100.00&routingNumber=1234&account=9876&_csrf=<secure-random token>
```

您会注意到我们添加了带有随机值的`_csrf`参数。现在，恶意网站将无法猜测`_csrf`参数的正确值（必须在恶意网站上显式提供）并且在服务器将实际令牌与预期令牌比较时，传输将会失败。

以下图表显示了同步令牌模式的标准用例：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/a55eec39-0e93-4503-82d8-af9c17f44ce6.png)

# 在 Spring Security 中的同步器令牌支持

Spring Security 提供了默认启用的同步器令牌支持。您可能在前几章中注意到，在我们的`SecurityConfig.java`文件中，我们禁用了 CSRF 保护，如下面的代码片段所示：

```java
//src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

protected void configure(HttpSecurity http) throws Exception {
...
// CSRF protection is enabled by default.
http.csrf().disable(); ...
}
```

到目前为止，在本书中，我们已经禁用了同步器令牌保护，以便我们可以专注于其他安全问题。

如果我们在这个时候启动应用程序，我们可以走过安全流程，但不会有任何页面的同步器令牌支持被添加。

您应该从`chapter16.00-calendar`的代码开始。

# 何时使用 CSRF 保护

建议您对任何可以由浏览器或普通用户处理的请求使用 CSRF 保护。如果您只是创建一个被非浏览器客户端使用的服务，您很可能会想要禁用 CSRF 保护。

# CSRF 保护与 JSON

一个常见的问题是：我需要为 JavaScript 发出的 JSON 请求提供保护吗？简短的答案是，视情况而定。然而，您必须非常小心，因为存在可以影响 JSON 请求的 CSRF 利用方式。例如，恶意用户可以使用以下表单创建一个 CSRF 攻击：

```java
    <form action="https://example.com/secureTransaction" method="post"   
    enctype="text/plain">
    <input name='{"amount":100,"routingNumber":"maliciousRoutingNumber",
    "account":"evilsAccountNumber", "ignore_me":"' value='test"}'
    type='hidden'>
    <input type="submit" value="Win Money!"/>
    </form>This will produce the following JSON structure{ "amount":   
    100,"routingNumber": "maliciousRoutingNumber","account": 
    "maliciousAccountNumber","ignore_me": "=test"
    }
```

如果一个应用程序没有验证 Content-Type 方法，那么它将受到这种利用的影响。根据设置，一个验证 Content-Type 方法的 Spring MVC 应用程序仍然可以通过将 URL 后缀更新为以`.json`结尾来被利用，如下面的代码所示：

```java
    <form action="https://example.com/secureTransaction.json" method="post"        
    enctype="text/plain">
    <input name='{"amount":100,"routingNumber":"maliciousRoutingNumber",
    "account":"maliciousAccountNumber", "ignore_me":"' value='test"}' 
    type='hidden'>
    <input type="submit" value="Win Money!"/>
    </form>
```

# CSRF 与无状态浏览器应用程序

如果您的应用程序是无状态的，那并不意味着您就受到了保护。实际上，如果用户不需要在网页浏览器中为特定请求执行任何操作，他们仍然可能受到 CSRF 攻击的威胁。

例如，考虑一个使用自定义 cookie 的应用程序，它包含所有认证状态，而不是`JSESSIONID`cookie。当发生 CSRF 攻击时，自定义 cookie 将按照我们之前例子中`JSESSIONID`cookie 的方式随请求发送。

使用基本认证的用户也容易受到 CSRF 攻击，因为浏览器将自动在所有请求中包含用户名和密码，就像我们在之前的例子中`JSESSIONID` cookie 一样发送。

# 使用 Spring Security CSRF 保护

那么，使用 Spring Security 保护我们的网站免受 CSRF 攻击需要哪些步骤呢？使用 Spring Security 的 CSRF 保护的步骤如下：

1.  使用正确的 HTTP 动词。

1.  配置 CSRF 保护。

1.  包含 CSRF 令牌。

# 使用正确的 HTTP 动词

防止 CSRF 攻击的第一步是确保你的网站使用正确的 HTTP 动词。特别是，在 Spring Security 的 CSRF 支持可以发挥作用之前，你需要确信你的应用程序正在使用`PATCH`、`POST`、`PUT`和/或`DELETE`来处理任何改变状态的操作。

这不是 Spring Security 支持的限制，而是防止 CSRF 攻击的一般要求。原因是将私有信息包含在 HTTP `GET`方法中可能会导致信息泄露。

参考*RFC 2616*，*第 15.1.3 节*，*在 URI 中编码敏感信息*，以了解如何使用`POST`而不是`GET`来处理敏感信息的一般指导原则（[`www.w3.org/Protocols/rfc2616/rfc2616-sec15.html#sec15.1.3`](https://www.w3.org/Protocols/rfc2616/rfc2616-sec15.html#sec15.1.3)）。

# 配置 CSRF 保护

下一步是在你的应用程序中包含 Spring Security 的 CSRF 保护。一些框架通过使用户会话无效来处理无效的 CSRF 令牌，但这会带来它自己的问题。相反，默认情况下，Spring Security 的 CSRF 保护将产生 HTTP 403 禁止访问。这可以通过配置`AccessDeniedHandler`以不同的方式处理`InvalidCsrfTokenException`来自定义。

出于被动原因，如果你使用 XML 配置，必须使用`<csrf>`元素显式启用 CSRF 保护。查阅`<csrf>`元素的文档以获取其他自定义设置。

SEC-2347 被记录下来，以确保 Spring Security 4.x 的 XML 命名空间配置将默认启用 CSRF 保护（[`github.com/spring-projects/spring-security/issues/2574`](https://github.com/spring-projects/spring-security/issues/2574)）。

# 默认的 CSRF 支持

使用 Java 配置时，CSRF 保护默认启用。查阅`csrf()`的 Javadoc 以获取有关如何配置 CSRF 保护的其他自定义设置。

为了在这个配置中详细说明，我们将在`SecurityConfig.java`文件中添加 CSRS 方法，如下所示：

```java
//src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java
    @Override
```

```java
    public void configure(HttpSecurity http) throws Exception {
 http.csrf();    }
```

# 在<Form>提交中包含 CSRF 令牌

最后一步是确保你在所有的`PATCH`、`POST`、`PUT`和`DELETE`方法中包含 CSRF 令牌。一种实现方法是使用`_csrf`请求属性来获取当前的`CsrfToken`令牌。以下是在 JSP 中这样做的一个例子：

```java
    <c:url var="logoutUrl" value="/logout"/>
    <form action="${logoutUrl}" method="post">
      <input type="submit" value="Log out" />
 <input type="hidden"name="${_csrf.parameterName}" value="${_csrf.token}"/>
    </form>
```

# 使用 Spring Security JSP 标签库包含 CSRF 令牌

如果启用了 CSRF 保护，此标记将插入一个带有正确名称和值的秘密表单字段，以供 CSRF 保护令牌使用。如果未启用 CSRF 保护，此标记将不输出任何内容。

通常，Spring Security 会自动为任何使用的`<form:form>`标签插入 CSRF 表单字段，但如果出于某种原因不能使用`<form:form>`，`csrfInput`是一个方便的替代品。

你应该在 HTML `<form></form>`块中放置这个标签，你通常会在其他输入字段中放置其他输入字段。不要在这个标签中放置 Spring `<form:form></form:form>`块。Spring Security 会自动处理 Spring 表单，如下所示：

```java
    <form method="post" action="/logout">
 <sec:csrfInput />      ...
    </form>
```

# 默认的 CSRF 令牌支持

如果你使用 Spring MVC `<form:form>`标签，或者 Thymeleaf 2.1+，并且你用`@EnableWebMvcSecurity`替换`@EnableWebSecurity`，`CsrfToken`令牌会自动包含在内（我们一直在处理`CsrfRequestDataValue`令牌）。

因此，在这本书中，我们已经使用 Thymeleaf 为所有的网页页面。如果我们启用 Spring Security 中的 CSRF 支持，Thymeleaf 默认具有 CSRF 支持。

你应该从`chapter16.01-calendar`的代码开始。

如果我们启动 JBCP 日历应用程序并导航到登录页面`https://localhost:8443/login.html`，我们可以查看生成的`login.html`页面的源代码，如下所示：

```java
    <form method="POST" action="/login" ...>
      ...
 <input type="hidden" name="_csrf" value="e86c9744-5b7d-4d5f-81d5-450463222908">
    </form>
```

# Ajax 和 JSON 请求

如果你使用 JSON，那么不可能在 HTTP 参数中提交 CSRF 令牌。相反，你可以在 HTTP 头中提交令牌。一个典型的模式是将 CSRF 令牌包括在你的`<meta>`HTML 标签中。一个在 JSP 中的示例如下：

```java
    <html>
       <head>
 <meta name="_csrf" content="${_csrf.token}"/>         <!-- default header name is X-CSRF-TOKEN -->
 <meta name="_csrf_header" content="${_csrf.headerName}"/>         ...
       </head>
     ¦
```

instead of manually creating the meta tags, you can use the simpler `csrfMetaTags` tag from the Spring Security JSP tag library.

# `csrfMetaTags`标签

如果启用了 CSRF 保护，这个标签将插入包含 CSRF 保护令牌表单字段、头部名称和 CSRF 保护令牌值的元标签。这些元标签对于在应用程序中的 JavaScript 中使用 CSRF 保护非常有用。

你应该在 HTML `<head></head>`块中放置`csrfMetaTags`标签，你通常会在其他元标签中放置其他元标签。一旦使用这个标签，你可以轻松地使用 JavaScript 访问表单字段名、头部名称和令牌值，如下所示：

```java
<html>
   <head>
       ...
 <sec:csrfMetaTags />       <script type="text/javascript" language="javascript">
 var csrfParameter = $("meta[name='_csrf_parameter']").attr("content"); var csrfHeader = $("meta[name='_csrf_header']").attr("content"); var csrfToken = $("meta[name='_csrf']").attr("content");           ...
       <script>
   </head>
   ...
```

如果未启用 CSRF 保护，`csrfMetaTags`不会输出任何内容。

# jQuery 使用

You can then include the token within all of your Ajax requests. If you were using jQuery, this could be done with the following code snippet:

```java
$(function () {
var token = $("meta[name='_csrf']").attr("content");
var header = $("meta[name='_csrf_header']").attr("content");
$(document).ajaxSend(function(e, xhr, options) {
   xhr.setRequestHeader(header, token);
});
});
```

# 使用 cujoJS 的 rest.js 模块

作为 jQuery 的替代品，我们建议使用 cujoJS 的`rest.js`模块。`rest.js`模块提供了高级支持，用于以 RESTful 方式处理 HTTP 请求和响应。其核心功能是能够对 HTTP 客户端进行上下文化处理，通过将拦截器链接到客户端来添加所需的行为，如下所示：

```java
    var client = rest.chain(csrf, {
    token: $("meta[name='_csrf']").attr("content"),
    name: $("meta[name='_csrf_header']").attr("content")
    });
```

配置的客户端可以与应用程序中需要对 CSRF 受保护资源进行请求的任何组件共享。`rest.js`与 jQuery 之间的一个重要区别是，仅使用配置的客户端发出的请求将包含 CSRF 令牌，而在 jQuery 中，所有请求都将包含令牌。能够确定哪些请求接收到令牌有助于防止泄露 CSRF 令牌给第三方。

有关`rest.js`的更多信息，请参考`rest.js`参考文档。

[(](https://github.com/cujojs/rest/tree/master/docs)[`github.com/cujojs/rest/tree/master/docs`](https://github.com/cujojs/rest/tree/master/docs)[).](https://github.com/cujojs/rest/tree/master/docs)

# CSRF 注意事项

在 Spring Security 中实现 CSRF 时，有几个注意事项你需要知道。

# 超时

一个问题是在`HttpSession`方法中存储了预期的 CSRF 令牌，所以一旦`HttpSession`方法过期，您配置的`AccessDeniedHandler`处理器将会接收到`InvalidCsrfTokenException`。如果您正在使用默认的`AccessDeniedHandler`处理器，浏览器将得到一个 HTTP 403，并显示一个糟糕的错误信息。

你可能会问为什么预期的`CsrfToken`令牌不是存储在 cookie 中。这是因为已知存在一些利用方式，其中头部（指定 cookie）可以由另一个域设置。

这是同样的原因，Ruby on Rails 不再在存在 X-Requested-With 头时跳过 CSRF 检查 ([`weblog.rubyonrails.org/2011/2/8/csrf-protection-bypass-in-ruby-on-rails/`](http://weblog.rubyonrails.org/2011/2/8/csrf-protection-bypass-in-ruby-on-rails/)).

Web 应用安全委员会(*Web Application Security Consortium*) ([`www.webappsec.org`](http://www.webappsec.org/))有一个详细的线程，讨论使用 CSRF 和 HTTP 307 重定向来执行 CSRF cookie 利用。

有关如何执行利用的具体细节，请参阅这个[www.webappsec.org](http://www.webappsec.org/)线程：[`lists.webappsec.org/pipermail/websecurity_lists.webappsec.org/2011-February/007533.html`](http://lists.webappsec.org/pipermail/websecurity_lists.webappsec.org/2011-February/007533.html)。

另一个缺点是，通过移除状态（超时），您失去了在某些东西被泄露时强制终止令牌的能力。

减轻活动用户遇到超时的一种简单方法是有一些 JavaScript，让用户知道他们的会话即将过期。用户可以点击一个按钮来继续并刷新会话。

另外，指定一个自定义的`AccessDeniedHandler`处理器可以让您以任何喜欢的方式处理`InvalidCsrfTokenException`，正如我们接下来代码中所看到的：

```java
//src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

@Override
public void configure(HttpSecurity http) throws Exception {
 http.exceptionHandling() .accessDeniedHandler(accessDeniedHandler); }
@Bean
public CustomAccessDeniedHandler accessDeniedHandler(){
 return new CustomAccessDeniedHandler(); }
```

# 登录

为了防止伪造登录请求，登录表单也应该受到 CSRF 攻击的保护。由于`CsrfToken`令牌存储在`HttpSession`中，这意味着一旦访问`CsrfToken`属性，就会立即创建一个`HttpSession`方法。虽然这在 RESTful/无状态架构中听起来很糟糕，但现实是状态是实现实际安全所必需的。如果没有状态，如果令牌被泄露，我们无能为力。实际上，CSRF 令牌的大小相当小，对架构的影响应该可以忽略不计。

攻击者可能会伪造一个请求，使用攻击者的凭据将受害者登录到目标网站，这被称为登录 CSRF([`en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests`](https://en.wikipedia.org/wiki/Cross-site_request_forgery#Forging_login_requests))。

# 登出

添加 CSRF 将更新`LogoutFilter`过滤器，使其只使用 HTTP`POST`。这确保了登出需要 CSRF 令牌，并且恶意用户不能强制登出您的用户。

一种方法是使用`<form>`标签进行登出。如果你想要一个 HTML 链接，你可以使用 JavaScript 让链接执行 HTTP`POST`（可以是一个隐藏的表单）。对于禁用 JavaScript 的浏览器，你可以选择让链接带用户到执行 HTTP`POST`的登出确认页面。

如果你想使用 HTTP`GET`进行登出，你可以这样做，但请记住，这通常不推荐。例如，以下 Java 配置将在任何 HTTP 方法请求登出 URL 模式时执行登出：

```java
//src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

@Override
protected void configure(HttpSecurity http) throws Exception {
 http.logout() .logoutRequestMatcher( new AntPathRequestMatcher("/logout")); }
```

# 安全 HTTP 响应头

下面的部分讨论了 Spring Security 为将各种安全头添加到响应中提供的支持。

# 默认安全头

Spring Security 允许用户轻松地注入默认的安全头，以帮助保护他们的应用程序。以下是由 Spring Security 提供的当前默认安全头的列表：

+   `Cache-Control`

+   `Content-Type Options`

+   HTTP 严格传输安全

+   `X-Frame-Options`

+   `X-XSS-Protection`

虽然每个头都被认为是最佳实践，但应注意的是，并非所有客户端都使用这些头，因此鼓励进行额外测试。出于被动原因，如果你使用 Spring Security 的 XML 命名空间支持，你必须显式启用安全头。所有默认头都可以通过没有子元素的`<headers>`元素轻松添加。

*SEC-2348*被记录下来，以确保 Spring Security 4.x 的 XML 命名空间配置将默认启用安全头([`github.com/spring-projects/spring-security/issues/2575`](https://github.com/spring-projects/spring-security/issues/2575))。

如果你使用 Spring Security 的 Java 配置，所有的默认安全头都会被默认添加。它们可以通过 Java 配置禁用，如下所示：

```java
//src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

@Override
protected void configure(HttpSecurity http) throws Exception {
 http.headers().disable(); }
```

下面的代码将安全头添加到响应中。当使用`WebSecurityConfigurerAdapter`的默认构造函数时，这是默认激活的。接受`WebSecurityConfigurerAdapter`提供的默认值，或者只调用`headers()`方法而不调用其他方法，等效于以下代码片段：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   http
 .headers() .contentTypeOptions() .and() .xssProtection() .and() .cacheControl() .and() .httpStrictTransportSecurity() .and() .frameOptions()         .and()
     ...;
}
```

一旦你指定了任何应该包括的头，那么只有这些头会被包括。例如，以下配置仅包括对 X-Frame-Options 的支持：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   ...
 http.headers().frameOptions(); }
```

# Cache-Control

在过去，Spring Security 要求你必须为你的网络应用程序提供自己的 `Cache-Control` 方法。当时这看起来是合理的，但是浏览器缓存已经发展到包括对安全连接的缓存。这意味着一个用户可能查看一个认证过的页面，登出后，恶意用户就可以利用浏览器历史记录来查看缓存的页面。

为了帮助减轻这个问题，Spring Security 增加了对 `Cache-Control` 的支持，它将以下头部信息插入到你的响应中：

```java
Cache-Control: no-cache, no-store, max-age=0, must-revalidate
Pragma: no-cache
Expires: 0
```

仅仅添加 `headers()` 方法而没有子元素将会自动添加 `Cache-Control` 和其他很多保护选项。然而，如果你只想要 `Cache-Control`，你可以使用 Spring Security 的 Java 配置方法，如下所示：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   http.headers()
 .cacheControl(); }
```

如果你想要缓存特定的响应，你的应用程序可以选择性地调用 `HttpServletResponse.setHeader(String,String)` 来覆盖 Spring Security 设置的头部。这对于确保诸如 CSS、JavaScript 和图片等被正确缓存很有用。

在使用 Spring Web MVC 时，这通常是在你的配置中完成的。例如，以下配置将确保为你的所有资源设置缓存头部：

```java
@EnableWebMvc
public class WebMvcConfiguration
extends WebMvcConfigurerAdapter {
   @Override
   public void addResourceHandlers(
                   ResourceHandlerRegistry registry) {
 registry .addResourceHandler("/resources/**") .addResourceLocations("/resources/") .setCachePeriod(3_155_6926);   }
   // ...
}
```

# Content-Type 选项

历史上，包括 Internet Explorer 在内的浏览器会尝试使用内容嗅探来猜测请求的内容类型。这允许浏览器通过猜测未指定内容类型的资源的內容类型来改进用户体验。例如，如果浏览器遇到一个没有指定内容类型的 JavaScript 文件，它将能够猜测内容类型并执行它。

还有许多其他的事情需要做，比如只在一个独特的域中显示文档，确保设置 Content-Type 头部，对文档进行清理等等，当允许内容上传时。然而，这些措施超出了 Spring Security 提供的范围。重要的是指出，在禁用内容嗅探时，你必须指定内容类型，以便一切正常工作。

内容嗅探的问题在于，这允许恶意用户使用多语言（一个可以作为多种内容类型有效的文件）来执行 XSS 攻击。例如，一些网站可能允许用户向网站提交一个有效的 PostScript 文档并查看它。恶意用户可能会创建一个同时是有效的 JavaScript 文件的 PostScript 文档，并利用它执行 XSS 攻击（[`webblaze.cs.berkeley.edu/papers/barth-caballero-song.pdf`](http://webblaze.cs.berkeley.edu/papers/barth-caballero-song.pdf)）。

可以通过向我们的响应中添加以下头部来禁用内容嗅探：

```java
    X-Content-Type-Options: nosniff
```

与`Cache-Control`元素一样，`nosniff`指令在没有子元素的情况下使用`headers()`方法时默认添加。在 Spring Security Java 配置中，`X-Content-Type-Options`头默认添加。如果您想对头部有更精细的控制，您可以显式指定内容类型选项，如下代码所示：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   http.headers()
       .contentTypeOptions();
}
```

# HTTP 严格传输安全

当您输入您的银行网站时，您是输入`mybank.example.com`，还是输入`https://mybank.example.com`？如果您省略了 HTTPS 协议，您可能会受到中间人攻击的潜在威胁。即使网站执行重定向到`https://**my**bank.example.com`，恶意用户仍然可以拦截最初的 HTTP 请求并操纵响应（重定向到`https://**mi**bank.example.com`并窃取他们的凭据）。

许多用户省略了 HTTPS 协议，这就是为什么创建了 HSTS。

根据*RFC6797*，HSTS 头部仅注入到 HTTPS 响应中。为了使浏览器认可该头部，浏览器必须首先信任签署用于建立连接的 SSL 证书的 CA，而不仅仅是 SSL 证书（[`tools.ietf.org/html/rfc6797`](https://tools.ietf.org/html/rfc6797)）。

一旦`mybank.example.com`被添加为 HSTS 主机，浏览器就可以提前知道任何对`mybank.example.com`的请求都应该被解释为`https://mybank.example.com`。这大大减少了发生中间人攻击的可能性。

一个网站被标记为 HSTS 主机的途径之一是将主机预加载到浏览器中。另一个途径是在响应中添加`Strict-Transport-Security`头部。例如，下面的内容将指导浏览器将域名视为 HSTS 主机一年（一年大约有`31,536,000`秒）：

```java
    Strict-Transport-Security: max-age=31536000 ; includeSubDomains
```

可选的`includeSubDomains`指令告知 Spring Security，子域名（如`secure.mybank.example.com`）也应该被视为一个 HSTS 域名。

与其它头部一样，当在`headers()`方法中没有子元素指定时，Spring Security 将前一个头部添加到响应中，但当你使用 Java 配置时，它会自动添加。您还可以仅使用 HSTS 头部与`hsts()`方法一起使用，如下面的代码所示：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   http.headers()
 .hsts(); }
```

# X-Frame-Options

允许您的网站被添加到框架中可能是一个安全问题。例如，通过巧妙的 CSS 样式，用户可能会被诱骗点击他们本不想点击的东西。

在[`www.youtube.com/watch?v=3mk0RySeNsU`](https://www.youtube.com/watch?v=3mk0RySeNsU)观看 Clickjacking 视频演示。

例如，一个已登录其银行的用户的可能会点击一个授予其他用户访问权限的按钮。这种攻击称为 Clickjacking。

在[`www.owasp.org/index.php/Clickjacking`](https://www.owasp.org/index.php/Clickjacking)阅读更多关于 Clickjacking 的信息。

处理 Clickjacking 的另一种现代方法是使用内容安全策略。Spring Security 不提供对此的支持，因为该规范尚未发布，而且相当复杂。然而，你可以使用静态头功能来实现这一点。要了解此问题的最新动态以及如何使用 Spring Security 实现它，请参阅*SEC-2117*在[`github.com/spring-projects/spring-security/issues/2342`](https://github.com/spring-projects/spring-security/issues/2342)。

有许多方法可以缓解 Clickjacking 攻击。例如，为了保护老式浏览器不受 Clickjacking 攻击，你可以使用破帧代码。虽然不是完美的，但破帧代码对于老式浏览器来说是最好的做法。

解决 Clickjacking 的更现代方法是使用`X-Frame-Options`头，如下所示：

```java
    X-Frame-Options: DENY
```

`X-Frame-Options`响应头指示浏览器防止任何在响应中包含此头的站点被渲染在框架内。与其他响应头一样，当没有子元素的`headers()`方法被指定时，此头会自动包含。你还可以明确指定 frame-options 元素以控制要添加到响应中的哪些头，如下所示：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   http.headers()
 .frameOptions(); }
```

如果你想要更改`X-Frame-Options`头的值，那么你可以使用一个`XFrameOptionsHeaderWriter`实例。

一些浏览器内置了对过滤掉反射型 XSS 攻击的支持。这绝不是万无一失的，但它确实有助于 XSS 保护。

过滤通常默认启用，因此添加头 just 确保它已启用，并指示浏览器在检测到 XSS 攻击时应该做什么。例如，过滤器可能会尝试以最不具侵入性的方式更改内容以仍然呈现一切。有时，这种类型的替换本身可能成为一个 XSS 漏洞。相反，最好阻止内容，而不是尝试修复它。为此，我们可以添加以下头：

```java
    X-XSS-Protection: 1; mode=block
```

当使用`headers()`方法且没有子元素时，默认包含此标题。我们可以使用`xssProtection`元素明确地声明，如下所示：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   http.headers()
       .xssProtection();
}
```

# 自定义头

Spring Security 具有机制，使其方便地向你的应用程序添加更多常见的 security headers。然而，它还提供了挂载点，以启用添加自定义头。

# 静态头

有时你可能希望向你的应用程序中注入自定义的安全头，但这些头并不是开箱即用的。例如，也许你希望提前支持内容安全策略，以确保资源只从同一来源加载。由于内容安全策略的支持尚未最终确定，浏览器使用两个常见的扩展头之一来实现此功能。这意味着我们将需要注入策略两次。以下代码段显示了头部的示例：

```java
X-Content-Security-Policy: default-src 'self'
X-WebKit-CSP: default-src 'self'
```

当使用 Java 配置时，这些头可以使用`header()`方法添加到响应中，如下所示：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   http.headers()
       .addHeaderWriter(
         new StaticHeadersWriter(
               "X-Content-Security-Policy",
               "default-src 'self'"))
       .addHeaderWriter(
           new StaticHeadersWriter(
               "X-WebKit-CSP",
               "default-src 'self'"));
}
```

# `HeadersWriter`实例

当命名空间或 Java 配置不支持您想要的头时，您可以创建一个自定义`HeadersWriter`实例，甚至提供`HeadersWriter`的自定义实现。

让我们来看一个使用自定义实例`XFrameOptionsHeaderWriter`的例子。也许你想允许相同源的内容框架。这可以通过将策略属性设置为`SAMEORIGIN`轻松支持，但让我们来看一个更明确的例子，使用`ref`属性，如下面的代码片段所示：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
   http.headers()
       .addHeaderWriter(
           new XFrameOptionsHeaderWriter(
               XFrameOptionsMode.SAMEORIGIN));
}
```

# `DelegatingRequestMatcherHeaderWriter`类

有时，您可能只想为某些请求写入头。例如，也许您只想保护登录页面不被框架。您可以使用`DelegatingRequestMatcherHeaderWriter`类来实现。当使用 Java 配置时，可以用以下代码完成：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
 DelegatingRequestMatcherHeaderWriter headerWriter = new DelegatingRequestMatcherHeaderWriter( new AntPathRequestMatcher("/login"), new XFrameOptionsHeaderWriter());   http.headers()
       .addHeaderWriter(headerWriter);
}
```

# 总结

在本章中，我们介绍了几种安全漏洞，并使用了 Spring Security 来规避这些漏洞。阅读本章后，你应该理解 CSRF 的威胁以及使用同步令牌来预防 CSRF。

您还应该知道如何使用`Cache-Control`、`Content-Type Options`、HSTS、`X-Frame-Options`和`X-XSS-Protection`方法，将各种 HTTP 头包含在内，以保护免受常见安全漏洞的侵害。

在下一章中，我们将讨论如何从 Spring Security 3.x 迁移到 Spring Security 4.2。


# 第十五章：迁移到 Spring Security 4.2。

在本书的最后一章中，我们将回顾与从 Spring Security 3 迁移到 Spring Security 4.2 的常见迁移问题有关的信息。我们将花更多的时间讨论 Spring Security 3 和 Spring Security 4 之间的差异，因为这是大多数用户将遇到的难题。这是由于从 Spring Security 3 更新到 Spring Security 4.2 包含大量的非被动重构。

在本章末尾，我们还将突出显示 Spring Security 4.2 中可以找到的一些新功能。然而，我们并没有明确涵盖从 Spring Security 3 到 Spring Security 4.2 的变化。这是因为通过解释 Spring Security 3 和 Spring Security 4 之间的差异，用户应该能够轻松地更新到 Spring Security 4.2，因为 Spring Security 4.2 的变化是被动的。

在本章中，我们将涵盖以下主题：

+   回顾 Spring Security 4.2 中的重要增强功能。

+   了解您现有 Spring 版本中所需的配置更改。

+   当将它们迁移到 Spring Security 4.2 时，回顾 Spring Security 3 应用程序。

+   说明 Spring Security 4 中重要类和包的整体移动情况。

+   突出显示 Spring Security 4.2 中的一些新功能。一旦完成了本章的复习，你将处于一个很好的位置，可以将从 Spring Security 3 迁移到 Spring Security 4.2 的现有应用程序。

+   从 Spring Security 3 迁移。

你可能正在计划将一个现有应用程序迁移到 Spring Security 4.2，或者你可能正在尝试为 Spring Security 3 应用程序添加功能，并在这本书的页面中寻找指导。我们将在本章中尝试解决你们的两个问题。

首先，我们将概述 Spring Security 3 和 4.2 之间的关键差异，包括功能和配置。其次，我们将提供一些关于映射配置或类名更改的指导。这将使你更好地能够将书中的示例从 Spring Security 4.2 回退到 Spring Security 3（适用的）。

一个非常重要的迁移注意事项是，Spring Security 3+ 强制要求迁移到 Spring Framework 4 和 Java 5 (1.5) 或更高版本。请注意，在许多情况下，迁移这些其他组件可能对您的应用程序的影响比 Spring Security 的升级要大！

# 引言。

随着应用程序的利用方式不断发展，Spring Security 也必须做出相应的更新。在重大发布版本中，Spring Security 团队抓住了机会，进行了一些非被动的更改，主要关注以下几点：

+   通过默认设置确保 Spring Security 更加安全([`www.owasp.org/index.php/Establish_secure_defaults`](https://www.owasp.org/index.php/Establish_secure_defaults))。

+   最小化信息泄露([`www.owasp.org/index.php/Information_Leakage`](https://www.owasp.org/index.php/Information_Leakage))。

+   移除已弃用的 API。

在 JIRA 中可以找到 3.x 和 4.x 之间非被动更改的完整列表：[`jira.spring.io/browse/SEC-2916?jql=project%20%3D%20SEC%20AND%20fixVersion%20in%20(4.0.0%2C%204.0.0.M1%2C%204.0.0.M2%2C%204.0.0.RC1%2C%204.0.0.RC2)%20AND%20labels%20%3D%20passivity`](https://jira.spring.io/browse/SEC-2916?jql=project%20%3D%20SEC%20AND%20fixVersion%20in%20(4.0.0%2C%204.0.0.M1%2C%204.0.0.M2%2C%204.0.0.RC1%2C%204.0.0.RC2)%20AND%20labels%20%3D%20passivity).

# 示例迁移

Spring Security 团队创建了一个示例项目，展示了从 3.x 迁移到 4.x 时的所有更改，并将在 GitHub 上提供该项目。

示例包括 XML 和 JavaConfig 示例，可以在[`github.com/spring-projects/spring-security-migrate-3-to-4/`](https://github.com/spring-projects/spring-security-migrate-3-to-4/)找到。

# 在 Spring Security 4.2 中的增强功能

在 Spring Security 4.2 中有很多值得注意的更改，此版本还带来了对 Spring Framework 5 的早期支持。你可以找到 4.2.0.M1、4.2.0.RC1 和 4.2.0.RELEASE 的更改日志，涵盖了超过 80 个问题。社区贡献了绝大多数这些功能。

在 Spring Security 4.2 中进行了重大改进，自 Spring Security 3 以来，包括以下特性和它们的支持号码：

# 网络改进：

以下项目与 Spring Security 与基于 Web 的应用程序的交互相关：

+   **#3812**: Jackson 支持

+   **#4116**: 引用策略

+   **#3938**: 添加 HTTP 响应分割预防

+   **#3949**: 为`@AuthenticationPrincipal`添加了 bean 引用支持

+   **#3978**: 支持使用新添加的`RequestAttributeAuthenticationFilter`的 Standford WebAuth 和 Shibboleth。

+   **#4076**: 文档代理服务器配置

+   **#3795**: `ConcurrentSessionFilter`支持`InvalidSessionStrategy`

+   **#3904**: 添加`CompositeLogoutHandler`

# Spring Security 配置改进：

以下项目与 Spring Security 的配置相关：

+   **#3956**: 默认角色前缀的集中配置。详情请看问题

+   **#4102**: 在`WebSecurityConfigurerAdapter`中自定义默认配置

+   **#3899**: `concurrency-control@max-sessions`支持无限会话。

+   **#4097**: `intercept-url@request-matcher-ref`为 XML 命名空间添加了更强大的请求匹配支持

+   **#3990**: 支持从 Map（如 YML）构建`RoleHierarchy`。

+   **#4062**: 自定义`cookiePath`到`CookieCsrfTokenRepository`。

+   **#3794**: 允许在`SessionManagementConfigurer`上配置`InvalidSessionStrategy`

+   **#4020**: 修复`defaultMethodExpressionHandler`暴露的 beans 可以防止方法安全

# 在 Spring Security 4.x 中的其他更改

以下项目是一些值得注意的其他更改，其中许多可能会影响升级到 Spring Security 4.x：

+   **#4080**: Spring 5

+   #4095 - 添加`UserBuilder`

+   **#4018**：在`csrf()`被调用后进行修复，未来的`MockMvc`调用使用原始的`CsrfTokenRepository`

+   **常规依赖版本更新**

请注意，列出的数字指的是 GitHub 的 pull 请求或问题。

其他更微小的变化，包括代码库和框架配置的整体重构和清理，使整体结构和使用更具意义。Spring Security 的作者在登录和 URL 重定向等领域增加了可扩展性，尤其是之前不存在扩展性的地方。

如果你已经在 Spring Security 3 环境中工作，如果你没有推动框架的边界，可能不会找到升级的强烈理由。然而，如果你在 Spring Security 3 的可扩展点、代码结构或可配置性方面发现了局限性，那么你会欢迎我们在本章剩余部分详细讨论的许多小变化。

# **Spring Security 4 中的配置更改**

Spring Security 4 中的许多变化将在基于 XML 的配置的命名空间风格中可见。本章将主要覆盖基于 Java 的配置，但也会注意一些值得注意的基于 XML 的变化。尽管本章无法详细涵盖所有的小变化，但我们将尝试涵盖那些在您迁移到 Spring Security 4 时最可能影响您的变化。

# **废弃内容**

在 Spring Security 4 中移除了一大批废弃内容，以清理混乱。

以下是对 XML 和 JavaConfig 废弃内容的最终提交，其中包含 177 个更改文件，新增 537 处，删除 5023 处：[`github.com/spring-projects/spring-security/commit/6e204fff72b80196a83245cbc3bd0cd401feda00`](https://github.com/spring-projects/spring-security/commit/6e204fff72b80196a83245cbc3bd0cd401feda00)。

如果你使用 XML 命名空间或基于 Java 的配置，在许多情况下，你会避免废弃问题。如果你（或你使用的非 Spring 库）没有直接使用 API，那么你将不会受到影响。你可以很容易地在你的工作区中搜索这些列出的废弃内容。

# **Spring Security 核心模块的废弃内容**

本节描述了`spring-security-core`模块中所有的废弃 API。

# **org.springframework.security.access.SecurityConfig**

`SecurityConfig.createSingleAttributeList(String)`接口已被`SecurityConfig.createList(String¦ )`取代。这意味着如果你有这样的内容：

```java
     List<ConfigAttribute> attrs = SecurityConfig.createSingleAttributeList
     ("ROLE_USER");
```

它需要用以下代码替换：

```java
    List<ConfigAttribute> attrs = SecurityConfig.createList("ROLE_USER");
```

# **UserDetailsServiceWrapper**

`UserDetailsServiceWrapper`已被`RoleHierarchyAuthoritiesMapper`取代。例如，你可能有这样的内容：

```java
@Bean
public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
      return new ProviderManager(providers);
}
@Bean
public AuthenticationProvider authenticationProvider(UserDetailsServiceWrapper userDetailsService) {
      DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
      provider.setUserDetailsService(userDetailsService);
      return provider;
}
@Bean
public UserDetailsServiceWrapper userDetailsServiceWrapper(RoleHierarchy roleHierarchy) {
      UserDetailsServiceWrapper wrapper = new UserDetailsServiceWrapper();
      wrapper.setRoleHierarchy(roleHierarchy);
      wrapper.setUserDetailsService(userDetailsService());
      return wrapper;
}
```

它需要被替换成类似这样的内容：

```java
@Bean
public AuthenticationManager authenticationManager(List<AuthenticationProvider> providers) {
      return new ProviderManager(providers);
}
@Bean
public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService, GrantedAuthoritiesMapper authoritiesMapper) {
      DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
      provider.setUserDetailsService(userDetailsService);
      provider.setAuthoritiesMapper(authoritiesMapper);
      return provider;
}
@Bean
public RoleHierarchyAuthoritiesMapper roleHierarchyAuthoritiesMapper(RoleHierarchy roleHierarchy) {
      return new RoleHierarchyAuthoritiesMapper(roleHierarchy);
}
```

# **UserDetailsWrapper**

`UserDetailsWrapper`因使用`RoleHierarchyAuthoritiesMapper`而被废弃。通常用户不会直接使用`UserDetailsWrapper`类。然而，如果他们这样做，他们可以使用`RoleHierarchyAuthoritiesMapper`，例如，下面代码可能存在：

```java
    UserDetailsWrapper authenticate = new UserDetailsWrapper
    (userDetails, roleHiearchy);
```

如果如此，则需要用以下代码片段替换：

```java
    Collection<GrantedAuthority> allAuthorities = roleHiearchy.
    getReachableGrantedAuthorities(userDetails.getAuthorities());
    UserDetails authenticate = new User(userDetails.getUsername(), 
    userDetails.getPassword(), allAuthorities);
```

# 抽象访问决策管理器

`AbstractAccessDecisionManager`的默认构造函数以及`setDecisionVoters`方法已被废弃。自然而然，这影响了`AffirmativeBased`、`ConsensusBased`和`UnanimousBased`子类。例如，您可能使用以下代码片段：

```java
    AffirmativeBased adm = new AffirmativeBased();
    adm.setDecisionVoters(voters);
```

如果如此，它需要更改为以下代码片段：

```java
    AffirmativeBased adm = new AffirmativeBased(voters);
```

# 认证异常

在`AuthenticationException`中接受`extraInformation`的构造函数已被移除，以防止意外泄露`UserDetails`对象。具体来说，我们移除了以下代码：

```java
    public AccountExpiredException(String msg, Object extraInformation) {
      ...
    }
```

这影响了子类`AccountStatusException`、`AccountExpiredException`、`BadCredentialsException`、`CredentialsExpiredException`、`DisabledException`、`LockedException`和`UsernameNotFoundException`。如果您使用这些构造函数中的任何一个，只需移除附加参数。例如，以下代码片段更改了：

```java
    new LockedException("Message", userDetails);
```

上述代码片段应更改为以下代码片段：

```java
    new LockedException("Message");
```

# 匿名认证提供者

`AnonymousAuthenticationProvider`的默认构造函数和`setKey`方法因使用构造器注入而被废弃。例如，您可能有以下代码片段：

```java
    AnonymousAuthenticationProvider provider = new 
    AnonymousAuthenticationProvider();
    provider.setKey(key);
```

上述代码片段应更改为以下代码：

```java
    AnonymousAuthenticationProvider provider = new 
    AnonymousAuthenticationProvider(key);
```

# 认证详情源实现类

`AuthenticationDetailsSourceImpl`类因编写自定义`AuthenticationDetailsSource`而被废弃。例如，您可能有以下内容：

```java
    AuthenticationDetailsSourceImpl source = new 
    AuthenticationDetailsSourceImpl();
    source.setClazz(CustomWebAuthenticationDetails.class);
```

您应该直接实现`AuthenticationDetailsSource`类以返回`CustomSource`对象：

```java
public class CustomWebAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, WebAuthenticationDetails> {
      public WebAuthenticationDetails buildDetails(HttpServletRequest context) {
            return new CustomWebAuthenticationDetails(context);
      }
}
```

# 认证提供者管理器

`ProviderManager`类移除了废弃的默认构造函数和相应的设置器方法，改为使用构造器注入。它还移除了`clearExtraInformation`属性，因为`AuthenticationException`异常已经移除了额外信息属性。

例如，您可能像以下内容一样：

```java
ProviderManager provider = new ProviderManager();
provider.setParent(parent);
provider.setProviders(providers);
provider.setClearExtraInformation(true);
```

如果如此，上述代码应更改为以下代码：

```java
ProviderManager provider = new ProviderManager(providers, parent);
```

由于`AuthenticationException`异常已经移除了额外信息属性，因此移除了`clearExtraInformation`属性。对此没有替代方案。

# 记住我认证提供者

`RememberMeAuthenticationProvider`类移除了默认构造函数和`setKey`方法，改为使用构造器注入。例如，查看以下代码：

```java
    RememberMeAuthenticationProvider provider = new 
    RememberMeAuthenticationProvider();
    provider.setKey(key);
```

上述代码片段应迁移至以下内容：

```java
    RememberMeAuthenticationProvider provider = new 
    RememberMeAuthenticationProvider(key);
```

# 授权实体实现类

`GrantedAuthorityImpl`已被`SimpleGrantedAuthority`所取代，或者实现你自己的`GrantAuthority`对象。例如：

```java
    new GrantedAuthorityImpl(role);
```

这应该替换为以下内容：

```java
    new SimpleGrantedAuthority(role);
```

# `InMemoryDaoImpl`

`InMemoryDaoImpl`已被`InMemoryUserDetailsManager`所取代。例如：

```java
InMemoryDaoImpl uds = new InMemoryDaoImpl();
uds.setUserProperties(properties);
```

这应该被替换为：

```java
InMemoryUserDetailsManager uds = new InMemoryUserDetailsManager(properties);
spring-security-web
```

# `spring-security-web`模块中的弃用

本节描述了`spring-security-web`模块中所有弃用的 API。

# `FilterChainProxy`

`FilterChainProxy`移除了`setFilterChainMap`方法，改为使用构造注入。例如，你可能有以下内容：

```java
FilterChainProxy filter = new FilterChainProxy();
filter.setFilterChainMap(filterChainMap);
```

它应该被替换为：

```java
FilterChainProxy filter = new FilterChainProxy(securityFilterChains);
```

`FilterChainProxy`也移除了`getFilterChainMap`，改为使用`getFilterChains`，例如：

```java
    FilterChainProxy securityFilterChain = ...
    Map<RequestMatcher,List<Filter>> mappings = 
    securityFilterChain.getFilterChainMap();
    for(Map.Entry<RequestMatcher, List<Filter>> entry : mappings.entrySet()) {
          RequestMatcher matcher = entry.getKey();
          boolean matches = matcher.matches(request);
          List<Filter> filters = entry.getValue();
    }
```

这应该替换为以下代码：

```java
    FilterChainProxy securityFilterChain = ...
    List<SecurityFilterChain> mappings = securityFilterChain.getFilterChains();
    for(SecurityFilterChain entry : mappings) {
          boolean matches = entry.matches(request);
          List<Filter> filters = entry.getFilters();
    }
```

# `ExceptionTranslationFilter`

`ExceptionTranslationFilter`的默认构造函数和`setAuthenticationEntryPoint`方法已被移除，改为使用构造注入：

```java
ExceptionTranslationFilter filter = new ExceptionTranslationFilter();
filter.setAuthenticationEntryPoint(entryPoint);
filter.setRequestCache(requestCache);
```

这可以用以下代码替换：

```java
    ExceptionTranslationFilter filter = new 
    ExceptionTranslationFilter(entryPoint, requestCache);
```

# `AbstractAuthenticationProcessingFilter`

`AbstractAuthenticationProcessingFilter`类的`successfulAuthentication(HttpServletRequest,HttpServletResponse,Authentication)`方法已被移除。所以，你的应用程序可能重写了以下方法：

```java
    protected void successfulAuthentication(HttpServletRequest request, 
    HttpServletResponse response, Authentication authResult) throws IOException,    
    ServletException {
    }
```

应替换为以下代码：

```java
    protected void successfulAuthentication(HttpServletRequest request,
     HttpServletResponse response, FilterChain chain, Authentication 
     authResult) throws IOException, ServletException {
    }
```

# `AnonymousAuthenticationFilter`

`AnonymousAuthenticationFilter`类的默认构造函数和`setKey`、`setPrincipal`方法已被移除，改为使用构造注入。例如，看看以下代码片段：

```java
    AnonymousAuthenticationFilter filter = new 
    AnonymousAuthenticationFilter();
    filter.setKey(key);
    filter.setUserAttribute(attrs);
```

这应该替换为以下代码：

```java
    AnonymousAuthenticationFilter filter = new   
    AnonymousAuthenticationFilter(key,attrs.getPassword(),
    attrs.getAuthorities());
```

# `LoginUrlAuthenticationEntryPoint`

`LoginUrlAuthenticationEntryPoint`的默认构造函数和`setLoginFormUrl`方法已被移除，改为使用构造注入。例如：

```java
    LoginUrlAuthenticationEntryPoint entryPoint = new 
    LoginUrlAuthenticationEntryPoint();
    entryPoint.setLoginFormUrl("/login");
```

这应该替换为以下代码：

```java
    LoginUrlAuthenticationEntryPoint entryPoint = new   
    LoginUrlAuthenticationEntryPoint(loginFormUrl);
```

# `PreAuthenticatedGrantedAuthoritiesUserDetailsService`

`PreAuthenticatedGrantedAuthoritiesUserDetailsService`接口移除了`createuserDetails`，改为`createUserDetails`。

新方法在案例中进行了更正（`U`而不是`u`）。

这意味着如果你有一个`PreAuthenticatedGrantedAuthoritiesUserDetailsService`类的子类，它重写了`createuserDetails`，例如`SubclassPreAuthenticatedGrantedAuthoritiesUserDetailsService`扩展了`PreAuthenticatedGrantedAuthoritiesUserDetailsService`。

```java
{
      @Override
      protected UserDetails createuserDetails(Authentication token,
                  Collection<? extends GrantedAuthority> authorities) {
            // customize
      }
}
```

它应该更改为重写`createUserDetails`：

```java
public class SubclassPreAuthenticatedGrantedAuthoritiesUserDetailsService extends PreAuthenticatedGrantedAuthoritiesUserDetailsService {
      @Override
      protected UserDetails createUserDetails(Authentication token,
                  Collection<? extends GrantedAuthority> authorities) {
            // customize
      }
}
```

# `AbstractRememberMeServices`

`AbstractRememberMeServices`及其子类`PersistentTokenBasedRememberMeServices`和`TokenBasedRememberMeServices`移除了默认构造函数、`setKey`和`setUserDetailsService`方法，改为使用构造注入。

# `PersistentTokenBasedRememberMeServices`

对`AbstractRememberMeServices`及其子类`PreAuthenticatedGrantedAuthoritiesUserDetailsService`的更改使得用法类似于以下示例：

```java
PersistentTokenBasedRememberMeServices services = new PersistentTokenBasedRememberMeServices();
services.setKey(key);
services.setUserDetailsService(userDetailsService);
services.setTokenRepository(tokenRepository);
```

但实现用法现在应替换为：

```java
PersistentTokenBasedRememberMeServices services = new PersistentTokenBasedRememberMeServices(key, userDetailsService, tokenRepository);
```

# `RememberMeAuthenticationFilter`

`RememberMeAuthenticationFilter`的默认构造函数、`setAuthenticationManager`和`setRememberMeServices`方法已被移除，改为使用构造器注入，如下：

```java
RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter();
filter.setAuthenticationManager(authenticationManager);
filter.setRememberMeServices(rememberMeServices);
```

这应该替换为：

```java
RememberMeAuthenticationFilter filter = new RememberMeAuthenticationFilter(authenticationManager,rememberMeServices);
```

# TokenBasedRememberMeServices

`AbstractRememberMeServices`及其子类`PersistentTokenBasedRememberMeServices`和`TokenBasedRememberMeServices`移除了默认构造函数、`setKey`和`setUserDetailsService`方法，改为使用构造器注入。例如：

```java
TokenBasedRememberMeServices services = new TokenBasedRememberMeServices();
services.setKey(key);
services.setUserDetailsService(userDetailsService);
```

这应该替换为：

```java
TokenBasedRememberMeServices services = new TokenBasedRememberMeServices(key, userDetailsService);
```

# ConcurrentSessionControlStrategy

`ConcurrentSessionControlStrategy`已被替换为`ConcurrentSessionControlAuthenticationStrategy`。以前，`ConcurrentSessionControlStrategy`无法与`SessionFixationProtectionStrategy`解耦。现在它完全解耦了。例如：

```java
ConcurrentSessionControlStrategy strategy = new ConcurrentSessionControlStrategy(sessionRegistry);
```

这可以替换为：

```java
List<SessionAuthenticationStrategy> delegates = new ArrayList<SessionAuthenticationStrategy>();
delegates.add(new ConcurrentSessionControlAuthenticationStrategy(sessionRegistry));
delegates.add(new SessionFixationProtectionStrategy());
delegates.add(new RegisterSessionAuthenticationStrategy(sessionRegistry));
CompositeSessionAuthenticationStrategy strategy = new CompositeSessionAuthenticationStrategy(delegates);
```

# SessionFixationProtectionStrategy

`SessionFixationProtectionStrategy`移除了`setRetainedAttributes`方法，改为让用户继承`SessionFixationProtectionStrategy`并重写`extractAttributes`方法。查看以下代码：

```java
SessionFixationProtectionStrategy strategy = new SessionFixationProtectionStrategy();
strategy.setRetainedAttributes(attrsToRetain);
```

它应该替换为：

```java
public class AttrsSessionFixationProtectionStrategy extends SessionFixationProtectionStrategy {
      private final Collection<String> attrsToRetain;
      public AttrsSessionFixationProtectionStrategy(
                  Collection<String> attrsToRetain) {
            this.attrsToRetain = attrsToRetain;
      }
      @Override
      protected Map<String, Object> extractAttributes(HttpSession session) {
            Map<String,Object> attrs = new HashMap<String, Object>();
            for(String attr : attrsToRetain) {
                  attrs.put(attr, session.getAttribute(attr));
            }
            return attrs;
      }
}
SessionFixationProtectionStrategy strategy = new AttrsSessionFixationProtectionStrategy(attrsToRetain);
```

# BasicAuthenticationFilter

`BasicAuthenticationFilter`的默认构造函数、`setAuthenticationManager`和`setRememberMeServices`方法已被移除，改为使用构造器注入：

```java
BasicAuthenticationFilter filter = new BasicAuthenticationFilter();
filter.setAuthenticationManager(authenticationManager);
filter.setAuthenticationEntryPoint(entryPoint);
filter.setIgnoreFailure(true);
```

这应该替换为：

```java
BasicAuthenticationFilter filter = new BasicAuthenticationFilter(authenticationManager,entryPoint);
```

使用这个构造函数会自动将`ignoreFalure`设置为`true`。

# SecurityContextPersistenceFilter

`SecurityContextPersistenceFilter`移除了`setSecurityContextRepository`，改为使用构造器注入。例如：

```java
SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
filter.setSecurityContextRepository(securityContextRepository);
```

这应该替换为：

```java
SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter(securityContextRepository);
```

# RequestCacheAwareFilter

`RequestCacheAwareFilter`移除了`setRequestCache`，改为使用构造器注入。例如：

```java
RequestCacheAwareFilter filter = new RequestCacheAwareFilter();
filter.setRequestCache(requestCache);
```

这应该替换为：

```java
RequestCacheAwareFilter filter = new RequestCacheAwareFilter(requestCache);
```

# ConcurrentSessionFilter

`ConcurrentSessionFilter`移除了默认构造函数、`setExpiredUrl`和`setSessionRegistry`方法，改为使用构造器注入。例如：

```java
ConcurrentSessionFilter filter = new ConcurrentSessionFilter();
filter.setSessionRegistry(sessionRegistry);
filter.setExpiredUrl("/expired");
```

这应该替换为：

```java
ConcurrentSessionFilter filter = new ConcurrentSessionFilter(sessionRegistry,"/expired");
```

# SessionManagementFilter

`SessionManagementFilter`移除了`setSessionAuthenticationStrategy`方法，改为使用构造器注入。例如：

```java
SessionManagementFilter filter = new SessionManagementFilter(securityContextRepository);
filter.setSessionAuthenticationStrategy(sessionAuthenticationStrategy);
```

这应该替换为：

```java
SessionManagementFilter filter = new SessionManagementFilter(securityContextRepository, sessionAuthenticationStrategy);
```

# RequestMatcher

`RequestMatcher`及其实现已从`org.springframework.security.web.util`包移动到`org.springframework.security.web.util.matcher`。具体如下：

```java
org.springframework.security.web.util.RequestMatcher  org.springframework.security.web.util.matcher.RequestMatcher
org.springframework.security.web.util.AntPathRequestMatcher org.springframework.security.web.util.matcher.AntPathRequestMatcher
org.springframework.security.web.util.AnyRequestMatcher org.springframework.security.web.util.matcher.AnyRequestMatcher.INSTANCE
org.springframework.security.web.util.ELRequestMatcher org.springframework.security.web.util.matcher.ELRequestMatcher
org.springframework.security.web.util.IpAddressMatcher org.springframework.security.web.util.matcher.IpAddressMatcher
org.springframework.security.web.util.RequestMatcherEditor  org.springframework.security.web.util.matcher.RequestMatcherEditor
org.springframework.security.web.util.RegexRequestMatcher org.springframework.security.web.util.matcher.RegexRequestMatcher
```

# WebSecurityExpressionHandler

`WebSecurityExpressionHandler`已被移除，改为使用`SecurityExpressionHandler<FilterInvocation>`。

这意味着你可能有以下内容：

```java
WebSecurityExpressionHandler handler = ...
```

这需要更新为：

```java
SecurityExpressionHandler<FilterInvocation> handler = ...
```

你可以这样实现`WebSecurityExpressionHandler`：

```java
public class CustomWebSecurityExpressionHandler implements WebSecurityExpressionHandler {
      ...
}
```

然后它必须更新为：

```java
public class CustomWebSecurityExpressionHandler implements SecurityExpressionHandler<FilterInvocation> {
     ...
}
```

# @AuthenticationPrincipal

`org.springframework.security.web.bind.annotation.AuthenticationPrincipal`已被弃用，改为`org.springframework.security.core.annotation.AuthenticationPrincipal`。例如：

```java
import org.springframework.security.web.bind.annotation.AuthenticationPrincipal;
// ...

@RequestMapping("/messages/inbox")
public ModelAndView findMessagesForUser(@AuthenticationPrincipal CustomUser customUser) {
      // .. find messages for this user and return them ...
}
```

这应该替换为：

```java
import org.springframework.security.core.annotation.AuthenticationPrincipal;
// ...

@RequestMapping("/messages/inbox")
public ModelAndView findMessagesForUser(@AuthenticationPrincipal CustomUser customUser) {
      // .. find messages for this user and return them ...
}
```

# 迁移默认过滤器 URL

许多 servlet 过滤器的默认 URL 被更改为帮助防止信息泄露。

有很多 URL 被更改，以下提交包含了 125 个更改的文件，共有 8,122 个增加和 395 个删除：[`github.com/spring-projects/spring-security/commit/c67ff42b8abe124b7956896c78e9aac896fd79d9`](https://github.com/spring-projects/spring-security/commit/c67ff42b8abe124b7956896c78e9aac896fd79d9)。

# JAAS

遗憾的是，我们没有篇幅讨论 Spring Security 的 JAAS 集成。然而，在 Spring Security 的示例中包含了一个 JAAS 样本应用程序，可以在[`docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#jaas-sample`](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#jaas-sample)找到。实际上，还有关于 JAAS 集成的优秀文档，可以在 Spring Security 的参考资料中找到，链接为[`docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#jaas`](https://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#jaas)。当查看 JAAS 参考文档时，你会注意到，从 Spring Security 4.2 开始，支持使用 JAAS 登录模块与任意的 JAAS 配置实现。Spring Security 4.2 还在`<http>`元素中添加了`jaas-api-provision`属性，确保了对于可能依赖于 JAAS 主题的应用程序，JAAS 主题被填充。

# 摘要

本章回顾了将现有 Spring Security 3 项目升级到 Spring Security 4.2 时您将发现的主要和小幅变化。在本章中，我们回顾了框架的主要增强功能，这些功能可能会促使进行升级。我们还检查了升级要求、依赖关系和常见的代码、配置更改，这些更改可能会在升级后阻止应用程序运行。我们还涵盖了 Spring Security 作者在代码库重构过程中进行的高级代码组织变化调查。

如果你是第一次阅读这一章节，我们希望你能回到书的其余部分，并使用这一章节作为指南，使你的 Spring Security 4.2 升级尽可能顺利地进行！


# 第十六章：使用 OAuth 2 和 JSON Web Tokens 的微服务安全

在本章中，我们将探讨基于微服务的架构，并查看 OAuth 2 与**JSON Web Tokens**（**JWT**）在 Spring 基础应用程序中扮演的安全角色。

以下是在本章中将要覆盖的主题列表：

+   单体应用和微服务之间的通用区别

+   比较**服务导向架构**（**SOA**）与微服务

+   OAuth 2 的概念架构及其如何为您的服务提供可信的客户端访问

+   OAuth 2 访问令牌的类型

+   OAuth 2 的授权类型

+   检查 JWT 及其一般结构

+   实现资源服务器和认证服务器，以授予客户端访问 OAuth 2 资源的权限

+   实现 RESTful 客户端以通过 OAuth 2 授权流程访问资源

我们在这章中要覆盖的内容还有很多，但在我们详细介绍如何开始利用 Spring Security 实现 OAuth 2 和 JWT 之前，我们首先想要创建一个没有 Thymeleaf 或其他基于浏览器的用户界面的日历应用程序的基本线。

在移除所有 Thymeleaf 配置和资源后，各种控制器已转换为**JAX-RS REST**控制器。

你应该从`chapter16.00-calendar`的代码开始。

# 微服务是什么？

微服务是一种允许开发物理上分离的模块化应用程序的架构方法，这些应用程序是自主的，支持敏捷性、快速开发、持续部署和扩展。

应用程序作为一组服务构建，类似于 SOA，这样服务可以通过标准 API 进行通信，例如 JSON 或 XML，这允许聚合语言不可知的服务。基本上，服务可以用最适合创建服务任务的编程语言编写。

每个服务在其自己的进程中运行，且与位置无关，因此它可以在访问网络的任何位置运行。

# 单体应用

微服务方法与传统的单体软件方法相反，后者由紧密集成的模块组成，这些模块不经常发货，必须作为一个单一单元进行扩展。本书中的传统 Java EE 应用程序和日历应用程序就是单体应用的例子。请查看以下图表，它描述了单体架构：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/8a5ed567-edbf-45ad-bada-a2ee8e8d2dd0.png)

尽管单体方法对于某些组织和某些应用来说非常适合，但对于需要在其生态系统中具有更多灵活性和可伸缩性的公司来说，微服务越来越受欢迎。

# 微服务

微服务架构是一系列小型离散服务的集合，每个服务实现特定的业务功能。这些服务运行自己的进程，并通过 HTTP API 进行通信，通常使用 RESTful 服务方法。这些服务是为了只服务于一个特定的业务功能而创建的，比如用户管理、行政角色、电子商务购物车、搜索引擎、社交媒体集成等。请查看以下描述微服务架构的图表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/spr-sec-3e/img/4d14f1d3-65aa-41c4-9de5-2117238b8db8.png)

每个**s**服务可以独立于应用程序中的其他服务和企业中的其他系统进行部署、升级、扩展、重启和移除。

因为每个服务都是独立于其他服务创建的，所以它们可以分别用不同的编程语言编写，并使用不同的数据存储。集中式服务管理实际上是不存在的，这些服务使用轻量级的 HTTP、REST 或 Thrift API 进行相互之间的通信。

**Apache Thrift** 软件框架可以从 [`thrift.apache.org`](https://thrift.apache.org/) 下载。它是一个用于开发可扩展的跨语言服务的框架，结合了软件栈和代码生成引擎，以高效、无缝地在 C++、Java、Python、PHP、Ruby、Erlang、Perl、Haskell、C#、Cocoa、JavaScript、Node.js、Smalltalk 和其他语言之间构建服务。

# 面向服务的架构

你可能会问自己，“这不是和 SOA 一样吗？” 不完全是，你可以说是微服务实现了 SOA 最初承诺的东西。

面向服务架构（SOA）是一种软件设计风格，其中服务通过计算机网络上的语言无关的通信协议暴露给其他组件。

面向服务架构（SOA）的基本原则是独立于供应商、产品和技术的。

服务的定义是一个可以远程访问、独立操作和更新的离散功能单元，例如在线获取信用卡账单。

尽管相似，但 SOA 和微服务仍然是不同类型的架构。

典型的 SOA 通常在部署单体内部实现，并且更受平台驱动，而微服务可以独立部署，因此，在所有维度上提供更多的灵活性。

当然，关键区别在于规模；单词“微”说明了一切。微服务通常比传统的 SOA 服务要小得多。正如 Martin Fowler 所说：

“我们应该将 SOA 视为微服务的超集。”

-Martin Fowler

# 微服务安全

微服务可以提供极大的灵活性，但也会引入必须解决的问题。

# 服务通信

单体应用程序使用进程间的内存通信，而微服务通过网络进行通信。向网络通信的转变不仅涉及到速度问题，还有安全性问题。

# 紧密耦合

微服务使用许多数据存储而不是几个。这创造了微服务与紧密集成的服务之间的隐式服务合同的机会。

# 技术复杂性

微服务可能会创建额外的复杂性，这可能会造成安全漏洞。如果团队没有正确的经验，那么管理这些复杂性可能会迅速变得无法管理。

# OAuth 2 规范

有时会有一种误解，认为 OAuth 2 是 OAuth 1 的演变，但它是完全不同的方法。OAuth1 规范要求签名，因此你必须使用加密算法来创建生成和验证那些在 OAuth 2 中不再需要的签名。OAuth 2 的加密现在由 TLS 处理，这是强制性的。

**OAuth 2** *RFC-6749*, *OAuth 2.0 授权框架*([`tools.ietf.org/html/rfc6749`](https://tools.ietf.org/html/rfc6749)):

*OAuth 2.0 授权框架允许第三方应用程序获取对 HTTP 服务的有限访问， either on behalf of a resource owner by orchestrating an approval interaction between the resource owner and the HTTP service, or by allowing the third-party application to obtain access on its own behalf*.

本规范取代并使*RFC 5849, The OAuth 1.0 Protocol*([`tools.ietf.org/html/rfc5849)描述的 OAuth 1.0 协议过时.*`](https://tools.ietf.org/html/rfc5849)

为了正确理解如何使用 OAuth 2，我们需要确定某些角色以及这些角色之间的协作。让我们定义参与 OAuth 2 授权过程的每个角色：

+   **资源所有者：**资源所有者是能够授权位于资源服务器上的受保护资源的实体。

+   **授权服务器：**授权服务器在成功验证资源所有者并获取授权后，向客户端发放访问令牌的一个集中的安全网关。

+   **资源服务器：**资源服务器是托管受保护资源的服务器，并能够使用 OAuth 2 访问令牌来解析和响应受保护资源请求。

+   **微服务客户端：**客户端是代表资源所有者请求受保护资源的应用程序，但需要他们的授权。

# 访问令牌

一个 OAuth 2 访问令牌，在代码示例中通常被称为`access_token`，代表一个客户端可以用来访问 API 的凭据。

# 访问令牌

访问令牌通常具有限定的生命周期，当在每次请求的 HTTP 请求头中包含此令牌时，它被用来允许客户端访问受保护的资源。

# 刷新令牌

刷新令牌具有更长的生命周期，当访问令牌过期时用来获取新的访问令牌，而无需再次向服务器发送凭据。

# 授权类型

授权类型是客户端用来获取代表授权的`access_token`的方法。根据应用程序的不同需求，有不同的授权类型允许不同类型的访问。每种授权类型都可以支持不同的 OAuth 2 流程，而无需担心实现的技术方面。

# 授权码

授权码授权类型，定义在*RFC 6749*的第*4.1*节([`tools.ietf.org/html/rfc6749`](https://tools.ietf.org/html/rfc6749))中，是一种基于重定向的流程，浏览器从授权服务器接收一个授权码，并将其发送给客户端。客户端随后与授权服务器交互，用这个授权码交换`access_token`，可选的还有`id_token`和`refresh_token`。客户端现在可以使用这个`access_token`代表用户调用受保护的资源。

# 隐式

隐式授权类型，定义在*RFC 6749*的第*4.1*节([`tools.ietf.org/html/rfc6749`](https://tools.ietf.org/html/rfc6749))中，与授权码授权类型相似，但客户端应用程序直接接收`access_token`，而无需`authorization_code`。这是因为通常在浏览器内运行、比在服务器上运行的客户端应用程序信任度较低的客户端应用程序，不能信任其拥有`client_secret`（授权码授权类型中需要）。隐式授权类型由于信任限制，不会将刷新令牌发送给应用程序。

# 密码凭证

资源所有者密码授权类型，定义在*RFC 6749*的第*4.3*节([`tools.ietf.org/html/rfc6749`](https://tools.ietf.org/html/rfc6749))中，可以直接作为授权许可来获取`access_token`，可选的还有`refresh_token`。这种许可在用户与客户端之间有高度信任，且其他授权许可流程不可用时使用。这种许可类型通过用长期有效的`access_token`或`refresh_token`交换凭据，消除了客户端存储用户凭据的需要。

# 客户端证书

客户端证书授权，定义在*RFC 6749*的第*4.4*节([`tools.ietf.org/html/rfc6749#section-4.4`](https://tools.ietf.org/html/rfc6749#section-4.4))中，适用于非交互式客户端（CLI）、守护进程或其他服务。客户端可以通过使用提供的凭据（客户端 ID 和客户端密钥）进行身份验证，直接向授权服务器请求`access_token`。

# JSON Web 令牌

JWT 是一个开放标准，*RFC 7519* ([`tools.ietf.org/html/rfc7519`](https://tools.ietf.org/html/rfc7519))，定义了一个紧凑且自包含的格式，用于在 JSON 对象的形式下安全地在各方之间传输信息。由于其是数字签名的，这些信息可以被验证和信任。JWT 可以使用秘密（使用**基于哈希的消息认证码**（**HMAC**）**算法**）或使用**Rivest-Shamir-Adleman**（**RSA**）加密算法的公钥/私钥对进行签名。

JWT *RFC- 7519* ([`tools.ietf.org/html/ rfc7519`](https://tools.ietf.org/html/%20rfc7519)):

*JSON Web Token (JWT)是一个紧凑、URL 安全的方式来表示要在两个方之间转移的主张。JWT 中的主张以 JSON 对象的形式作为 JSON Web 签名(*JWS*)结构的载荷或作为 JSON Web 加密(JWE)结构的明文，使主张可以被数字签名或完整性保护 Message Authentication Code (MAC)和/或加密.*

JWT 用于携带与持有令牌的客户端的身份和特征（声明）相关的信息。JWT 是一个容器，并且由服务器签名，以避免客户端篡改。此令牌在认证过程中创建，并在进行任何处理之前由授权服务器验证。资源服务器使用此令牌允许客户端将其“身份卡”呈现给资源服务器，并允许资源服务器以无状态、安全的方式验证令牌的有效性和完整性。

# 令牌结构

JWT 的结构遵循以下三部分结构，包括头部、载荷和签名：

```java
    [Base64Encoded(HEADER)] . [Base64Encoded (PAYLOAD)] . [encoded(SIGNATURE)]
```

# 编码 JWT

以下代码片段是基于客户端请求返回的完整编码`access_token`：

```java
     eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MDk2MTA2ODks
    InVzZXJfbmFtZSI6InVzZXIxQGV4YW1wbGUuY29tIiwiYXV0aG9yaXRpZXMiOlsi
    Uk9MRV9VU0VSIl0sImp0aSI6Ijc1NTRhZGM4LTBhMjItNDBhYS05YjQ5LTU4MTU2N
    DBhNDUzNyIsImNsaWVudF9pZCI6Im9hdXRoQ2xpZW50MSIsInNjb3BlIjpb
    Im9wZW5pZCJdfQ.iM5BqXj70ET1e5uc5UKgws1QGDv6NNZ4iVEHimsp1Pnx6WXuFwtpHQoerH_F-    
    pTkbldmYWOwLC8NBDHElLeDi1VPFCt7xuf5Wb1VHe-uwslupz3maHsgdQNGcjQwIy7_U-  
    SQr0wmjcc5Mc_1BWOq3-pJ65bFV1v2mjIo3R1TAKgIZ091WG0e8DiZ5AQase
    Yy43ofUWrJEXok7kUWDpnSezV96PDiG56kpyjF3x1VRKPOrm8CZuylC57wclk-    
    BjSdEenN_905sC0UpMNtuk9ENkVMOpa9_Redw356qLrRTYgKA-qpRFUpC-3g5
    CXhCDwDQM3jyPvYXg4ZW3cibG-yRw
```

# 头部

我们的`access_token` JWT 的编码头部是**base64**编码的，如下面的代码所示：

```java
    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9
```

通过解码编码头部，我们得到以下载荷：

```java
    {
      "alg": "RS256",
       "typ": "JWT"
    }
```

# 载荷

我们的`access_token` JWT 的编码载荷是 base64 编码的，如下所示：

```java
    eyJleHAiOjE1MDk2MTA2ODksInVzZXJfbmFtZSI6InVzZXIxQGV4YW1wbGUuY29
    tIiwiYXV0aG9yaXRpZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6Ijc1NTR
    hZGM4LTBhMjItNDBhYS05YjQ5LTU4MTU2NDBhNDUzNyIsImNsaWVudF9pZCI6I
    m9hdXRoQ2xpZW50MSIsInNjb3BlIjpbIm9wZW5pZCJdfQ
```

通过解码编码载荷，我们得到以下载荷声明：

```java
    {
      "exp": 1509610689,  
      "jti": "7554adc8-0a22-40aa-9b49-5815640a4537",
      "client_id": "oauthClient1",
      "authorities": [
         "ROLE_USER"
        ],
         "scope": [
        "openid"
       ],
      "user_name": "user1@example.com"
    }
```

# 签名

授权服务器使用私钥对我们的`access_token`进行了编码，如下面的代码所示：

```java
    iM5BqXj70ET1e5uc5UKgws1QGDv6NNZ4iVEHimsp1Pnx6WXuFwtpHQoerH_F-          
    pTkbldmYWOwLC8NBDHElLeDi1VPFCt7xuf5Wb1VHe-uwslupz3maHsgdQNGcjQwIy7_U-   
    SQr0wmjcc5Mc_1BWOq3-pJ65bFV1v2mjIo3R1TAKgIZ091WG0e8DiZ5AQaseYy43ofUWrJEXok7kUWDpn
    SezV96PDiG56kpyjF3x1VRKPOrm8CZuylC57wclk-    
    BjSdEenN_905sC0UpMNtuk9ENkVMOpa9_Redw356qLrRTYgKA-qpRFUp
    C-3g5CXhCDwDQM3jyPvYXg4ZW3cibG-yRw
```

以下是创建 JWT 签名的伪代码：

```java
    var encodedString = base64UrlEncode(header) + ".";
    encodedString += base64UrlEncode(payload);
    var privateKey = "[-----PRIVATE KEY-----]";
    var signature = SHA256withRSA(encodedString, privateKey);
    var JWT = encodedString + "." + base64UrlEncode(signature);
```

# Spring Security 中的 OAuth 2 支持

Spring Security OAuth 项目提供了使用 Spring Security 进行 OAuth 2 授权的支持，使用标准的 Spring 框架和 Spring Security 编程模型以及配置习惯。

# 资源所有者

资源所有者可以是一个或多个来源，在 JBCP 日历的上下文中，它将拥有日历应用程序作为资源所有者。JBCP 日历除了配置资源服务器外，不需要有任何特定的配置来表示其所有权。

# 资源服务器

`@EnableResourceServer`注解表示容器应用程序的意图，启用一个 Spring Security 过滤器，该过滤器通过传入的 OAuth2 令牌来验证请求：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    OAuth2ResourceServerConfig.java

    @EnableResourceServer
    public class OAuth2ResourceServerConfig
    extends ResourceServerConfigurerAdapter {...}
```

`@EnableResourceServer`注解表示容器应用程序的意图，启用一个`OAuth2AuthenticationProcessingFilter`过滤器，该过滤器通过传入的 OAuth 2 令牌来验证请求。`OAuth2AuthenticationProcessingFilter`过滤器需要使用`@EnableWebSecurity`注解在应用程序中的某个位置启用 web 安全。`@EnableResourceServer`注解注册了一个硬编码`@Order`为`3`的自定义`WebSecurityConfigurerAdapter`类。由于 Spring Framework 的技术限制，目前无法更改这个`WebSecurityConfigurerAdapter`类的顺序。为了解决这个限制，建议不要使用其他顺序为`3`的安全适配器，否则 Spring Security 会在你设置相同顺序的一个时提出抗议：

```java
//o.s.s.OAuth 2.config.annotation.web.configuration.ResourceServerConfiguration.class

    @Configuration
    public class ResourceServerConfiguration
       extends WebSecurityConfigurerAdapter implements Ordered {
 private int order = 3;           ...
        }
```

# 授权服务器

为了启用授权服务器功能，我们在配置中包含了`@EnableAuthorizationServer`注解。添加此注解将在上下文中放入`o.s.s.OAuth 2.provider.endpoint.AuthorizationEndpoint`接口和`o.s.s.OAuth 2.provider.endpoint.TokenEndpoint`接口。开发者需要负责使用`@EnableWebSecurity`配置保护`AuthorizationEndpoint`（`/oauth/authorize`）。`TokenEndpoint`（`/oauth/token`）将基于 OAuth 2 客户端凭据自动使用 HTTP 基本身份验证进行保护：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    OAuth2AuthorizationServerConfig.java

    @Configuration
    @EnableAuthorizationServer
    public class OAuth 2AuthorizationServerConfig {...}
```

# RSA JWT 访问令牌转换器密钥对

为了创建一个安全的 JWT 编码签名，我们将创建一个自定义 RSA `keystore`，我们将其用于创建自定义`o.s.s.OAuth 2.provider.token.storeJwtAccessTokenConverter`接口：

```java
$ keytool -genkey -alias jbcpOAuth 2client -keyalg RSA \
-storetype PKCS12 -keystore jwtConverterStore.p12 \
-storepass changeit \
-dname "CN=jwtAdmin1@example.com,OU=JBCP Calendar,O=JBCP,L=Park City,S=Utah,C=US"
```

这将创建一个名为`jwtConverterStore.p12`的`PKCS12`证书，需要将其复制到`./src/main/resources/key`目录中。

# OAuth 2 资源配置属性

我们希望通过提供`keyPair`属性来外部化配置我们的 JWT 资源，包括`keystore`、`alias`和`storePassword`，正如你在我们的`application.yml`文件中看到的，位于`src/main/resources/application.yml`：

```java
    # OAuth 2 Configuration:
    security:
    OAuth 2:
       # Resource Config:
       resource:
         jwt:
 keyPair: keystore: keys/jwtConverterStore.p12 alias: jbcpOAuth 2client storePassword: changeit
```

# OAuth 2 客户端配置属性

我们需要为客户端认证、授权和 OAuth 2 范围配置客户端详细信息，正如你在`application.yml`文件中所看到的，位于`src/main/resources/application.yml`：

```java
# OAuth 2 Configuration:
security:
OAuth 2:
   # Client Config:
   client:
     # Basic Authentication credentials for OAuth 2
 clientId: oauthClient1 clientSecret: oauthClient1Password authorizedGrantTypes: password,refresh_token scope: openid
```

# JWT 访问令牌转换器

创建 JWT 令牌的最后一步是创建一个自定义`JwtAccessTokenConverter`，它将使用生成的 RSA 证书为我们的 JWT 签名。为此，我们需要拉取我们的 keyPair 配置，并配置一个自定义`JwtAccessTokenConverter`，正如在 OAuth2AuthorizationServerConfig.java 文件中所看到的：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/
    OAuth2AuthorizationServerConfig.java

    public class OAuth2AuthorizationServerConfig {
       @Value("${security.OAuth 2.resource.jwt.keyPair.keystore}")
       private String keystore;
       @Value("${security.OAuth 2.resource.jwt.keyPair.alias}")
       private String keyPairAlias;
     @Value("${security.OAuth 2.resource.jwt.keyPair.storePassword}")
       private String keyStorePass;
       @Bean
       public JwtAccessTokenConverter jwtAccessTokenConverter() {
           JwtAccessTokenConverter converter = new
           JwtAccessTokenConverter();
           KeyPair keyPair = new KeyStoreKeyFactory
           (new ClassPathResource(keystore),
           keyStorePass.toCharArray() ).getKeyPair(keyPairAlias);
           converter.setKeyPair(keyPair);
           return converter;
       }
    }
```

# 用户详情服务对象

我们将使用`CalendarUser`凭据为客户端分配一个授权的`GrantedAuthority`。为了做到这一点，我们必须要么配置我们的`CalendarUserDetailsService`类，要么通过在下面的`CalendarUserDetailsService.java`文件中指定名称`userDetailsService`来实现，正如你所看到的：

```java
    //src/main/java/com/packtpub/springsecurity/core/userdetails/
    CalendarUserDetailsService.java
 @Component("userDetailsService")    public class CalendarUserDetailsService
    implements UserDetailsService {...}
```

为我们的`@Component`注解定义自定义名称的另一个替代方案是定义一个`@Bean`声明，我们可以通过在`SecurityConfig.java`文件中使用以下条目来实现：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/SecurityConfig.java

    @Bean
    public CalendarUserDetailsService userDetailsService
    (CalendarUserDao calendarUserDao) {
       return new CalendarUserDetailsService(calendarUserDao);
    }
```

# 运行 OAuth 2 服务器应用程序

此时，我们可以启动应用程序，并准备好发送 OAuth 2 请求。

此时，你的代码应该看起来像这样：`chapter16.01-calendar`。

# 服务器请求

我们可以使用命令行工具，如`cURL`或`HTTPie`，来测试应用程序，或者你也可以使用像 Postman 这样的 REST 客户端插件来向服务器发送请求。

`HTTPie`: 一个像 cURL 的面向人类的 CLI 工具，`HTTPie`（发音为 aitch-tee-tee-pie）是一个命令行 HTTP 客户端。它的目标是使与 Web 服务的 CLI 交互尽可能地人性化。它提供了一个简单的 HTTP 命令，使用简单自然的语法发送任意的 HTTP 请求，并显示彩色输出。`HTTPie`可用于测试、调试和与 HTTP 服务器进行交互（[`httpie.org`](https://httpie.org/)）。

# 令牌请求

当我们初次请求令牌时，我们应该得到一个类似于以下的成功响应：

```java
    $ http -a oauthClient1:oauthClient1Password -f POST
    localhost:8080/oauth/token     
    grant_type=password username=user1@example.com password=user1 
    HTTP/1.1 200
    Cache-Control: no-cache, no-store, max-age=0, must-revalidate
    Cache-Control: no-store
    Content-Type: application/json;charset=UTF-8
    Date: Thu, 09 Nov 2017 20:29:26 GMT
    Expires: 0
    Pragma: no-cache
    Pragma: no-cache
    Transfer-Encoding: chunked
    X-Application-Context: application:default
    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    X-XSS-Protection: 1; mode=block 
    {
 "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MT
    AzMDI1NjYsInVzZXJfbmFtZSI6InVzZXIxQGV4YW1wbGUuY29tIiwiYXV0aG9yaXRpZ
    XMiOlsiUk9MRV9VU0VSIl0sImp0aSI6ImYzNzYzMWI4LWI0OGEtNG
    Y1MC1iNGQyLTVlNDk1NTRmYzZjZSIsImNsaWVudF9pZCI6Im9hdXRoQ
    2xpZW50MSIsInNjb3BlIjpbIm9wZW5pZCJdfQ.d5I2ZFX9ia_43eeD5X3JO6i_uF1Zw-    
    SaZ1CWbphQlYI3oCq6Xr9Yna5fvvosOZoWjb8pyo03EPVCig3mobhO6AF
    18802XOlBRx3qb0FGmHZzDoPw3naTDHlhE97ctlIFIcuJVqi34T60cvii
    uXmcE1tJ-H6-7AB04-wZl_WaucoO8-K39GvPyVabWBfSpfv0nbhh_XMNiB
    PnN8u5mqSKI9xGjYhjxXspRyy--    
    zXx50Nqj1aYzxexy8Scawrtt2F87o1IesOodoPEQGTgVVieIilplwkMLhMvJfxhyMOt
    ohR63XOGBSI4dDz58z3zOlk9P3k2Uq5FmkqwNNkduKceSw","expires_in": 43199,
    "jti": "f37631b8-b48a-4f50-b4d2-5e49554fc6ce","refresh_token":    
    "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiJ1c2VyM
    UBleGFtcGxlLmNvbSIsInNjb3BlIjpbIm9wZW5pZCJdLCJhdGkiOiJmMzc2MzF
    iOC1iNDhhLTRmNTAtYjRkMi01ZTQ5NTU0ZmM2Y2UiLCJleHAiOjE1MTI4NTEzNjYs
    ImF1dGhvcml0aWVzIjpbIlJPTEVfVVNFUiJdLCJqdGkiOiJjODM2OGI4NS0xNTk5L
    TQ0NTgtODQ2Mi1iNGFhNDg1OGIzY2IiLCJjbGllbnRfaWQiOiJvYXV0aENsaWVudDEifQ.
    RZJ2GbEvcmFbZ3SVHmtFnSF_O2kv- 
    TmN56tddW2GkG0gIRr612nN5DVlfWDKorrftmmm64x8bxuV2CcFx8Rm4SSWuoYv
    j4oxMXZzANqXWLwj6Bei4z5uvuu00g6PtJvy5Twjt7GWCvEF82PBoQL-  
    bTM3RNSKmPnYPBwOGaRFTiSTdKsHCcbrg-   
    H84quRKCjXTl7Q6l8ZUxAf1eqWlOYEhRiGHtoULzdOvL1_W0OoWrQds1EN5g
    AuoTTSI3SFLnEE2MYu6cNznJFgTqmVs1hYmX1hiXUhmCq9nwYpWei-  
    bu0MaXCa9LRjDRl9E6v86vWJiBVzd9qQilwTM2KIvgiG7w", "scope": "openid",
    "token_type": "bearer"
    }
```

具体来说，我们已经获得了一个可以在后续请求中使用的访问令牌。以下是我们将用作持有者的`access_token`：

```java
 eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTAzMDI1
    NjYsInVzZXJfbmFtZSI6InVzZXIxQGV4YW1wbGUuY29tIiwiYXV0aG9yaXRpZXM
    iOlsiUk9MRV9VU0VSIl0sImp0aSI6ImYzNzYzMWI4LWI0OGEtNGY1MC1iNGQyL
    TVlNDk1NTRmYzZjZSIsImNsaWVudF9pZCI6Im9hdXRoQ2xpZW50MSIsInNjb
    3BlIjpbIm9wZW5pZCJdfQ.d5I2ZFX9ia_43eeD5X3JO6i_uF1Zw-   
    SaZ1CWbphQlYI3oCq6Xr9Yna5fvvosOZoWjb8pyo03EPVCig3mobhO6AF18802XO
    lBRx3qb0FGmHZzDoPw3naTDHlhE97ctlIFIcuJVqi34T60cviiuXmcE1tJ-H6-7AB04-wZl_WaucoO8-   
    K39GvPyVabWBfSpfv0nbhh_XMNiBPnN8u5mqSKI9xGjYhjxXspRyy--   
    zXx50Nqj1aYzxexy8Scawrtt2F87o1IesOodoPEQGTgVVieIilplwkMLhMvJfxhyMOto
    hR63XOGBSI4dDz58z3zOlk9P3k2Uq5FmkqwNNkduKceSw
```

现在我们将使用`access_token`，并使用该令牌以以下格式初始化对服务器的额外请求：

```java
$ http localhost:8080/ "Authorization: Bearer [access_token]"
```

当我们添加第一次请求中收到的`access_token`时，我们应该得到以下请求：

```java
 $ http localhost:8080/ 'Authorization: Bearer    
    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTAzMD
    I1NjYsInVzZXJfbmFtZSI6InVzZXIxQGV4YW1wbGUuY29tIiwiYXV0aG9yaXRp
    ZXMiOlsiUk9MRV9VU0VSIl0sImp0aSI6ImYzNzYzMWI4LWI0OGEtNGY1MC1iNGQyLT
    VlNDk1NTRmYzZjZSIsImNsaWVudF9pZCI6Im9hdXRoQ2xpZW50MSIsInNjb3BlIjpb
    Im9wZW5pZCJdfQ.d5I2ZFX9ia_43eeD5X3JO6i_uF1Zw-    
    SaZ1CWbphQlYI3oCq6Xr9Yna5fvvosOZoWjb8pyo03EPVCig3mobhO6AF18802XOl
    BRx3qb0FGmHZzDoPw3naTDHlhE97ctlIFIcuJVqi34T60cviiuXmcE1tJ-H6-7AB04-wZl_WaucoO8-   
    K39GvPyVabWBfSpfv0nbhh_XMNiBPnN8u5mqSKI9xGjYhjxXspRyy--   
    zXx50Nqj1aYzxexy8Scawrtt2F87o1IesOodoPEQGTgVVieIilplwkMLhMvJf  
    xhyMOtohR63XOGBSI4dDz58z3zOlk9P3k2Uq5FmkqwNNkduKceSw'    HTTP/1.1 200
    Cache-Control: no-cache, no-store, max-age=0, must-revalidate
    Content-Length: 55
    Content-Type: text/plain;charset=UTF-8
    Date: Thu, 09 Nov 2017 20:44:00 GMT
    Expires: 0
    Pragma: no-cache
    X-Application-Context: application:default
    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    X-XSS-Protection: 1; mode=block
    {'message': 'welcome to the JBCP Calendar Application'}
```

我们可以继续使用相同的`access_token`进行后续请求，例如获取当前用户的日历事件：

```java
    $ http localhost:8080/events/my 'Authorization: Bearer    
    eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1MTAzMDI1NjYsI
    nVzZXJfbmFtZSI6InVzZXIxQGV4YW1wbGUuY29tIiwiYXV0aG9yaXRpZXMiOlsiU
    k9MRV9VU0VSIl0sImp0aSI6ImYzNzYzMWI4LWI0OGEtNGY1MC1iNGQyLTVlNDk1NT
    RmYzZjZSIsImNsaWVudF9pZCI6Im9hdXRoQ2xpZW50MSIsInNjb3BlIjpbIm9wZW5pZ
    CJdfQ.d5I2ZFX9ia_43eeD5X3JO6i_uF1Zw-    
    SaZ1CWbphQlYI3oCq6Xr9Yna5fvvosOZoWjb8pyo03EPVCig3mobhO6AF18802XO
    lBRx3qb0FGmHZzDoPw3naTDHlhE97ctlIFIcuJVqi34T60cviiuXmcE1tJ-H6-7AB04-wZl_WaucoO8-   
    K39GvPyVabWBfSpfv0nbhh_XMNiBPnN8u5mqSKI9xGjYhjxXspRyy--  
    zXx50Nqj1aYzxexy8Scawrtt2F87o1IesOodoPEQGTgVVieIilplwkMLhMvJfxhyMOtohR63
    XOGBSI4dDz58z3zOlk9P3k2Uq5FmkqwNNkduKceSw'
    HTTP/1.1 200
    Cache-Control: no-cache, no-store, max-age=0, must-revalidate
    Content-Type: application/json;charset=UTF-8
    Date: Thu, 09 Nov 2017 20:57:17 GMT
    Expires: 0
    Pragma: no-cache
    Transfer-Encoding: chunked
    X-Application-Context: application:default
    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    X-XSS-Protection: 1; mode=block
 { "currentUser": [ { "description": "This is going to be a great birthday", "id": 100, "summary": "Birthday Party", 
```

```java
 "when": 1499135400000 } ] }
```

现在我们已经准备好为客户端发放`access_tokens`的 OAuth 2 服务器，我们可以创建一个微服务客户端来与我们的系统交互。

# 微服务客户端

我们通过添加`@EnableOAuth2Client`注解使我们的新客户端应用程序作为一个 OAuth 2 客户端启动。添加`@EnableOAuth2Client`注解将允许这个应用程序从一台或多台 OAuth2 授权服务器检索和使用授权码授予。使用客户端凭据授予的客户端应用程序不需要`AccessTokenRequest`或受限于范围的`RestOperations`（对于应用程序来说，状态是全局的），但它们仍然应该使用过滤器触发`OAuth2RestOperations`在需要时获取一个令牌。使用密码授予的应用程序在使用`RestOperations`方法之前需要设置`OAuth2ProtectedResourceDetails`中的认证属性，我们稍后会进行配置。让我们来看看以下步骤，看看是如何完成的：

1.  我们需要设置一些将在以下`JavaConfig.java`文件中用于配置客户端的属性：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/JavaConfig.java

    @Configuration
 @EnableOAuth 2Client    public class JavaConfig {
       @Value("${oauth.token.uri}")
       private String tokenUri;
       @Value("${oauth.resource.id}")
       private String resourceId;
       @Value("${oauth.resource.client.id}")
       private String resourceClientId;
       @Value("${oauth.resource.client.secret}")
       private String resourceClientSecret;
      @Value("${oauth.resource.user.id}")
      private String resourceUserId;
      @Value("${oauth.resource.user.password}")
      private String resourceUserPassword;
      @Autowired
      private DataSource dataSource;
     ...
    }
```

1.  除了我们需要执行 OAuth 2 RESTful 操作的几个标准属性外，我们还需要创建一个`dataSource`来保存将在初始请求时检索并在后续操作中使用的给定资源的`oauth_client_token`。现在让我们为管理`oauth_client_token`创建一个`ClientTokenServices`，如以下`JavaConfig.java`文件所示：

```java
    //src/main/java/com/packtpub/springsecurity/configuration/JavaConfig.java

    @Bean
   public ClientTokenServices clientTokenServices() {
     return new JdbcClientTokenServices(dataSource);
    }
```

1.  现在我们创建一个`OAuth2RestTemplate`，它将管理 OAuth2 通信。我们将从创建一个`ResourceOwnerPasswordResourceDetails`来持有资源连接详细信息开始，然后构建一个`OAuth2RestTemplate`作为客户端请求的`OAuth2RestOperations`使用：

```java
//src/main/java/com/packtpub/springsecurity/configuration/JavaConfig.java

@Bean
public OAuth2RestOperationsOAuth2RestOperations() {
   ResourceOwnerPasswordResourceDetails resource =
                     new ResourceOwnerPasswordResourceDetails();
   resource.setAccessTokenUri(tokenUri);
   resource.setId(resourceId);
   resource.setClientId(resourceClientId);
   resource.setClientSecret(resourceClientSecret);
   resource.setGrantType("password");
   resource.setScope(Arrays.asList("openid"));
   resource.setUsername(resourceUserId);
   resource.setPassword(resourceUserPassword);
   return new OAuth 2RestTemplate(resource);
}
```

# 配置 OAuth 2 客户端

自从我们启用了`@EnableOAuth2Client`注解并设置了一个`ResourceOwnerPasswordResourceDetails`对象后，我们需要配置用于连接资源服务器和认证服务器的属性：

```java
    //src/main/resources/application.yml

    oauth:
    url: ${OAUTH_URL:http://localhost:8080}
    token:
       uri: ${OAUTH_URL:http://localhost:8080}/oauth/token
    resource:
       id: microservice-test
       # Client BASIC Authentication for Authentication Server
       client:
         id: ${OAUTH_CLIENT_ID:oauthClient1}
         secret: ${OAUTH_CLIENT_SECRET:oauthClient1Password}
       # Resource Password Credentials
       user:
         id: ${OAUTH_USER_ID:user1@example.com}
         password: ${OAUTH_USER_PASSWORD:user1}
```

现在我们已经有了这些组件，可以开始使用`OAuth2RestOperations`对象发送请求。我们将首先创建一个`RestController`来拉取远程详细信息，并将其作为 RESTful 请求的结果显示，正如我们在`OAuth2EnabledEventsController.java`文件中所展示的那样：

```java
    //src/main/java/com/packtpub/springsecurity/web/controllers/
    OAuth2EnabledEventsController.java

    @RestController
    public class OAuth2EnabledEventsController {
       @Autowired
       private OAuth2RestOperations template;
       @Value("${base.url:http://localhost:8888}")
       private String baseUrl;
       @Value("${oauth.url:http://localhost:8080}")
       private String baseOauthUrl;
       @GetMapping("/events/my")
      public String eventsMy() {
          @SuppressWarnings("unchecked")
          String result = template.getForObject(baseOauthUrl+"/events/my",
          String.class);
          return result;
       }
    }
```

现在我们应为客户端应用拥有相同的代码库。

你的代码应看起来像`chapter16.01-calendar-client`。

我们需要确保`chapter16.01-calendar`应用正在运行，并准备好接收来自客户端的 OAuth 2 请求。然后我们可以启动`chapter16.01-calendar-client`应用，该应用将暴露几个 RESTful 端点，包括一个访问配置用户事件（位于远程资源上的`/events/my`）的端点，并通过运行`http://localhost:8888/events/my`返回以下结果：

```java
    {
    "currentUser": [
   {
     "id": 100,
     "summary": "Birthday Party",
     "description": "This is going to be a great birthday",
     "when": 1499135400000
   }
    ]
    }
```

# 摘要

在本章中，你学习了单体应用和微服务之间的通用区别，并将服务导向架构（SOA）与微服务进行了比较。你还了解了 OAuth 2 的概念性架构以及它是如何为你的服务提供可信的客户端访问的，并学习了 OAuth 2 访问令牌的类型以及 OAuth 2 授权类型的类型。

我们检查了 JWT 以及它们的通用结构，实现了一个资源服务器和认证服务器，用于向客户端授予访问 OAuth 2 资源的权限，并实现了一个 RESTful 客户端，通过 OAuth 2 授权流程来获取资源。
