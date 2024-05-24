# 使用 Spring5 构建 REST Web 服务（二）

> 原文：[`zh.annas-archive.org/md5/5A57DB9C3C86080E5A1093BAC90B467A`](https://zh.annas-archive.org/md5/5A57DB9C3C86080E5A1093BAC90B467A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：Spring Security 和 JWT（JSON Web Token）

在本章中，我们将简单了解 Spring Security，并且我们还将讨论**JSON Web Token**（**JWT**）以及如何在我们的 web 服务调用中使用 JWT。这也将包括 JWT 的创建。

在本章中，我们将涵盖以下内容：

+   Spring Security

+   JSON Web Token（JWT）

+   如何在 web 服务中生成 JWT

+   如何在 web 服务中访问和检索 JWT 中的信息

+   如何通过添加 JWT 安全来限制 web 服务调用

# Spring Security

Spring Security 是一个强大的身份验证和授权框架，将帮助我们提供一个安全的应用程序。通过使用 Spring Security，我们可以确保所有的 REST API 都是安全的，并且只能通过经过身份验证和授权的调用访问。

# 身份验证和授权

让我们举个例子来解释一下。假设你有一个有很多书的图书馆。身份验证将提供一个进入图书馆的钥匙；然而，授权将给予你取书的权限。没有钥匙，你甚至无法进入图书馆。即使你有图书馆的钥匙，你也只能取几本书。

# JSON Web Token（JWT）

Spring Security 可以以多种形式应用，包括使用强大的库如 JWT 进行 XML 配置。由于大多数公司在其安全中使用 JWT，我们将更多地关注基于 JWT 的安全，而不是简单的 Spring Security，后者可以在 XML 中配置。

JWT 令牌在 URL 上是安全的，并且在**单点登录**（**SSO**）环境中与 Web 浏览器兼容。JWT 有三部分：

+   头部

+   有效载荷

+   签名

头部部分决定了应该使用哪种算法来生成令牌。在进行身份验证时，客户端必须保存服务器返回的 JWT。与传统的会话创建方法不同，这个过程不需要在客户端存储任何 cookie。JWT 身份验证是无状态的，因为客户端状态从未保存在服务器上。

# JWT 依赖

为了在我们的应用程序中使用 JWT，我们可能需要使用 Maven 依赖。以下依赖应该添加到`pom.xml`文件中。您可以从以下链接获取 Maven 依赖：[`mvnrepository.com/artifact/javax.xml.bind`](https://mvnrepository.com/artifact/javax.xml.bind)。

我们在应用程序中使用了 Maven 依赖的版本`2.3.0`：

```java
<dependency>
      <groupId>javax.xml.bind</groupId>
      <artifactId>jaxb-api</artifactId>
      <version>2.3.0</version>
</dependency>
```

由于 Java 9 在其捆绑包中不包括`DataTypeConverter`，我们需要添加上述配置来使用`DataTypeConverter`。我们将在下一节中介绍`DataTypeConverter`。

# 创建 JWT 令牌

为了创建一个令牌，我们在`SecurityService`接口中添加了一个名为`createToken`的抽象方法。该接口将告诉实现类必须为`createToken`创建一个完整的方法。在`createToken`方法中，我们将只使用主题和到期时间，因为在创建令牌时这两个选项很重要。

首先，我们将在`SecurityService`接口中创建一个抽象方法。具体类（实现`SecurityService`接口的类）必须在其类中实现该方法：

```java
public interface SecurityService {
  String createToken(String subject, long ttlMillis);    
 // other methods  
}
```

在上述代码中，我们在接口中定义了令牌创建的方法。

`SecurityServiceImpl`是一个具体的类，它通过应用业务逻辑来实现`SecurityService`接口的抽象方法。以下代码将解释如何使用主题和到期时间来创建 JWT：

```java
private static final String secretKey= "4C8kum4LxyKWYLM78sKdXrzbBjDCFyfX";
@Override
public String createToken(String subject, long ttlMillis) {    
    if (ttlMillis <= 0) {
      throw new RuntimeException("Expiry time must be greater than Zero :["+ttlMillis+"] ");
    }    
    // The JWT signature algorithm we will be using to sign the token
    SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;   
    byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(secretKey);
    Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
    JwtBuilder builder = Jwts.builder()
        .setSubject(subject) 
        .signWith(signatureAlgorithm, signingKey);
    long nowMillis = System.currentTimeMillis();    
    builder.setExpiration(new Date(nowMillis + ttlMillis)); 
    return builder.compact();
}
```

上述代码为主题创建了令牌。在这里，我们已经硬编码了秘钥`"4C8kum4LxyKWYLM78sKdXrzbBjDCFyfX"`，以简化令牌创建过程。如果需要，我们可以将秘钥保存在属性文件中，以避免在 Java 代码中硬编码。

首先，我们验证时间是否大于零。如果不是，我们立即抛出异常。我们使用 SHA-256 算法，因为它在大多数应用程序中都被使用。

**安全哈希算法**（**SHA**）是一种密码哈希函数。密码哈希是数据文件的文本形式。SHA-256 算法生成一个几乎唯一的、固定大小的 256 位哈希。SHA-256 是更可靠的哈希函数之一。

我们已在此类中将密钥硬编码。我们也可以将密钥存储在`application.properties`文件中。但是为了简化流程，我们已经将其硬编码：

```java
private static final String secretKey= "4C8kum4LxyKWYLM78sKdXrzbBjDCFyfX";
```

我们将字符串密钥转换为字节数组，然后将其传递给 Java 类`SecretKeySpec`，以获取`signingKey`。此密钥将用于令牌生成器。此外，在创建签名密钥时，我们使用 JCA，这是我们签名算法的名称。

**Java 密码体系结构**（**JCA**）是 Java 引入的，以支持现代密码技术。

我们使用`JwtBuilder`类来创建令牌，并为其设置到期时间。以下代码定义了令牌创建和到期时间设置选项：

```java
JwtBuilder builder = Jwts.builder()
        .setSubject(subject) 
        .signWith(signatureAlgorithm, signingKey);
long nowMillis = System.currentTimeMillis(); 
builder.setExpiration(new Date(nowMillis + ttlMillis)); 
```

在调用此方法时，我们必须传递毫秒时间，因为`setExpiration`只接受毫秒。

最后，我们必须在我们的`HomeController`中调用`createToken`方法。在调用该方法之前，我们将不得不像下面这样自动装配`SecurityService`：

```java
@Autowired
SecurityService securityService;
```

`createToken`调用编码如下。我们将主题作为参数。为了简化流程，我们已将到期时间硬编码为`2 * 1000 * 60`（两分钟）。

`HomeController.java`：

```java
@Autowired
SecurityService securityService;
@ResponseBody
  @RequestMapping("/security/generate/token")
  public Map<String, Object> generateToken(@RequestParam(value="subject") String subject){    
    String token = securityService.createToken(subject, (2 * 1000 * 60));    
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", token);    
    return map;
  }
```

# 生成令牌

我们可以通过在浏览器或任何 REST 客户端中调用 API 来测试令牌。通过调用此 API，我们可以创建一个令牌。此令牌将用于用户身份验证等目的。

创建令牌的示例 API 如下：

```java
http://localhost:8080/security/generate/token?subject=one
```

在这里，我们使用`one`作为主题。我们可以在以下结果中看到令牌。这就是我们为传递给 API 的所有主题生成令牌的方式：

```java
{
  result: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvbmUiLCJleHAiOjE1MDk5MzY2ODF9.GknKcywiI-G4-R2bRmBOsjomujP0MxZqdawrB8TO3P4"
}
```

JWT 是一个由三部分组成的字符串，每部分用一个点（.）分隔。每个部分都经过 base-64 编码。第一部分是头部，它提供了关于用于签署 JWT 的算法的线索。第二部分是主体，最后一部分是签名。

# 从 JWT 令牌中获取主题

到目前为止，我们已经创建了一个 JWT 令牌。在这里，我们将解码令牌并从中获取主题。在后面的部分中，我们将讨论如何解码并从令牌中获取主题。

像往常一样，我们必须定义获取主题的方法。我们将在`SecurityService`中定义`getSubject`方法。

在这里，我们将在`SecurityService`接口中创建一个名为`getSubject`的抽象方法。稍后，我们将在我们的具体类中实现这个方法：

```java
String getSubject(String token);
```

在我们的具体类中，我们将实现`getSubject`方法，并在`SecurityServiceImpl`类中添加我们的代码。我们可以使用以下代码从令牌中获取主题：

```java
  @Override
  public String getSubject(String token) {     
    Claims claims = Jwts.parser()              .setSigningKey(DatatypeConverter.parseBase64Binary(secretKey))
             .parseClaimsJws(token).getBody();    
    return claims.getSubject();
  } 
```

在前面的方法中，我们使用`Jwts.parser`来获取`claims`。我们通过将密钥转换为二进制并将其传递给解析器来设置签名密钥。一旦我们得到了`Claims`，我们可以通过调用`getSubject`来简单地获取主题。

最后，我们可以在我们的控制器中调用该方法，并传递生成的令牌以获取主题。您可以检查以下代码，其中控制器调用`getSubject`方法，并在`HomeController.java`文件中返回主题：

```java
  @ResponseBody
  @RequestMapping("/security/get/subject")
  public Map<String, Object> getSubject(@RequestParam(value="token") String token){    
    String subject = securityService.getSubject(token);    
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", subject);    
    return map;
  }
```

# 从令牌中获取主题

以前，我们创建了获取令牌的代码。在这里，我们将通过调用获取主题 API 来测试我们之前创建的方法。通过调用 REST API，我们将得到之前传递的主题。

示例 API：

```java
http://localhost:8080/security/get/subject?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJvbmUiLCJleHAiOjE1MDk5MzY2ODF9.GknKcywiI-G4-R2bRmBOsjomujP0MxZqdawrB8TO3P4
```

由于我们在调用`generateToken`方法创建令牌时使用了`one`作为主题，所以我们将在`getSubject`方法中得到`"one"`：

```java
{
  result: "one"
}
```

通常，我们将令牌附加在标头中；然而，为了避免复杂性，我们已经提供了结果。此外，我们已将令牌作为参数传递给`getSubject`。在实际应用中，您可能不需要以相同的方式进行操作。这只是为了演示目的。

# 摘要

在本章中，我们已经讨论了 Spring Security 和基于 JWT 令牌的安全性，以获取和解码令牌。在未来的章节中，我们将讨论如何在 AOP 中使用令牌，并通过使用 JWT 令牌来限制 API 调用。


# 第七章：测试 RESTful Web 服务

在之前的章节中，我们已经讨论了如何创建 REST API 并在我们的 REST API 和服务方法中应用业务逻辑。然而，为了确保我们的业务逻辑，我们可能需要编写适当的测试用例并使用其他测试方法。测试我们的 REST API 将帮助我们在部署到生产环境时保持应用程序的清洁和功能。我们编写单元测试用例或其他测试方法越多，对于将来维护我们的应用程序来说就越好。

在本章中，我们将讨论以下用于我们示例 RESTful web 服务的测试策略：

+   在 Spring 控制器上进行 JUnit 测试

+   MockMvc（对控制器进行模拟）

+   Postman REST 客户端

+   SoapUI REST 客户端

+   jsoup 读取器作为客户端

# JUnit

JUnit 是 Java 和 Spring 应用程序最简单和最受欢迎的测试框架。通过为我们的应用程序编写 JUnit 测试用例，我们可以提高应用程序的质量，避免出现错误的情况。

在这里，我们将讨论一个简单的 JUnit 测试用例，它调用`userService`中的`getAllUsers`方法。我们可以检查以下代码：

```java
@RunWith(SpringRunner.class)
@SpringBootTest
public class UserTests {  
  @Autowired
  UserService userSevice;
  @Test
  public void testAllUsers(){
    List<User> users = userSevice.getAllUsers(); 
    assertEquals(3, users.size());
  }
}
```

在前面的代码中，我们调用了`getAllUsers`并验证了总数。让我们在另一个测试用例中测试单用户方法：

```java
// other methods
@Test
public void testSingleUser(){
    User user = userSevice.getUser(100); 
    assertTrue(user.getUsername().contains("David"));
}
```

在前面的代码片段中，我们只是测试了我们的服务层并验证了业务逻辑。然而，我们可以通过使用模拟方法直接测试控制器，这将在本章后面讨论。

# MockMvc

MockMvc 主要用于通过控制器测试代码。通过直接调用控制器（REST 端点），我们可以在 MockMvc 测试中覆盖整个应用程序。此外，如果我们在控制器上保留任何身份验证或限制，它也将在 MockMvc 测试用例中得到覆盖。

以下代码将使用 MockMvc 标准测试我们的基本 API（`localhost:8080/`）：

```java
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
public class UserMockMVCTests {  
  @Autowired
  private WebApplicationContext ctx;  
  private MockMvc mockMvc;  
  @Before
  public void setUp() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.ctx).build();
  }  
  @Test
  public void testBasicMVC() throws Exception {
    MvcResult result = mockMvc
        .perform(MockMvcRequestBuilders.get("/"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("result", is("Aloha")))         
        .andReturn();    
    String content = result.getResponse().getContentAsString();
     System.out.println("{testBasicMVC} response : " + content);
  }
}
```

在前面的代码中，我们只是在`setUp()`方法中初始化了 Web 应用程序。此外，我们使用`@Autowired`注解绑定了`WebApplicationContext`。设置准备好后，我们创建一个名为`testBasicMVC`的方法来测试我们的普通 API（`localhost:8080`），它将返回`"result: Aloha"`。

当我们完成代码后，如果在 Eclipse 上选择 Run As | JUnit test 来运行它，前面的方法将被执行并显示结果。我们可以在 Eclipse 的 JUnit 窗口中查看成功的测试用例结果。

# 测试单个用户

到目前为止，我们只测试了一个普通的 REST API。在这里，我们可以再进一步，通过从`userid`获取单个用户来测试我们的用户 API。以下代码将带领我们实现获取单个用户：

```java
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
@SpringBootTest
@RunWith(SpringJUnit4ClassRunner.class)
public class UserMockMVCTests {  
  @Autowired
  private WebApplicationContext ctx;  
  private MockMvc mockMvc;  
  @Before
  public void setUp() {
    this.mockMvc = MockMvcBuilders.webAppContextSetup(this.ctx).build();
  }    
  @Test
  public void testBasicMVC() throws Exception {
    MvcResult result = mockMvc
        .perform(MockMvcRequestBuilders.get("/"))        
        .andExpect(status().isOk())
        .andExpect(jsonPath("result", is("Aloha")))        
        .andReturn();    
    String content = result.getResponse().getContentAsString();
     System.out.println("{testBasicMVC} response : " + content);
  }    
  @Test
  public void testSingleUser() throws Exception {
    MvcResult result = mockMvc
        .perform(MockMvcRequestBuilders.get("/user/100")) 
        .andExpect(status().isOk())
        .andExpect(jsonPath("userid", is(100)))
        .andExpect(jsonPath("username", is("David")))
        .andReturn();    
    String content = result.getResponse().getContentAsString();
    System.out.println("{testSingleUser} response : " + content);
  }
}
```

在前面的代码（`testSingleUser`）中，我们可以看到我们期望`status`、`userid`和`username`分别为`Ok`、`100`和`David`。此外，我们打印从 REST API 获取的结果。

# Postman

在之前的章节中，我们已经使用 Postman 来测试我们的 REST API。当我们需要完全测试应用程序时，Postman 会很有帮助。在 Postman 中，我们可以编写测试套件来验证我们的 REST API 端点。

# 获取所有用户 - Postman

首先，我们将从一个简单的 API 开始，用于获取所有用户：

```java
http://localhost:8080/user
```

之前的方法将获取所有用户。获取所有用户的 Postman 截图如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/ab3e6aae-451c-4800-8730-ab0bb7372b29.png)

在前面的截图中，我们可以看到我们之前添加的所有用户。我们使用了`GET`方法来调用这个 API。

# 添加用户 - Postman

让我们尝试使用`POST`方法在`user`中添加一个新用户：

```java
http://localhost:8080/user
```

按照以下截图所示添加用户：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/ab0d5a93-c309-485a-b820-a674f80d6907.png)

在前面的结果中，我们可以看到 JSON 输出：

```java
{
     "result" : "added"
}
```

# 生成 JWT - Postman

让我们尝试通过调用 Postman 中的生成令牌 API 来生成令牌（JWT）：

```java
http://localhost:8080/security/generate/token
```

我们可以清楚地看到我们在 Body 中使用`subject`来生成令牌。一旦我们调用 API，我们将获得令牌。我们可以在下面的截图中检查令牌：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/17f854d7-d862-48a4-89b7-99bd03347c52.png)

# 从令牌中获取主题

通过使用我们之前创建的现有令牌，我们将通过调用获取主题 API 来获取主题：

```java
http://localhost:8080/security/get/subject
```

结果将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/58232047-8dee-4e98-b4f5-5fd2fbce2de8.png)

在前面的 API 调用中，我们在 API 中发送了令牌以获取主题。我们可以在生成的 JSON 中看到主题。

# SoapUI

与 Postman 一样，SoapUI 是另一个用于测试 Web 服务的开源工具。SoapUI 帮助进行 Web 服务调用、模拟、仿真、负载测试和功能测试。SoapUI 在负载测试中被广泛使用，并且具有许多控件，使负载测试变得容易。

SoapUI 在 Windows 和 Linux 等操作系统中非常容易安装。其用户界面为我们提供了很大的灵活性，可以构建复杂的测试场景。此外，SoapUI 支持第三方插件，如`TestMaker`和`Agiletestware`，并且很容易与 NetBeans 和 Eclipse 等 IDE 集成。

# 获取所有用户 - SoapUI

我们将使用 SoapUI 测试我们的基本 API(`/user`)。当我们在 SoapUI 中使用`GET`方法时，以下方法将获取所有用户：

```java
http://localhost:8080/user
```

获取所有用户的 SoapUI 截图如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/40628590-4e6b-45ae-9461-9146a3cbd89d.png)

我们将尝试使用`POST`方法添加用户：

```java
http://localhost:8080/user
```

添加用户的截图如下：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/2135de40-e5c9-4b0d-a88b-14ea7c17ab56.png)

在这个结果中，我们可以看到 JSON 输出：

```java
{"result" : "added"}
```

# 生成 JWT SoapUI

我们将使用`GET`方法生成令牌如下：

```java
http://localhost:8080/security/generate/token
```

在 SoapUI 中，我们使用`subject`作为参数。我们可以在下面的截图中看到这一点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/61345243-380c-448b-b585-f7245d9267ea.png)

我们可以清楚地看到我们在 Body 中使用`subject`来生成令牌。此外，我们可以在 SoapUI 中看到 Style 为 QUERY。这将使我们的 Value(`test`)成为 API 的参数。

一旦我们调用 API，我们将获得令牌。我们可以在前面的截图中检查令牌。

# 从令牌中获取主题 - SoapUI

现在我们可以从之前生成的令牌中获取主题。我们可能需要将令牌作为参数传递以获取主题。

当我们在 SoapUI 中使用`GET`方法调用 API 时，以下 API 将从令牌中获取主题：

```java
http://localhost:8080/security/get/subject
```

尽管我们可以在前面的 API 调用中使用`POST`方法，但我们只使用`GET`方法来简化流程，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/88105b9e-24a6-408c-b71f-a37f146b4a15.png)

在前面的 API 调用中，我们在 API 中发送了令牌以获取主题。我们可以在生成的 JSON 中看到主题。

到目前为止，我们已经通过 SoapUI 测试了我们的 API。尽管 SoapUI 似乎比 Postman 更难一些，但在企业级负载测试和安全测试时可能非常有帮助。

# jsoup

jsoup 是一个用于提取 HTML 文档并从 HTML DOM 获取详细信息的 Java 库。jsoup 使用 DOM、CSS 和类似 jQuery 的方法从任何网页中检索信息。尽管 jsoup 主要用于 HTML 文档解析，但在我们的应用程序中，我们将用它进行 API 测试。

首先，我们将在 jsoup 中调用 REST API 并将结果转换为 JSON。为了将字符串转换为 JSON，我们将使用 Gson 库。

对于 jsoup 和 Gson 库，我们可能需要在`pom.xml`中添加依赖项。以下是 jsoup 和 Gson 依赖项的代码：

```java
    <dependency>
      <groupId>org.jsoup</groupId>
      <artifactId>jsoup</artifactId>
      <version>1.8.2</version>
    </dependency> 
    <dependency>
        <groupId>com.google.code.gson</groupId>
        <artifactId>gson</artifactId>
        <version>2.8.2</version>
    </dependency>
```

我们将在测试资源中使用 jsoup REST 消费者，这样测试将更容易：

```java
String doc = Jsoup.connect("http://localhost:8080/user").ignoreContentType(true).get().body().text();
```

以下代码将以 HTML 形式调用 REST API 并将主体作为文本获取。通过这样做，我们将只获取 REST API 结果作为 JSON 文本。JSON 文本如下：

```java
[{"userid":100,"username":"David"},{"userid":101,"username":"Peter"},{"userid":102,"username":"John"}]
```

一旦我们获得 JSON 文本，我们可以使用`JsonParser`类将其转换为 JSON 数组。以下代码将解析 JSON 文本并将其转换为`JsonArray`类：

```java
JsonParser parser = new JsonParser();
JsonElement userElement = parser.parse(doc);
JsonArray userArray = userElement.getAsJsonArray();
```

一旦我们获得了 JSON 数组，我们可以简单地检查数组大小来验证我们的 REST API。以下代码将测试我们的 REST API 的大小：

```java
assertEquals(3, userArray.size());
```

以下是完整的类和前面提到的代码：

```java
import static org.junit.Assert.assertEquals;
import java.io.IOException;
import org.jsoup.Jsoup;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.packtpub.model.User;
@RunWith(SpringRunner.class)
@SpringBootTest
public class JsoupUserTest {  
  private final Logger _log = LoggerFactory.getLogger(this.getClass());  
  @Test
  public void testUsersJsoup() throws IOException{    
    String doc = Jsoup.connect("http://localhost:8080/user").ignoreContentType(true).get().body().text();    
    _log.info("{test} doc : "+doc);    
    JsonParser parser = new JsonParser();
    JsonElement userElement = parser.parse(doc);
    JsonArray userArray = userElement.getAsJsonArray();    
    _log.info("{test} size : "+userArray.size());        
    assertEquals(3, userArray.size());
  }
}
```

在前面的方法中，我们使用记录器打印大小。此外，我们使用`assertEquals`方法来检查用户数组大小。

由于这类似于 JUnit 测试，我们可能需要在 Eclipse 中使用 JUnit 测试选项进行测试。我们可以简单地右键单击文件，然后单击运行为| JUnit 测试。

# 获取用户 - jsoup

在之前的方法中，我们已经测试了 REST API 中的所有用户。现在，我们可以检查单个用户和详细信息。以下代码将测试单个用户 REST API：

```java
  @Test
  public void testUserJsoup() throws IOException{   
    String doc = Jsoup.connect("http://localhost:8080/user/100").ignoreContentType(true).get().body().text();    
    Gson g = new Gson(); 
    User user = g.fromJson(doc, User.class);        
    assertEquals("David", user.getUsername());
  }
```

前面的代码将调用 REST API，以文本格式获取 JSON，然后将其转换为`User`类。一旦我们将它们转换为`User`类，我们可以通过`assertEquals`检查用户名。

# 添加用户 - jsoup

让我们尝试使用`jsoup`中的`POST`方法添加新用户。在这个 REST API（添加用户）中，我们可能需要向 REST API 传递一些参数。以下代码将调用添加用户 API 并获取结果：

```java
@Autowired
UserService userSevice;
@Test
public void testUserAdditionJsoup() throws IOException{    
    String doc = Jsoup.connect("http://localhost:8080/user/") 
        .data("userid", "103")
        .data("username", "kevin")
        .ignoreContentType(true)
        .post().body().text();    
    Gson g = new Gson(); 
    Map<String, Object> result = g.fromJson(doc, Map.class);    
    _log.info("{test} result : "+result);        
    assertEquals("added", result.get("result"));
    // user should be deleted as we tested the case already 
    userSevice.deleteUser(103);
}
```

在前面的代码中，我们使用了`.post()`方法来调用 API。此外，我们使用了`.data()`方法来传递参数。通过添加`.ignoreContentType()`，我们告诉`Jsoup`库我们不关心 API 返回的内容类型。此外，`body().text()`将以文本形式获取主体。

通过在`assertEquals`中检查结果，我们确保 API 正常工作。

要测试 jsoup，服务器需要运行，所以我们需要先运行服务器。然后我们可以运行我们的测试用例。要运行其他测试用例，如 JUnit 和 MockMvc，我们不需要服务器。

# 运行测试用例

首先，我们运行服务器并确保可以访问服务器。如果我们不运行服务器，我们将无法测试 jsoup，因此保持服务器运行。一旦服务器启动，右键单击项目运行为| JUnit 测试。我们可以在 JUnit 窗口中看到结果，如下图所示：

！[](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/5f56729a-5618-42ec-adc1-59613d2de0cd.png)

在前面的截图中，我们可以清楚地看到我们所有的测试用例都通过了。

# 摘要

在本章中，我们讨论了 RESTful Web 服务的各种测试方法。我们已经应用了 JUnit 测试，MockMvc，Postman 和 SoapUI。这些测试方法对于测试应用程序中的业务逻辑将非常有帮助。在下一章中，我们将讨论 REST 客户端和在 REST 客户端中消耗 RESTful 服务。


# 第八章：性能

在应用程序中，性能被认为是 RESTful Web 服务的主要标准。本章将主要关注如何改善应用程序的性能并减少响应时间。尽管性能优化技术可以应用在 Web 应用程序的不同层，我们将讨论 RESTful（Web）层。其余的性能优化技术将在[第十一章]（c3ef97e3-fbad-4b9e-b7f8-91c6d3d6c6f0.xhtml）*扩展*中讨论。

本章将讨论以下主题：

+   HTTP 压缩

+   HTTP 缓存和 HTTP 缓存控制

+   在 REST API 中的缓存实现

+   使用 HTTP If-Modified-Since 标头和 ETags

# HTTP 压缩

为了从 REST 服务中快速获取内容，数据可以被压缩并通过 HTTP 等协议发送。在压缩数据时，我们必须遵循一些编码格式，因此接收方将应用相同的格式。

# 内容协商

在请求服务器的资源时，客户端将有许多选项来接收各种表示的内容。例如，DOC/PDF 是数据类型表示。土耳其语或英语是语言表示，服务器可以以特定语言发送资源。服务器和客户端之间必须就资源将以哪种格式访问达成一致，例如语言、数据类型等。这个过程称为**内容协商**。

在这里，我们将讨论两种不同的内容协商机制：服务器驱动和代理驱动机制。在继续讨论这些机制之前，我们将讨论 Accept-Encoding 和 Content-Encoding，因为它们很重要。

# 接受编码

客户端将告诉服务器它可以接收哪种压缩算法。最常见的编码类型是`gzip`和`deflate`。在请求服务器时，客户端将在请求标头中共享编码类型。接受编码将用于此类目的。简而言之，客户端会告诉服务器，“我只接受提到的压缩格式”。

我们将看到以下示例`Accept-Encoding`：

```java
Accept-Encoding: gzip, deflate
```

在前面的标头中，客户端表示它只能接受响应中的`gzip`或`deflate`。

其他可能的选项如下所述：

```java
Accept-Encoding: compress, gzip
Accept-Encoding: 
Accept-Encoding: *
Accept-Encoding: compress;q=0.5, gzip;q=1.0
Accept-Encoding: gzip;q=1.0, identity; q=0.5, *;q=0
```

我们可以看到`compress`值后面跟着`q=0.5`，这意味着质量评级只有`0.5`，与`gzip`评级的`q=1.0`相比，后者非常高。在这种情况下，客户端建议服务器可以使用`gzip`而不是`compress`。但是，如果`gzip`不可行，`compress`对于客户端来说也是可以接受的。

如果服务器不支持客户端请求的压缩算法，服务器应该发送一个带有`406（不可接受）`状态码的错误响应。

# 内容编码

Content-Encoding 是一个实体标头，用于将要从服务器发送到客户端的数据类型进行压缩。Content-Encoding 值告诉客户端在实体主体中使用了哪些编码。它将告诉客户端如何解码数据以检索值。

让我们来看看单个和多个编码选项：

```java
// Single Encoding option
Content-Encoding: gzip
Content-Encoding: compress

// Multiple Encoding options
Content-Encoding: gzip, identity
Content-Encoding: deflate, gzip
```

在前面的配置中，Content-Encoding 提供了单个和多个选项。在这里，服务器告诉客户端它可以提供基于`gzip`和`compress`算法的编码。如果服务器提到了多个编码，这些编码将按照提到的顺序应用。

尽可能压缩数据是非常推荐的。

不建议在运行时更改内容编码。因为这将破坏未来的请求（例如在`GET`上进行`PUT`），在运行时更改内容编码根本不是一个好主意。

# 服务器驱动的内容协商

服务器驱动的内容协商是由服务器端算法执行的，以决定服务器必须发送给客户端的最佳表示。这也被称为主动内容协商。在服务器驱动的协商中，客户端（用户代理）将提供具有质量评级的各种表示选项。服务器中的算法将不得不决定哪种表示对客户端提供的标准最有效。

例如，客户端通过共享媒体类型标准请求资源，带有诸如哪种媒体类型对客户端更好的评级。服务器将完成其余工作并提供最适合客户需求的资源表示。

# 代理驱动的内容协商

代理驱动的内容协商是由客户端算法执行的。当客户端请求特定资源时，服务器将告知客户端有关资源的各种表示，包括内容类型、质量等元数据。然后客户端算法将决定哪种表示最佳，并再次从服务器请求。这也被称为被动内容协商。

# HTTP 缓存

当客户端多次请求相同的资源表示时，从服务器端提供它将是浪费时间并且在 Web 应用程序中会耗时。如果资源被重复使用，而不是与服务器通信，它肯定会提高 Web 应用程序的性能。

缓存将被视为提高我们的 Web 应用性能的主要选项。Web 缓存避免了多次与服务器联系并减少了延迟；因此，应用程序将更快。缓存可以应用在应用程序的不同层面。在本章中，我们将只讨论 HTTP 缓存，这被认为是中间层。我们将在第十一章《扩展》中更深入地讨论其他形式的缓存。

# HTTP 缓存控制

缓存控制是一个指定 Web 缓存操作指令的头字段。这些指令给出了缓存授权，定义了缓存的持续时间等。这些指令定义了行为，通常旨在防止缓存响应。

在这里，我们将讨论 HTTP 缓存指令：`public`，`private`，`no-cache`和`only-if-cached`指令。

# 公共缓存

如果缓存控制允许公共缓存，则资源可以被多个用户缓存。我们可以通过在`Cache-Control`标头中设置`public`选项来实现这一点。在公共缓存中，响应可能会被多个用户缓存，即使是不可缓存或可缓存的，也仅限于非共享缓存：

```java
Cache-Control: public
```

在前面的设置中，`public`表示响应可以被任何缓存缓存。

# 私有缓存

与公共缓存不同，私有响应适用于单个用户缓存，而不适用于共享缓存。在私有缓存中，中间件无法缓存内容：

```java
Cache-Control: private
```

前面的设置表明响应仅适用于单个用户，并且不应被任何其他缓存访问。

此外，我们可以在我们的标题设置中指定内容应该缓存多长时间。这可以通过`max-age`指令选项来实现。

检查以下设置：

```java
Cache-Control: private, max-age=600
```

在前面的设置中，我们提到响应可以以私有模式（仅限单个用户）进行缓存，并且资源被视为新鲜的最长时间。

# 无缓存

对于访问动态资源可能不需要缓存。在这种情况下，我们可以在我们的缓存控制中使用`no-cache`设置来避免客户端缓存：

```java
Cache-Control: no-cache
```

前面的设置将告诉客户端在请求资源时始终检查服务器。

此外，在某些情况下，我们可能需要禁用缓存机制本身。这可以通过在我们的设置中使用`no-store`来实现：

```java
Cache-Control: no-store
```

前面的设置将告诉客户端避免资源缓存，并始终从服务器获取资源。

HTTP/1.0 缓存不会遵循 no-cache 指令，因为它是在 HTTP/1.1 中引入的。

缓存控制只在 HTTP/1.1 中引入。在 HTTP/1.0 中，只使用**Pragma: no-cache**来防止响应被缓存。

# 只有在缓存中有时效的资源时，客户端才会返回缓存的资源，而不是与服务器重新加载或重新验证。

在某些情况下，比如网络连接不佳，客户端可能希望返回缓存的资源，而不是与服务器重新加载或重新验证。为了实现这一点，客户端可以在请求中包含`only-if-cached`指令。如果收到，客户端将获得缓存的条目，否则将以`504`（网关超时）状态响应。

这些缓存控制指令可以覆盖默认的缓存算法。

到目前为止，我们已经讨论了各种缓存控制指令及其解释。以下是缓存请求和缓存响应指令的示例设置。

请求缓存控制指令（标准的`Cache-Control`指令，可以由客户端在 HTTP 请求中使用）如下：

```java
Cache-Control: max-age=<seconds>
Cache-Control: max-stale[=<seconds>]
Cache-Control: min-fresh=<seconds>
Cache-Control: no-cache 
Cache-Control: no-store
Cache-Control: no-transform
Cache-Control: only-if-cached
```

响应缓存控制指令（标准的`Cache-Control`指令，可以由服务器在 HTTP 响应中使用）如下：

```java
Cache-Control: must-revalidate
Cache-Control: no-cache
Cache-Control: no-store
Cache-Control: no-transform
Cache-Control: public
Cache-Control: private
Cache-Control: proxy-revalidate
Cache-Control: max-age=<seconds>
Cache-Control: s-maxage=<seconds>
```

不可能为特定的缓存指定缓存指令。

# 缓存验证

当缓存中有一个新条目可以作为客户端请求时的响应时，它将与原始服务器进行检查，以查看缓存的条目是否仍然可用。这个过程称为**缓存验证**。此外，当用户按下重新加载按钮时，也会触发重新验证。如果缓存的响应包括`Cache-Control: must revalidate`头，则在正常浏览时会触发它。

当资源的时间过期时，它将被验证或重新获取。只有在服务器提供了强验证器或弱验证器时，才会触发缓存验证。

# ETags

ETags 提供了验证缓存响应的机制。ETag 响应头可以用作强验证器。在这种情况下，客户端既不能理解该值，也无法预测其值。当服务器发出响应时，它生成一个隐藏资源状态的令牌：

```java
ETag : ijk564
```

如果响应中包含`ETag`，客户端可以在未来请求的头部中发出`If-None-Match`来验证缓存的资源：

```java
If-None-Match: ijk564
```

服务器将请求头与资源的当前状态进行比较。如果资源状态已更改，服务器将以新资源响应。否则，服务器将返回`304 Not Modified`响应。

# Last-Modified/If-Modified-Since 头

到目前为止，我们已经看到了一个强验证器（ETags）。在这里，我们将讨论一个可以在头部中使用的弱验证器。`Last-Modified`响应头可以用作弱验证器。与生成资源的哈希不同，时间戳将用于检查缓存的响应是否有效。

由于此验证器具有 1 秒的分辨率，与 ETags 相比被认为是弱的。如果响应中存在`Last-Modified`头，则客户端可以发送一个`If-Modified-Since`请求头来验证缓存的资源。

当客户端请求资源时，会提供`If-Modified-Since`头。为了在一个真实的例子中简化机制，客户端请求将类似于这样：“我已经在上午 10 点缓存了资源 XYZ；但是如果自上午 10 点以来它已经改变了，那么获取更新的 XYZ，否则只返回`304`。然后我将使用之前缓存的 XYZ。”

# 缓存实现

到目前为止，我们在本章中已经看到了理论部分。让我们尝试在我们的应用程序中实现这个概念。为了简化缓存实现，我们将只使用用户管理。我们将使用`getUser`（单个用户）REST API 来应用我们的缓存概念。

# REST 资源

在`getUser`方法中，我们将正确的`userid`传递给路径变量，假设客户端将传递`userid`并获取资源。有许多可用的缓存选项可供实现。在这里，我们将仅使用`If-Modified-Since`缓存机制。由于此机制将在标头中传递`If-Modified-Since`值，因此它将被转发到服务器，表示，如果资源在指定时间之后发生更改，请获取新资源，否则返回 null。

有许多实现缓存的方法。由于我们的目标是简化并清晰地传达信息，我们将保持代码简单，而不是在代码中添加复杂性。为了实现这种缓存，我们可能需要在我们的`User`类中添加一个名为`updatedDate`的新变量。让我们在我们的类中添加这个变量。

`updatedDate`变量将用作`If-Modified-Since`缓存的检查变量，因为我们将依赖于用户更新的日期。

客户端将询问服务器用户数据自上次缓存时间以来是否发生了更改。服务器将根据用户的`updatedDate`进行检查，如果未更新则返回 null；否则，它将返回新数据：

```java
  private Date updatedDate;
  public Date getUpdatedDate() {
    return updatedDate;
  }
  public void setUpdatedDate(Date updatedDate) {
    this.updatedDate = updatedDate;
  }
```

在前面的代码中，我们刚刚添加了一个新变量`updatedDate`，并为其添加了适当的 getter 和 setter 方法。稍后我们可能会通过添加 Lombok 库来简化这些 getter 和 setter 方法。我们将在接下来的章节中应用 Lombok。

此外，当我们获取类的实例时，我们需要添加另一个构造函数来初始化`updatedDate`变量。让我们在这里添加构造函数：

```java
public User(Integer userid, String username, Date updatedDate){
    this.userid = userid;
    this.username = username;
    this.updatedDate = updatedDate;
  }
```

如果可能的话，我们可以将`toString`方法更改如下：

```java
  @Override
  public String toString() {
    return "User [userid=" + userid + ", username=" + username + ", updatedDate=" + updatedDate + "]";
  }
```

在添加了所有上述提到的细节之后，我们的类将如下所示：

```java
package com.packtpub.model;
import java.io.Serializable;
import java.util.Date;
public class User implements Serializable {  
  private static final long serialVersionUID = 1L;
  public User() {
  }
  private Integer userid;
  private String username;
  private Date updatedDate;
  public User(Integer userid, String username) {
    this.userid = userid;
    this.username = username;
  }
  public User(Integer userid, String username, Date updatedDate) {
    this.userid = userid;
    this.username = username;
    this.updatedDate = updatedDate;
  }
  public Date getUpdatedDate() {
    return updatedDate;
  }
  public void setUpdatedDate(Date updatedDate) {
    this.updatedDate = updatedDate;
  }
  public Integer getUserid() {
    return userid;
  }
  public void setUserid(Integer userid) {
    this.userid = userid;
  }
  public String getUsername() {
    return username;
  }
  public void setUsername(String username) {
    this.username = username;
  }
  @Override
  public String toString() {
    return "User [userid=" + userid + ", username=" + username + ", updatedDate=" + updatedDate + "]";
  }
}
```

现在，我们将回到之前章节中介绍的`UserController`，并更改`getUser`方法：

```java
@RestController
@RequestMapping("/user")
public class UserController {
    // other methods and variables (hidden)  
    @ResponseBody
    @RequestMapping("/{id}")
    public User getUser(@PathVariable("id") Integer id, WebRequest webRequest){    
        User user = userSevice.getUser(id);
        long updated = user.getUpdatedDate().getTime();    
        boolean isNotModified = webRequest.checkNotModified(updated);    
        logger.info("{getUser} isNotModified : "+isNotModified);    
        if(isNotModified){
          logger.info("{getUser} resource not modified since last call, so exiting");
          return null;
        }    
        logger.info("{getUser} resource modified since last call, so get the updated content");    
        return userSevice.getUser(id);
   }
}
```

在前面的代码中，我们在现有方法中使用了`WebRequest`参数。`WebRequest`对象将用于调用`checkNotModified`方法。首先，我们通过`id`获取用户详细信息，并以毫秒为单位获取`updatedDate`。我们将用户更新日期与客户端标头信息进行比较（我们假设客户端将在标头中传递`If-Not-Modified-Since`）。如果用户更新日期比缓存日期更新，我们假设用户已更新，因此我们将不得不发送新资源。

由于我们在`UserController`中添加了记录器，因此我们可能需要导入`org.apache.log4j.Logger`。否则在编译时会显示错误。

如果用户在客户端缓存日期之后没有更新，它将简单地返回 null。此外，我们已经提供了足够的记录器来打印我们想要的语句。

让我们在 SoapUI 或 Postman 客户端中测试 REST API。当我们第一次调用 API 时，它将返回带有标头信息的数据，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/e9af7900-24f2-40b0-8ba0-b198978318b2.jpg)

SoapUI 客户端

我们可以看到我们正在使用`GET`方法来调用此 API，并且右侧是响应标头。

在我们之前的屏幕截图中，我们使用了端口`8081`。默认情况下，Spring Boot 在端口`8080`上运行。如果要将其更改为`8081`，请在`/src/main/resources/``application.properties`中配置端口如下：

`server.port = 8081`

如果在指定位置下没有`application.properties`，则可以创建一个。

响应（JSON）如下所示：

```java
{
   "userid": 100,
   "username": "David",
   "updatedDate": 1516201175654
}
```

在前面的 JSON 响应中，我们可以看到用户详细信息，包括`updatedDate`。

响应（标头）如下所示：

```java
HTTP/1.1 200 
Last-Modified: Wed, 17 Jan 2018 14:59:35 GMT
ETag: "06acb280fd1c0435ac4ddcc6de0aeeee7"
Content-Type: application/json;charset=UTF-8
Content-Length: 61
Date: Wed, 17 Jan 2018 14:59:59 GMT

{"userid":100,"username":"David","updatedDate":1516201175654}
```

在前面的响应标头中，我们可以看到 HTTP 结果`200`（表示 OK）和`Last-Modified`日期。

现在，我们将在标头中添加`If-Modified-Since`，并更新我们从先前响应中获取的最新日期。我们可以在以下屏幕截图中检查`If-Modified-Since`参数：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/ebde97a2-d5ee-4698-a91a-cb8a0ea76962.jpg)

在上述配置中，我们在标头部分添加了`If-Modified-Since`参数，并再次调用相同的 REST API。代码将检查资源是否自上次缓存日期以来已更新。在我们的情况下，资源没有更新，因此响应中将简单返回`304`。我们可以看到响应如下：

```java
HTTP/1.1 304 
Last-Modified: Wed, 17 Jan 2018 14:59:35 GMT
Date: Wed, 17 Jan 2018 15:05:29 GMT
```

HTTP `304`（未修改）响应只是向客户端传达资源未修改，因此客户端可以使用现有缓存。

如果我们通过调用更新 REST API（使用`PUT`的`http://localhost:8081/user/100`）更新指定的用户，然后再次调用先前的 API（使用`GET`的`http://localhost:8081/user/100`），我们将获得新的资源，因为用户在客户端缓存之后已更新。

# 使用 ETags 进行缓存

在上一节中，我们探讨了基于更新日期的缓存。然而，当我们需要检查更新的资源时，我们可能并不总是需要依赖更新日期。还有另一种机制，称为 ETag 缓存，它提供了一个强验证器，用于检查资源是否已更新。ETag 缓存将是检查更新日期的常规缓存的完美替代品。

在 ETag 缓存中，响应标头将为主体提供哈希 ID（MD5）。如果资源已更新，标头将在 REST API 调用时生成新的哈希 ID。因此，我们无需像在上一节中那样显式检查信息。

Spring 提供了一个名为`ShallowEtagHeaderFilter`的过滤器来支持 ETag 缓存。让我们尝试在我们现有的应用程序中添加`ShallowEtagHeaderFilter`。我们将在我们的主应用程序文件（`TicketManagementApplication`）中添加代码：

```java
  @Bean
  public Filter shallowEtagHeaderFilter() {
    return new ShallowEtagHeaderFilter();
  }
  @Bean
  public FilterRegistrationBean shallowEtagHeaderFilterRegistration() {
    FilterRegistrationBean result = new FilterRegistrationBean();
    result.setFilter(this.shallowEtagHeaderFilter());
    result.addUrlPatterns("/user/*");
    result.setName("shallowEtagHeaderFilter");
    result.setOrder(1);
    return result;
  }
```

在上述代码中，我们将`ShallowEtagHeaderFilter`作为一个 bean 添加，并通过提供我们的 URL 模式和名称进行注册。因为我们目前只测试用户资源，所以我们将在我们的模式中添加`/user/*`。最后，我们的主应用程序类将如下所示：

```java
package com.packtpub.restapp.ticketmanagement;
import javax.servlet.Filter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.ImportResource;
import org.springframework.web.filter.ShallowEtagHeaderFilter;
@ComponentScan("com.packtpub")
@SpringBootApplication
public class TicketManagementApplication {
  public static void main(String[] args) {
    SpringApplication.run(TicketManagementApplication.class, args);
  }
  @Bean
  public Filter shallowEtagHeaderFilter() {
    return new ShallowEtagHeaderFilter();
  }
  @Bean
  public FilterRegistrationBean shallowEtagHeaderFilterRegistration() {
    FilterRegistrationBean result = new FilterRegistrationBean();
    result.setFilter(this.shallowEtagHeaderFilter());
    result.addUrlPatterns("/user/*");
    result.setName("shallowEtagHeaderFilter");
    result.setOrder(1);
    return result;
  }
}
```

我们可以通过调用用户 API（`http://localhost:8081/user`）来测试这种 ETag 机制。当我们调用此 API 时，服务器将返回以下标头：

```java
HTTP/1.1 200 
ETag: "02a4bc8613aefc333de37c72bfd5e392a"
Content-Type: application/json;charset=UTF-8
Content-Length: 186
Date: Wed, 17 Jan 2018 15:11:45 GMT 
```

我们可以看到`ETag`已添加到我们的标头中，带有哈希 ID。现在我们将使用`If-None-Match`标头和哈希值调用相同的 API。我们将在以下截图中看到标头：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/bd-rst-websvc-spr5/img/d644eb31-ffdf-4337-8e47-a057eef15107.jpg)

当我们再次使用`If-None-Match`标头和先前哈希 ID 的值调用相同的 API 时，服务器将返回`304`状态，我们可以如下所示地看到：

```java
HTTP/1.1 304 
ETag: "02a4bc8613aefc333de37c72bfd5e392a"
Date: Wed, 17 Jan 2018 15:12:24 GMT 
```

在这种机制中，实际的响应主体将不会被发送到客户端。相反，它会告诉客户端资源未被修改，因此客户端可以使用先前缓存的内容。`304`状态表示资源未被缓存。

# 总结

在这一章中，我们已经学习了 HTTP 优化方法，以提高应用程序的性能。通过减少客户端和服务器之间的交互以及通过 HTTP 传输的数据大小，我们将在 REST API 服务中实现最大性能。在第十一章中，我们将探讨其他优化、缓存和扩展技术，*扩展*，因为我们将讨论与 Web 服务性能相关的更高级的主题。


# 第九章：AOP 和 Logger 控制

在本章中，我们将学习 Spring **面向方面的编程**（**AOP**）和日志控制，包括它们的理论和实现。我们将在我们现有的 REST API 中集成 Spring AOP，并了解 AOP 和日志控制如何使我们的生活更轻松。

在本章中，我们将涵盖以下主题：

+   Spring AOP 理论

+   Spring AOP 的实现

+   为什么我们需要日志控制？

+   我们如何实现日志控制？

+   集成 Spring AOP 和日志控制

# 面向方面的编程（AOP）

面向方面的编程是一个概念，它在不修改代码本身的情况下为现有代码添加新行为。当涉及到日志记录或方法认证时，AOP 概念真的很有帮助。

在 Spring 中，有许多方法可以使用 AOP。让我们不要深入讨论，因为这将是一个大的讨论话题。在这里，我们只讨论`@Before`切入点以及如何在我们的业务逻辑中使用`@Before`。

# AOP（@Before）与执行

AOP 中的执行术语意味着在`@Aspect`注解本身中有一个切入点，它不依赖于控制器 API。另一种方法是您将不得不在 API 调用中明确提及注解。让我们在下一个主题中讨论显式切入点：

```java
package com.packtpub.aop;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Before;
import org.springframework.stereotype.Component;
@Aspect
@Component
public class TokenRequiredAspect {  
  @Before("execution(* com.packtpub.restapp.HomeController.testAOPExecution())")
  public void tokenRequiredWithoutAnnoation() throws Throwable{
    System.out.println("Before tokenRequiredWithExecution");
  }
}
```

在这个切入点中，我们使用了`@Before`注解，它使用了`execution(* com.packtpub.restapp.HomeController.testAOPWithoutAnnotation())`，这意味着这个切入点将专注于一个特定的方法，在我们的例子中是`HomeController`类中的`testAOPWithoutAnnotation`方法。

对于与 AOP 相关的工作，我们可能需要将依赖项添加到我们的`pom.xml`文件中，如下所示：

```java
    <dependency>
        <groupId>org.aspectj</groupId>
        <artifactId>aspectjweaver</artifactId>
        <version>1.8.13</version>
    </dependency>
```

上述依赖项将带来所有面向方面的类，以支持我们在本章中的 AOP 实现。

`@Aspect`：这个注解用于使类支持方面。在 Spring 中，可以使用 XML 配置或注解（如`@Aspect`）来实现方面。

`@Component`：这个注解将使类根据 Spring 的组件扫描规则可扫描。通过将这个类与`@Component`和`@Aspect`一起提及，我们告诉 Spring 扫描这个类并将其识别为一个方面。

`HomeController`类的代码如下所示：

```java
  @ResponseBody
  @RequestMapping("/test/aop/with/execution") 
  public Map<String, Object> testAOPExecution(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Aloha");
    return map;
  }
```

在这里，我们只需创建一个新的方法来测试我们的 AOP。您可能不需要创建一个新的 API 来测试我们的 AOP。只要您提供适当的方法名，就应该没问题。为了使读者更容易理解，我们在`HomeContoller`类中创建了一个名为`testAOPExecution`的新方法。

# 测试 AOP @Before 执行

只需在浏览器中调用 API（`http://localhost:8080/test/aop/with/execution`）或使用任何其他 REST 客户端；然后，您应该在控制台中看到以下内容：

```java
Before tokenRequiredWithExecution
```

尽管这个日志并不真正帮助我们的业务逻辑，但我们现在会保留它，以便读者更容易理解流程。一旦我们了解了 AOP 及其功能，我们将把它集成到我们的业务逻辑中。

# AOP（@Before）与注解

到目前为止，我们已经看到了一个基于执行的 AOP 方法，可以用于一个或多个方法。然而，在某些地方，我们可能需要保持实现简单以增加可见性。这将帮助我们在需要的地方使用它，而且它不与任何方法绑定。我们称之为显式基于注解的 AOP。

为了使用这个 AOP 概念，我们可能需要创建一个接口，这个接口将帮助我们实现我们需要的东西。

`TokenRequired`只是我们`Aspect`类的一个基本接口。它将被提供给我们的`Aspect`类，如下所示：

```java
package com.packtpub.aop;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface TokenRequired {
}
```

`@Retention`：保留策略确定注解应在何时被丢弃。在我们的例子中，`RetentionPolicy.RUNTIME`将在 JVM 中通过运行时保留。

其他保留策略如下：

`SOURCE`：它将仅保留源代码，并且在编译时将被丢弃。一旦代码编译完成，注释将变得无用，因此不会写入字节码中。

`CLASS`：它将保留到编译时，并在运行时丢弃。

`@Target`：此注释适用于类级别，并在运行时匹配。目标注释可用于收集目标对象。

以下的`tokenRequiredWithAnnotation`方法将实现我们方面的业务逻辑。为了保持逻辑简单，我们只提供了`System.out.println(..)`。稍后，我们将向该方法添加主要逻辑：

```java
@Aspect
@Component
public class TokenRequiredAspect {
  // old method (with execution)  
  @Before("@annotation(tokenRequired)")
  public void tokenRequiredWithAnnotation(TokenRequired tokenRequired) throws Throwable{
    System.out.println("Before tokenRequiredWithAnnotation");
  } 
}
```

在前面的代码中，我们创建了一个名为`tokenRequiredWithAnnotation`的方法，并为该方法提供了`TokenRequired`接口作为参数。我们可以看到该方法顶部的`@Before`注释，并且`@annotation(tokenRequired)`。每次在任何方法中使用`@TokenRequired`注释时，将调用此方法。您可以如下所示查看注释用法：

```java
  @ResponseBody
  @RequestMapping("/test/aop/with/annotation")
  @TokenRequired
  public Map<String, Object> testAOPAnnotation(){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Aloha");   
    return map;
  }
```

以前的 AOP 方法和这个之间的主要区别是`@TokenRequired`。在旧的 API 调用者中，我们没有明确提到任何 AOP 注释，但在此调用者中，我们必须提到`@TokenRequired`，因为它将调用适当的 AOP 方法。此外，在此 AOP 方法中，我们不需要提到`execution`，就像我们在以前的`execution(* com.packtpub.restapp.HomeController.testAOPWithoutAnnotation())`方法中所做的那样。

# 测试 AOP @Before 注释

只需在浏览器中或使用任何其他 REST 客户端调用 API（`http://localhost:8080/test/aop/with/annotation`）;然后，您应该在控制台上看到以下内容：

```java
Before tokenRequiredWithAnnotation
```

# 将 AOP 与 JWT 集成

假设您想要在`UserContoller`方法中限制`deleteUser`选项。删除用户的人应该具有适当的 JWT 令牌。如果他们没有令牌，我们将不允许他们删除任何用户。在这里，我们将首先有一个`packt`主题来创建一个令牌。

可以调用`http://localhost:8080/security/generate/token?subject=packt`生成令牌的 API。

当我们在主题中使用`packt`时，它将生成`eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJwYWNrdCIsImV4cCI6MTUwOTk0NzY2Mn0.hIsVggbam0pRoLOnSe8L9GQS4IFfFklborwJVthsmz0`令牌。

现在，我们将不得不创建一个 AOP 方法，通过要求用户在`delete`调用的标头中具有令牌来限制用户：

```java
@Before("@annotation(tokenRequired)")
public void tokenRequiredWithAnnotation(TokenRequired tokenRequired) throws Throwable{   
       ServletRequestAttributes reqAttributes = (ServletRequestAttributes)RequestContextHolder.currentRequestAttributes();
       HttpServletRequest request = reqAttributes.getRequest();    
       // checks for token in request header
       String tokenInHeader = request.getHeader("token");    
       if(StringUtils.isEmpty(tokenInHeader)){
              throw new IllegalArgumentException("Empty token");
           }    
       Claims claims = Jwts.parser() .setSigningKey(DatatypeConverter.parseBase64Binary(SecurityServiceImpl.secretKey))
       .parseClaimsJws(tokenInHeader).getBody();    
       if(claims == null || claims.getSubject() == null){
                throw new IllegalArgumentException("Token Error : Claim is null");
             }    
       if(!claims.getSubject().equalsIgnoreCase("packt")){
                throw new IllegalArgumentExceptionception("Subject doesn't match in the token");
          }
       }
```

从前面的代码中可以看到 AOP 中的 JWT 集成。是的，我们已经将 JWT 令牌验证部分与 AOP 集成。因此，以后，如果有人调用`@TokenRequired`注释的 API，它将首先到达 AOP 方法并检查令牌匹配。如果令牌为空，不匹配或过期，我们将收到错误。所有可能的错误将如下所述。

现在，我们可以在`UserController`类中的 API 调用中开始使用`@TokenRequired`注释。因此，每当调用此`deleteUser`方法时，它将在执行 API 方法本身之前转到`JWT`，检查切入点。通过这样做，我们可以确保`deleteUser`方法不会在没有令牌的情况下被调用。

`UserController`类的代码如下：

```java
  @ResponseBody
  @TokenRequired
  @RequestMapping(value = "", method = RequestMethod.DELETE)
  public Map<String, Object> deleteUser(
      @RequestParam(value="userid") Integer userid){
    Map<String, Object> map = new LinkedHashMap<>();   
    userSevice.deleteUser(userid);   
    map.put("result", "deleted");
    return map;
  }
```

如果令牌为空或为空，它将抛出以下错误：

```java
{
   "timestamp": 1509949209993,
   "status": 500,
   "error": "Internal Server Error",
   "exception": "java.lang.reflect.UndeclaredThrowableException",
   "message": "No message available",
   "path": "/user"
}
```

如果令牌匹配，它将显示结果而不抛出任何错误。您将看到以下结果：

```java
{
    "result": "deleted"
} 
```

如果我们在标头中不提供任何令牌，可能会抛出以下错误：

```java
{
   "timestamp": 1509948248281,
   "status": 500,
   "error": "Internal Server Error",
   "exception": "java.lang.IllegalArgumentException",
   "message": "JWT String argument cannot be null or empty.",
   "path": "/user"
}
```

如果令牌过期，您将收到以下错误：

```java
 {
   "timestamp": 1509947985415,
   "status": 500,
   "error": "Internal Server Error",
   "exception": "io.jsonwebtoken.ExpiredJwtException",
   "message": "JWT expired at 2017-11-06T00:54:22-0500\. Current time: 2017-11-06T00:59:45-0500",
   "path": "/test/aop/with/annotation"
} 
```

# 日志记录控制

日志记录在需要跟踪特定过程的输出时非常有用。当我们在服务器上部署应用程序后，它将帮助我们验证过程或找出错误的根本原因。如果没有记录器，将很难跟踪和找出问题。

在我们的应用程序中，有许多日志记录框架可以使用；Log4j 和 Logback 是大多数应用程序中使用的两个主要框架。

# SLF4J，Log4J 和 Logback

SLF4j 是一个 API，帮助我们在部署过程中选择 Log4j 或 Logback 或任何其他 JDK 日志。SLF4j 只是一个抽象层，为使用我们的日志 API 的用户提供自由。如果有人想在他们的实现中使用 JDK 日志或 Log4j，SLF4j 将帮助他们在运行时插入所需的框架。

如果我们创建的最终产品不能被他人用作库，我们可以直接实现 Log4j 或 Logback。但是，如果我们有一个可以用作库的代码，最好选择 SLF4j，这样用户可以遵循他们想要的任何日志记录。

Logback 是 Log4j 的更好替代品，并为 SLF4j 提供本地支持。

# Logback 框架

我们之前提到 Logback 比 Log4j 更可取；在这里我们将讨论如何实现 Logback 日志框架。

Logback 有三个模块：

1.  `logback-core`：基本日志

1.  `logback-classic`：改进的日志记录和 SLF4j 支持

1.  `logback-access`：Servlet 容器支持

`logback-core`模块是 Log4j 框架中其他两个模块的基础。`logback-classic`模块是 Log4j 的改进版本，具有更多功能。此外，`logback-classic`模块本地实现了 SLF4j API。由于这种本地支持，我们可以切换到不同的日志框架，如**Java Util Logging**（**JUL**）和 Log4j。

`logback-access`模块为 Tomcat/Jetty 等 Servlet 容器提供支持，特别是提供 HTTP 访问日志功能。

# Logback 依赖和配置

为了在我们的应用程序中使用 Logback，我们需要`logback-classic`依赖项。但是，`logback-classic`依赖项已经包含在`spring-boot-starter`依赖项中。我们可以在项目文件夹中使用依赖树（`mvn dependency:tree`）来检查：

```java
mvn dependency:tree
```

在项目文件夹中检查依赖树时，我们将获得所有依赖项的完整树。以下是我们可以看到`spring-boot-starter`依赖项下的`logback-classic`依赖项的部分：

```java
[INFO] | +- org.springframework.boot:spring-boot-starter:jar:1.5.7.RELEASE:compile
[INFO] | +- org.springframework.boot:spring-boot:jar:1.5.7.RELEASE:compile
[INFO] | +- org.springframework.boot:spring-boot-autoconfigure:jar:1.5.7.RELEASE:compile
[INFO] | +- org.springframework.boot:spring-boot-starter-logging:jar:1.5.7.RELEASE:compile
[INFO] | | +- ch.qos.logback:logback-classic:jar:1.1.11:compile
[INFO] | | | \- ch.qos.logback:logback-core:jar:1.1.11:compile
[INFO] | | +- org.slf4j:jcl-over-slf4j:jar:1.7.25:compile
[INFO] | | +- org.slf4j:jul-to-slf4j:jar:1.7.25:compile
[INFO] | | \- org.slf4j:log4j-over-slf4j:jar:1.7.25:compile
[INFO] | \- org.yaml:snakeyaml:jar:1.17:runtime
[INFO] +- com.fasterxml.jackson.core:jackson-databind:jar:2
```

由于必要的依赖文件已经可用，我们不需要为 Logback 框架实现添加任何依赖项。

# 日志级别

由于 SLF4j 定义了这些日志级别，实现 SLF4j 的人应该适应 SFL4j 的日志级别。日志级别如下：

+   `TRACE`：详细评论，在所有情况下可能不会使用

+   `DEBUG`：用于生产环境中调试目的的有用评论

+   `INFO`：在开发过程中可能有帮助的一般评论

+   `WARN`：在特定场景下可能有帮助的警告消息，例如弃用的方法

+   `ERROR`：开发人员需要注意的严重错误消息

让我们将日志配置添加到`application.properties`文件中：

```java
# spring framework logging 
logging.level.org.springframework = ERROR

# local application logging
logging.level.com.packtpub.restapp = INFO
```

在前面的配置中，我们已经为 Spring Framework 和我们的应用程序使用了日志配置。根据我们的配置，它将为 Spring Framework 打印`ERROR`，为我们的应用程序打印`INFO`。

# 类中的 Logback 实现

让我们给类添加一个`Logger`；在我们的情况下，我们可以使用`UserController`。我们必须导入`org.slf4j.Logger`和`org.slf4j.LoggerFactory`。我们可以检查以下代码：

```java
private static final Logger _logger = LoggerFactory.getLogger(HomeController.class);
```

在前面的代码中，我们介绍了`_logger`实例。我们使用`UserController`类作为`_logger`实例的参数。

现在，我们必须使用`_logger`实例来打印我们想要的消息。在这里，我们使用了`_logger.info()`来打印消息：

```java
package com.packtpub.restapp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
// other imports
@RestController
@RequestMapping("/")
public class HomeController {  
  private static final Logger _logger = LoggerFactory.getLogger(HomeController.class);  
  @Autowired
  SecurityService securityService;  
  @ResponseBody
  @RequestMapping("")
  public Map<String, Object> test() {
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "Aloha");    
    _logger.trace("{test} trace");
    _logger.debug("{test} debug");
    _logger.info("{test} info");
    _logger.warn("{test} warn ");
    _logger.error("{test} error");    
    return map;
  }
```

在前面的代码中，我们使用了各种记录器来打印消息。当您重新启动服务器并调用`http://localhost:8080` REST API 时，您将在控制台中看到以下输出：

```java
2018-01-15 16:29:55.951 INFO 17812 --- [nio-8080-exec-1] com.packtpub.restapp.HomeController : {test} info
2018-01-15 16:29:55.951 WARN 17812 --- [nio-8080-exec-1] com.packtpub.restapp.HomeController : {test} warn 
2018-01-15 16:29:55.951 ERROR 17812 --- [nio-8080-exec-1] com.packtpub.restapp.HomeController : {test} error
```

正如您从日志中看到的，类名将始终在日志中以标识日志中的特定类。由于我们没有提及任何日志模式，记录器采用默认模式打印输出与类一起。如果需要，我们可以在配置文件中更改模式以获得定制日志。

在先前的代码中，我们使用了不同的日志级别来打印消息。对日志级别有限制，因此根据业务需求和实现，我们将不得不配置我们的日志级别。

在我们的日志配置中，我们只使用了控制台打印选项。我们还可以提供一个选项，将日志打印到我们想要的外部文件中。

# 总结

在本章中，我们涵盖了 Spring AOP 和日志控制的实现。在我们现有的代码中，我们介绍了 Spring AOP，并演示了 AOP 如何通过代码重用节省时间。为了让用户理解 AOP，我们简化了 AOP 的实现。在下一章中，我们将讨论如何构建一个 REST 客户端，并更多地讨论 Spring 中的错误处理。


# 第十章：构建 REST 客户端和错误处理

在之前的章节中，我们涵盖了 RESTful Web 服务的服务器端，包括 CRUD 操作。在这里，我们可以检查如何在代码中消费这些 API。REST 客户端将帮助我们实现这个目标。

在本章中，我们将讨论以下主题：

+   Spring 中的 RestTemplate

+   使用 Spring 构建 RESTful 服务客户端的基本设置

+   在客户端调用 RESTful 服务

+   定义错误处理程序

+   使用错误处理程序

# 构建 REST 客户端

到目前为止，我们已经创建了一个 REST API，并在诸如 SoapUI、Postman 或 JUnit 测试之类的第三方工具中使用它。可能会出现情况，您将不得不使用常规方法（服务或另一个控制器方法）本身来消费 REST API，比如在服务 API 中调用支付 API。当您在代码中调用第三方 API，比如 PayPal 或天气 API 时，拥有一个 REST 客户端将有助于完成工作。

在这里，我们将讨论如何构建一个 REST 客户端来在我们的方法中消费另一个 REST API。在进行这之前，我们将简要讨论一下 Spring 中的`RestTemplate`。

# RestTemplate

`RestTemplate`是一个 Spring 类，用于通过 HTTP 从客户端消费 REST API。通过使用`RestTemplate`，我们可以将 REST API 消费者保持在同一个应用程序中，因此我们不需要第三方应用程序或另一个应用程序来消费我们的 API。`RestTemplate`可以用于调用`GET`、`POST`、`PUT`、`DELETE`和其他高级 HTTP 方法（`OPTIONS`、`HEAD`）。

默认情况下，`RestTemplate`类依赖 JDK 建立 HTTP 连接。您可以切换到使用不同的 HTTP 库，如 Apache HttpComponents 和 Netty。

首先，我们将在`AppConfig`类中添加一个`RestTemplate` bean 配置。在下面的代码中，我们将看到如何配置`RestTemplate` bean：

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;
@Configuration
public class AppConfig {
  @Bean
  public RestTemplate restTemplate() {
      return new RestTemplate();
  }
}
```

在上面的代码中，我们已经在这个类中使用了`@Configuration`注解来配置类中的所有 bean。我们还在这个类中引入了`RestTemplate` bean。通过在`AppConfig`类中配置 bean，我们告诉应用程序所述的 bean 可以在应用程序的任何地方使用。当应用程序启动时，它会自动初始化 bean，并准备在需要的地方使用模板。

现在，我们可以通过在任何类中简单地使用`@Autowire`注解来使用`RestTemplate`。为了更好地理解，我们创建了一个名为`ClientController`的新类，并在该类中添加了一个简单的方法：

```java
@RestController
@RequestMapping("/client")
public class ClientController {  
  private final Logger _log = LoggerFactory.getLogger(this.getClass());    
  @Autowired
  RestTemplate template;  
  @ResponseBody
  @RequestMapping("/test") 
  public Map<String, Object> test(){
    Map<String, Object> map = new LinkedHashMap<>();
    String content = template.getForObject("http://localhost:8080/", String.class); 
    map.put("result", content);    
    return map;
  }  
}
```

在上面的代码中，我们使用了`RestTemplate`并调用了`getForObject`方法来消费 API。默认情况下，我们使用`String.class`来使我们的代码简单易懂。

当您调用这个 API `http://localhost:8080/client/test/`时，您将得到以下结果：

```java
{
  result: "{\"result\":"\Aloha\"}"
}
```

在上述过程中，我们在另一个 REST API 中使用了`RestTemplate`。在实时场景中，您可能会使用与调用第三方 REST API 相同的方法。

让我们在另一个方法中获取一个单个用户 API：

```java
@ResponseBody
  @RequestMapping("/test/user") 
  public Map<String, Object> testGetUser(){
    Map<String, Object> map = new LinkedHashMap<>();
    User user = template.getForObject("http://localhost:8080/user/100", User.class); 
    map.put("result", user);    
    return map;
  }
```

通过调用上述 API，您将得到单个用户作为结果。为了调用这个 API，我们的`User`类应该被序列化，否则您可能会得到一个未序列化对象错误。让我们通过实现`Serializable`并添加一个序列版本 ID 来使我们的`User`类序列化。

您可以通过在 Eclipse 中右键单击类名并生成一个序列号来创建一个序列版本 ID。

在对`User`类进行序列化之后，它将如下所示：

```java
public class User implements Serializable {  
  private static final long serialVersionUID = 3453281303625368221L;  
  public User(){ 
  }
  private Integer userid;  
  private String username;   
  public User(Integer userid, String username){
    this.userid = userid;
    this.username = username;
  }
  public Integer getUserid() {
    return userid;
  }
  public void setUserid(Integer userid) {
    this.userid = userid;
  }
  public String getUsername() {
    return username;
  }
  public void setUsername(String username) {
    this.username = username;
  }  
  @Override
  public String toString() {
    return "User [userid=" + userid + ", username=" + username + "]";
  }
}
```

最后，我们可以在浏览器中调用`http://localhost:8080/client/test/user`客户端 API，并得到以下结果：

```java
{
  result: {
    userid: 100,
    username: "David"
  }
}
```

为了便于理解，我们只使用了`GET`方法。然而，我们可以使用`POST`方法并在 REST 消费者中添加参数。

# 错误处理

到目前为止，在我们的应用程序中，我们还没有定义任何特定的错误处理程序来捕获错误并将其传达到正确的格式。通常，当我们在 REST API 中处理意外情况时，它会自动抛出 HTTP 错误，如`404`。诸如`404`之类的错误将在浏览器中明确显示。这通常是可以接受的；但是，无论事情是对是错，我们可能需要一个 JSON 格式的结果。

在这种情况下，将错误转换为 JSON 格式是一个不错的主意。通过提供 JSON 格式，我们可以保持我们的应用程序干净和标准化。

在这里，我们将讨论如何在事情出错时管理错误并以 JSON 格式显示它们。让我们创建一个通用的错误处理程序类来管理我们所有的错误：

```java
public class ErrorHandler {
  @ExceptionHandler(Exception.class)
  public @ResponseBody <T> T handleException(Exception ex) {    
    Map<String, Object> errorMap = new LinkedHashMap<>();
    if(ex instanceof org.springframework.web.bind.MissingServletRequestParameterException){      
      errorMap.put("Parameter Missing", ex.getMessage());
      return (T) errorMap;
    }    
    errorMap.put("Generic Error ", ex.getMessage());
    return (T) errorMap;
  }
}
```

上面的类将作为我们应用程序中的通用错误处理程序。在`ErrorHandler`类中，我们创建了一个名为`handleException`的方法，并使用`@ExceptionHandler`注解。此注解将使该方法接收应用程序中的所有异常。一旦我们获得异常，我们可以根据异常的类型来管理应该做什么。

在我们的代码中，我们只使用了两种情况来管理我们的异常：

+   缺少参数

+   一般错误（除了缺少参数之外的所有其他情况）

如果在调用任何 REST API 时缺少参数，它将进入第一种情况，“参数缺失”，否则它将进入“通用错误”默认错误。我们简化了这个过程，以便新用户能够理解。但是，我们可以在这种方法中添加更多情况来处理更多的异常。

完成错误处理程序后，我们将不得不在我们的应用程序中使用它。应用错误处理程序可以通过多种方式完成。扩展错误处理程序是使用它的最简单方法：

```java
@RestController
@RequestMapping("/")
public class HomeController extends ErrorHandler {    
    // other methods
  @ResponseBody
  @RequestMapping("/test/error") 
  public Map<String, Object> testError(@RequestParam(value="item") String item){
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("item", item);    
    return map;
  }   
}
```

在上面的代码中，我们只是在`HomeController`类中扩展了`ErrorHandler`。通过这样做，我们将所有错误情况绑定到`ErrorHandler`以正确接收和处理。此外，我们创建了一个名为`testError`的测试方法来检查我们的错误处理程序。

为了调用这个 API，我们需要将`item`作为参数传递；否则它将在应用程序中抛出一个错误。因为我们已经定义了`ErrorController`类并扩展了`HomeController`类，缺少参数将使您进入前面提到的第一个情景。

只需在浏览器或任何 REST 客户端（Postman/SoapUI）中尝试以下 URL：`http://localhost:8080/test/error`。

如果您尝试上述端点，您将得到以下结果：

```java
{
  Parameter Missing: "Required String parameter 'item' is not present"
}
```

由于我们在错误处理程序中定义了 JSON 格式，如果任何 REST API 抛出异常，我们将以 JSON 格式获得错误。

# 自定义异常

到目前为止，我们只探讨了应用程序引发的错误。但是，如果需要，我们可以定义自己的错误并抛出它们。以下代码将向您展示如何在我们的应用程序中创建自定义错误并抛出它：

```java
@RestController
@RequestMapping("/")
public class HomeController extends ErrorHandler {  
    // other methods  
  @ResponseBody
  @RequestMapping("/test/error/{id}")
  public Map<String, Object> testRuntimeError(@PathVariable("id") Integer id){    
    if(id == 1){
      throw new RuntimeException("some exception");
    }    
    Map<String, Object> map = new LinkedHashMap<>();
    map.put("result", "one");    
    return map;
  }
}
```

在上面的代码中，我们使用`RuntimeException`创建了一个自定义异常。这只是测试代码，向您展示自定义异常在错误处理中的工作原理。我们将在接下来的章节中在我们的应用程序中应用这个自定义异常。

如果您调用`http://localhost:8080/test/error/1`API，您将得到以下错误，这是由我们的条件匹配引起的：

```java
{
  Generic Error : "some exception"
}
```

# 摘要

在本章中，我们学习了如何使用`RestTemplate`构建 RESTful Web 服务客户端。此外，我们还涵盖了错误处理程序和集中式错误处理程序来处理所有容易出错的情况。在接下来的章节中，我们将讨论如何扩展我们的 Spring 应用程序，并简要讨论微服务，因为这些主题正在迅速增长。


# 第十一章：扩展

随着世界对网络的关注越来越多，我们所有的网络应用程序都需要处理更多的请求。为了应对更多的请求，我们可能需要扩展我们的应用程序来支持它们。

本章主要集中讨论可以应用于我们常规应用程序的技术、库和工具，以解决可扩展性问题。

在本章中，我们将讨论以下主题：

+   集群及其优势

+   负载均衡

+   扩展数据库

+   分布式缓存

# 集群

简而言之，集群就是添加多个服务器以提供相同的服务。这将帮助我们在灾难（如系统崩溃和其他不幸情况）期间避免中断。集群可以用作故障转移系统、负载均衡系统或并行处理单元。

故障转移集群是一组具有相同应用程序副本的服务器，以向客户端提供相同的服务，以维护应用程序和服务的高可用性。如果某个服务器因某种原因失败，其余服务器将接管负载，并为消费者提供不间断的服务。

+   **扩展（垂直扩展）**：这是指向我们的服务器添加更多资源，例如增加 RAM、硬盘容量和处理器。虽然这可能是一个不错的选择，但它只适用于某些情况，而不是所有情况。在某些情况下，增加更多资源可能会很昂贵。

+   **扩展（水平扩展）**：与在一个服务器内添加更多资源不同，扩展关注的是添加更多服务器/节点来处理请求。这种分组称为集群，因为所有服务器都在执行相同类型的任务，但在不同的服务器上复制，以避免中断。

# 集群的优势

集群是扩展服务的更受欢迎的解决方案，因为它提供了一种快速灵活的选项，可以在需要时添加更多服务器，而不会中断现有服务。在扩展期间可以提供不间断的服务。在扩展应用程序时，消费者不需要等待任何接近停机的事情。所有服务器负载都由中央负载平衡服务器正确平衡。

# 负载均衡

负载均衡器是集群中最有用的工具。负载均衡器使用各种算法，如轮询、最小连接等，将传入的请求转发到正确的后端服务器进行处理。

市场上有很多第三方负载均衡器可用，例如 F5（[`f5.com`](https://f5.com)）、HAProxy（[`www.haproxy.org`](http://www.haproxy.org)）等。尽管这些负载均衡工具的行为不同，但它们都专注于主要角色：将请求负载分发到可用的后端服务器，并在所有服务器之间保持平衡。通过适当的负载平衡，我们可以防止单个后端服务器过载。此外，大多数负载均衡器都配备了健康监控，例如检查可服务服务器的可用性。

除了在服务器之间进行主要请求分发外，负载均衡器还保护后端服务器免受前端服务器的影响。前端服务器不会知道将请求发送到哪个后端服务器，因为负载均衡器隐藏了所有关于后端服务器的细节。

# 扩展数据库

扩展数据库是架构设计中具有挑战性的部分之一。在这里，我们将讨论一些数据库扩展技术，以扩展我们的应用程序。

# 垂直扩展

正如我们之前讨论的，在应用程序服务器级别，我们也可以利用扩展技术来对我们的数据库服务器进行扩展。增加更多的计算能力，比如 CPU 和 RAM，将提高查询数据库的性能。通过使用垂直扩展技术，我们可以获得一致的性能，并且在出现问题时也很容易调试。此外，与水平扩展相比，垂直扩展提供了更高的效率。然而，垂直扩展可能需要定期停机来安装新硬件，并且受硬件容量的限制。

# 水平扩展

正如我们在应用程序级别讨论的水平扩展一样，我们可以通过向我们的集群添加更多机器来对数据库服务器进行相同的操作，以处理数据库负载。与垂直扩展相比，这要便宜得多；然而，这也伴随着集群配置、维护和管理成本。

# 读取副本

通过保留多个可用于读取的从库，我们可以显著改进我们的应用程序。读取副本有助于在所有只读从库中读取数据。然而，当我们需要发送写入请求时，我们可以使用主数据库。主数据库可以用于写入和读取，而从库只能用于读取。我们安装的从库越多，就可以处理更多基于读取的查询。这种读取副本技术在我们需要处理最小写入查询和最大读取查询的情况下非常有用。

# 连接池

当应用程序查询数据库时，它会创建客户端连接，发送查询并获取结果。由于与数据库的客户端连接是昂贵的操作，连接必须被重用以进行进一步的查询。连接池将在这种情况下有所帮助，通过防止为每个请求建立到数据库的连接。通过保持更好的连接池，比如 HikariCP，我们可以提高应用程序的性能。

# 使用多个主数据库

与读取副本不同，多主机制提供了复制多个数据库服务器的选项。与使用读取副本复制从库不同，这里我们复制主数据库以进行写入和读取数据。这种模式对于特定场景非常有用，比如 REST API 数据事务集中的应用程序。在多主模式中，我们需要我们的应用程序生成**通用唯一标识符**（**UUID**），以防止在多主复制过程中发生数据冲突。

# 数据库服务器的负载均衡

由于应用程序服务器的客户端连接限制是基于数据库供应商的，当应用程序服务器请求更多连接时，处理情况可能会有些棘手。通过保持负载均衡器，我们可以使用它们的连接池将数据库查询分发到可用的数据库服务器。借助负载均衡器，我们将确保所有数据库服务器负载均衡；然而，这取决于特定负载均衡器中使用的算法。

# 数据库分区

当我们处理需要高端服务器并且需要大量时间来查询的大型数据库时，分区数据库非常有帮助。此外，当我们的应用程序需要查询大量读取和写入请求时，这也是有用的。分区可以进行水平和垂直两种方式。水平和垂直分区都在以下部分中描述。

# 分片（水平分区）

数据库表可以根据任何特定属性分成多个表。例如，用户数据库可以分成两个不同的数据库，比如`user_1`和`user_2`，其中`user_1`表的用户名以*A*-*N*开头，而`user_2`表的用户名以*O*-*Z*开头。通过像之前那样分割数据库，我们可以减少每个表中的行数，从而提高性能。

# 垂直分区

在垂直分区中，数据库表可以根据业务概念分成多个表。例如，一个表可能有更多的列，以便其他表可以轻松访问以获得更好的性能。

通过进行水平和垂直分区，查询数据库所需的时间将减少，从而提高性能。此外，通过将大型数据库划分为小块，我们可以避免需要高端计算机。这些数据分片可以分布到低成本的服务器上以节省成本。然而，在特定场景下，数据共享可能是一个复杂的过程。

# 分布式缓存

分布式缓存技术将有助于提高 Web 服务的可伸缩性。与进程内缓存不同，分布式缓存不需要在相同的应用程序空间中构建。它们可以存储在集群的多个节点上。尽管分布式缓存部署在多个节点上，但它们提供单一的缓存状态。

# 数据层缓存

在数据库中添加缓存层将提供更好的性能。这被认为是改善性能的常见策略，特别是当我们的应用程序中读取请求很多时。在这里，我们将讨论 Hibernate 的缓存级别。

# 一级缓存

一级缓存是 Hibernate 启用的内置会话缓存，是通过所有请求的强制性缓存。在 Hibernate 中没有禁用一级缓存的选项。一级缓存与会话对象相关联，一旦会话过期，缓存将丢失。当我们第一次查询 Web 服务时，对象将从数据库中检索并存储在一级缓存中，该缓存与 Hibernate 会话相关联。如果我们再次请求相同的实体，它将从缓存中检索，而无需查询数据库。

# 二级缓存

二级缓存是 Hibernate 中的可选缓存。在我们的请求到达二级缓存之前，一级缓存将是联系点。二级缓存可以按类或集合配置，并负责在会话之间缓存对象。

由于只有少数类受益于缓存，默认情况下禁用了二级缓存。可以启用以服务设计师。

# 应用层缓存

与在数据库中缓存类似，我们还可以在应用程序层缓存任何对象以提高应用程序的性能。在这里，我们将讨论各种对象缓存，特别是键值缓存工具，并检查它们在市场上的独特性。

# Memcached

由于大多数公司在其应用程序中使用 Memcached (`https://memcached.org`)，我们认为 Memcached 是最强大的分布式缓存系统之一。它遵循分布式内存缓存机制，在重复的场景中非常有帮助，例如当多次请求相同的服务时。

# Redis

Redis ([`redis.io`](https://redis.io)) 是另一个可以用于缓存的内存键值存储。Redis 支持诸如哈希、列表、集合等数据结构。Redis 被认为是最受欢迎的键值存储之一，支持高级键值缓存。Redis 支持交集和并集等操作。由于其高级功能和速度，它比 Memcached 更受青睐。

# Hazelcast

Hazelcast（[`hazelcast.com`](https://hazelcast.com)）是一个支持分布式集合并简化分布式计算的内存数据网格。它提供了一个简单的 API 和简单直接的部署策略。由于 Hazelcast 提供了 Memcached 客户端库，使用 Memcached 集群的应用程序可能能够适应 Hazelcast 集群。Hazelcast 架构支持在集群平台上的数据分发和高可伸缩性。它还提供智能同步和自动发现。Hazelcast 提供了分布式数据结构、分布式查询和分布式计算等功能。Spring Boot 在其框架中明确支持 Hazelcast 缓存。

# Ehcache

Ehcache（[`www.ehcache.org`](http://www.ehcache.org)）由于其简化的可扩展选项，主要用于小型到中型部署。它被认为是最广泛使用的分布式缓存之一。此外，Ehcache 提供了与其他流行库和框架集成的选项。Ehcache 的扩展从进程内缓存开始，经过混合的进程内和进程外部署。此外，Ehcache 推出了 Terracotta 服务器，以提高缓存性能。

# Riak

Riak（[`github.com/basho/riak`](https://github.com/basho/riak)）是基于 Erlang 的键值数据存储，具有容错性和高可用性。在 Riak 中，数据可以存储在内存、磁盘或两者兼有。Riak 可以通过诸如 HTTP API 或本机 Erlang 接口之类的协议进行访问。Riak 支持主要语言，如 Java、C 和 Python。此外，它支持 MapReduce，可以在大数据相关操作中灵活使用。

# Aerospike

Aerospike（[`www.aerospike.com`](https://www.aerospike.com)）是一个开源的、针对闪存优化的、内存 NoSQL 数据库和键值存储。Aerospike 在三个层面上运行：针对闪存优化的数据层、自管理的分布层和集群感知的客户端层。为了确保一致性，分布层在所有数据中心都有副本。即使单个服务器节点失败或从集群中移除，这些副本也会保持功能正常。

# Infinispan

Infinispan（[`infinispan.org/`](http://infinispan.org/)）是一个分布式的内存键值数据存储，可以用作缓存或数据网格。它可以作为库或通过诸如 REST 之类的协议进行访问。此外，Infinispan 可以与 JPA、JCache、Spring 和 Spark 集成。Infinispan 支持大多数与 MapReduce 相关的操作。

# Cache2k

Cache2k（[`cache2k.org/`](https://cache2k.org/)）提供了 Java 应用程序中的内存对象缓存选项。Cache2k 主要侧重于 JVM 内部的缓存。

# 其他分布式缓存

之前，我们讨论了主要的缓存工具及其机制。在这里，我们将更多地讨论市场上可用的其他分布式缓存：

# Amazon ElastiCache

ElastiCache 主要用作内存数据存储和缓存服务；它是由 AWS 引入的。借助 Amazon ElastiCache 的支持，我们可以快速部署我们的缓存环境，而无需进行任何复杂的安装。它支持 Memcached 和 Redis 缓存。

# Oracle 分布式缓存（Coherence）

在这个分布式缓存中，数据被分区在集群中的所有计算机上。这些分区缓存将被配置为在集群中的节点上保留每个数据片段。分布式缓存是 Coherence 中最常用的缓存。

尽管市场上有很多缓存解决方案可供选择，但选择特定的解决方案取决于许多因素，如业务需求、性能需求、数据完整性、容错性、成本等。在应用程序层和数据库层添加正确的分布式缓存层将会带来更好的性能。

# 总结

在本章中，我们讨论了不同的库、工具和技术，以扩展 RESTful Web 服务。在开发应用程序时，我们将不得不通过使用明确定义的接口来寻找系统组件之间的松耦合。在接下来的章节中，我们将讨论微服务及其优势。


# 第十二章：微服务基础知识

尽管单体架构有其自身的好处，但当应用程序变得越来越大以支持各种类型的业务逻辑时，它给开发人员和部署工程师带来了很大的困难。即使是后端的一个小 bug 修复也会迫使开发人员在服务器上重新部署整个应用程序，导致不必要的维护。另一方面，微服务提供了将业务逻辑分离成服务的选项。因此，应用程序可以在不中断流程的情况下推送到服务器，尤其是最终用户不应该注意到任何中断。在本章中，我们将深入探讨一些关于微服务和相关主题的基础知识。

在本章中，我们将讨论：

+   单体架构及其缺点

+   微服务及其优势

+   微服务的基本特征

+   微服务组件

+   微服务工具

# 单体架构及其缺点

尽管微服务架构如今越来越受欢迎，但大多数公司仍然使用单体架构。作为单体应用程序，您可以将所有业务模块捆绑成一个单一单元，并将它们部署在所有需要的服务器上。如果应用程序需要进行任何更改，开发人员必须提供这些更改并重新部署应用程序的更新版本。在单体架构中，我们遵循服务模块之间的紧密耦合。

尽管单体架构有一些好处，但其缺点为另一种架构设计——微服务铺平了道路。在这里，我们将简要讨论单体架构的缺点：

+   对于每个 bug 修复或代码更改，我们必须在所有服务器上重新部署整个应用程序

+   如果单体应用程序存在任何常见问题，比如性能问题，它将影响整个应用程序，这可能很难找出并快速修复

+   更大的应用程序在部署期间可能需要更长的启动时间

+   库需求和冲突可能影响整个应用程序。我们将很难修复库以支持所有模块

+   单体架构的扩展可能很困难，因为所有模块都在一个统一的范围内

+   应用程序增长时，业务逻辑和实现的复杂性也会增加，这可能需要更多的时间来开发和维护

+   不经常、昂贵和大规模的部署选项：如果我们有多种类型的业务逻辑和层，并且想要升级一个业务逻辑，我们将需要部署所有其他层/服务

+   紧密耦合的服务在一个服务/层需要升级时会带来困难

# 服务发现

在微服务架构中，根据业务需求和服务负载，我们可能需要增加服务实例。在这种情况下，跟踪所有可用的服务实例及其信息，如端口号，可能很难管理。服务发现将帮助我们通过自动配置服务实例并在需要时查找它们来管理这些任务。

# 微服务简介

在一个大型应用程序中做一些改变对开发人员来说是一个不断的痛苦。每次我们在代码中做一个小改变，我们可能需要将整个应用程序部署到服务器上，这是一个耗时且繁琐的过程，特别是当我们有多个服务，比如会计、报告、用户管理等。微服务帮助我们摆脱这种痛苦。微服务的主要目标是将应用程序拆分为服务，并独立部署每个服务到我们的服务器上。通过这样做，我们在应用程序中提供了松散耦合的进程。此外，微服务可以部署在云中，以避免服务中断问题，并为消费者提供不间断的服务。

在微服务中，每个模块或业务部分都可以编写为一个单独的服务，以提供持续交付和集成。这些服务旨在满足特定的业务需求，并且可以通过自动化部署基础设施独立部署。管理这些服务可以是分散的，并且可以以不同的语言进行编程。

在转向组件之前，我们将简要讨论微服务的基本特征。

# 独立性和自治性

微服务作为单片环境的更好替代品。在微服务中，每个服务都可以在任何时候启动、停止、升级或替换，而不会中断其他服务。所有服务都是独立的，并且可以自动注册到我们的中央注册表中。

# 弹性和容错性

在复杂的应用程序设计中，创建一个具有弹性的系统对每个服务都至关重要。大多数云环境都需要一种架构设计，其中所有服务都能应对意外情况，比如停机等。这些情况可能包括接收到坏数据（损坏的数据），可能无法到达所需的服务，或者可能在并发系统中请求冲突。微服务需要对故障具有弹性，并且应该能够快速重启自己。

微服务应该防止故障通过系统中的其他依赖服务进行级联。

# 自动化环境

自动化应该是微服务架构设计中的一个重要因素，因为应用程序中将涉及许多服务，因此服务之间的交互将非常复杂。必须实施自动化监控和警报管理系统来增强微服务设计。所有服务都应记录其数据和指标，并且这些指标应得到适当监控，因为这将改善服务管理。

# 无状态

微服务是无状态的，这意味着它们不会在一个会话中保留数据到另一个会话。此外，微服务实例不会相互交互。当应用程序中有更多的微服务实例可用时，每个实例都不会知道其他实例，无论下一个实例是否存活。当我们扩展我们的应用程序时，这一特征非常有帮助。

# 微服务的好处

在本节中，我们将讨论在我们的应用程序中开发微服务的好处：

+   业务逻辑可以分组并开发成易于开发和部署的服务，具有多个服务实例

+   微服务可以通过将应用程序拆分为多个服务来避免复杂的应用程序，提供易于开发和维护业务逻辑，特别是在升级特定部分时

+   服务可以独立部署，而不会中断应用程序；因此，最终用户永远不会感受到任何服务中断

+   松散耦合的服务将在扩展应用程序方面提供更多的灵活性

+   单独升级服务以满足时尚的业务需求是方便的，开发人员可以引入新技术来开发服务

+   借助微服务，可以更容易地实现持续部署；因此，可以对所需的模块进行快速升级

+   扩展这些服务将非常灵活，特别是当特定的业务需求需要更多实例以为最终用户提供不间断的服务时

+   组织可以专注于可以快速移至生产环境的小批量工作，特别是在为特定客户测试新功能时

# 微服务组件

为了拥有完全功能的微服务应用程序，必须正确使用以下组件。这些组件帮助我们在服务之间解决复杂的业务逻辑分配：

+   配置服务器

+   负载均衡器

+   服务发现

+   断路器

+   边缘服务器

我们将在本节中简要讨论这些组件。

# 配置服务器

配置服务器将帮助我们存储将要部署的每个服务的所有可配置参数。如果需要，这些属性可以保存在存储库中。此外，配置服务器将提供更改应用程序配置的选项，而无需部署代码。一旦配置更改，它将自动反映在应用程序中，因此我们可以避免重新部署我们的服务。

由于我们的微服务应用中将有许多服务，拥有配置服务器将帮助我们避免服务重新部署，并且服务可以从服务器获取相应的配置。这也是持续交付的原则之一：将源代码与配置解耦。

# 负载均衡器

负载均衡器通过将负载分配给特定服务来作为扩展应用程序的支柱。负载均衡器被认为是微服务架构中的重要组成部分。与分布在服务器之间的常规负载均衡器不同，这些负载均衡器管理服务实例并在这些实例之间分配负载。借助服务发现组件的帮助，它们将获取有关可用服务实例的信息并分配负载。

Netflix Ribbon 被用作负载均衡器；我们将在本章的*微服务工具*部分探讨这一点。

# 断路器

由于我们的架构中有许多服务共同工作，每个服务可能相互依赖。有些情况会导致一些服务失败，并可能导致其他服务随之失败。为了避免这种情况，我们的架构应该具有容错性。使用断路器等模式可以减少微服务架构中的故障。

# 边缘服务器

边缘服务器实现了 API 网关模式，并且对外部世界的 API 行为像一堵墙。借助边缘服务器，所有公共流量将被转发到我们的内部服务。通过这样做，最终用户在未来我们的服务和内部结构发生任何变化时不会受到影响。Netflix Zuul 被用作边缘服务器，我们将在下一节中分享一些关于 Zuul 的内容。

# 微服务工具

Netflix 工程师为微服务开发做出了很大贡献，并为微服务生态系统引入了各种组件。在这里，我们将讨论可能涉及微服务的更多组件：

+   Netflix Eureka

+   Netflix Zuul

+   Spring Cloud Config 服务器

+   Netflix Ribbon

+   Spring Cloud Netflix

+   Spring Security OAuth2

+   Netflix Hystrix 和 Turbine

+   Eclipse Microprofile

我们将在接下来的部分中更多地讨论它们。

# Netflix Eureka

Eureka 在微服务中扮演着服务发现服务的角色。它允许微服务在运行时注册自己，并在需要时帮助我们定位服务。它用于中间层服务器的负载平衡和故障转移。此外，Eureka 还配备了一个 Java 客户端（Eureka 客户端）以使服务交互更加容易。Eureka 服务器通过定位中间层服务器中的服务来充当中间层（服务级别）负载平衡工具。这些中间层（服务级别）负载平衡工具可能在类似 AWS 的云中不可用。

尽管 AWS 的弹性负载均衡器（ELB）可用于负载均衡服务，但它仅支持传统负载均衡器等端用户 Web 服务，而不支持中间层负载均衡。

在 Eureka 服务器中，客户端的实例知道他们需要与哪些服务通信，因为 Eureka 负载均衡器也专注于实例级别。Eureka 服务是无状态的，因此它们支持可伸缩性。由于服务器信息被缓存在客户端，负载均衡在负载均衡器宕机的情况下非常有帮助。

Eureka 在 Netflix 中用于 memcached 服务、cassandra 部署和其他操作。强烈建议在本地服务应该对公共服务禁用的中间层服务中使用 Eureka 服务器。

Netflix 开发人员启动了 Eureka 服务器并将其开源。后来，Spring 将其纳入了 Spring Cloud。在微服务架构中，服务应该是细粒度的，以提高应用程序的模块化，便于开发、测试和维护。

# Netflix Zuul

Zuul 充当公共前门的门卫，并且不允许未经授权的外部请求通过。它还提供了我们服务器中微服务的入口点。Zuul 使用 Netflix Ribbon 来查找可用的服务并将外部请求路由到正确的服务实例。Zuul 支持动态路由、监控和安全性。

Zuul 的不同类型的过滤器，如`PRE`、`ROUTING`、`POST`和`ERROR`，有助于实现以下操作：

+   动态路由

+   洞察和监控

+   认证和安全

+   压力测试

+   多区域弹性

+   静态响应处理

Zuul 有多个组件：

+   `zuul-core`

+   `zuul-simple-webapp`

+   `zuul-netflix`

+   `zuul-netflix-webapp`

# Spring Cloud Netflix

Spring Cloud 提供了第三方云技术与 Spring 编程模型之间的交互。Spring Cloud Netflix 为 Spring Boot 提供了 Netflix **开源软件** (**OSS**)集成支持，通过自动配置和绑定到 Spring 环境来使用。通过在 Spring Boot 中添加一些注解，我们可以构建一个包括 Netflix 组件在内的大型分布式应用程序。

Spring Cloud Netfix 可以实现诸如服务发现、服务创建、外部配置、路由器和过滤器等功能。

# Netflix Ribbon

Netflix 被服务消费者用于在运行时查找服务。Ribbon 从 Eureka 服务器获取信息以定位适当的服务实例。在 Ribbon 有多个实例可用的情况下，它将应用负载均衡机制来将请求分布到可用的实例上。Ribbon 不作为一个独立的服务运行，而是作为每个服务消费者中的一个嵌入式组件。具有客户端负载均衡是使用服务注册表的一个重大好处，因为负载均衡器让客户端选择服务的注册实例。

Ribbon 提供以下功能：

+   负载均衡规则（多个和可插拔的）

+   服务发现集成

+   对故障的弹性

+   云支持

Ribbon 有子组件，如`ribbon-core`、`ribbon-eureka`和`ribbon-httpclient`。

Netflix Ribbon 充当客户端负载均衡器，并且可以与 Spring Cloud 集成。

# Netflix Hystrix

每个分布式环境都容易发生服务故障，这种情况可能经常发生。为了解决这个问题，我们的架构应该具有容错和延迟容忍性。Hystrix 是一个断路器，可以帮助我们避免这种情况，如服务依赖失败。Hystrix 可以防止服务过载，并在发生故障时隔离故障。

通过 Hystrix 支持，我们可以通过在微服务中添加延迟容忍和容错逻辑来控制它们之间的交互。在服务失败的情况下，Hystrix 提供了强大的回退选项，从而提高了系统的整体弹性。如果没有 Hystrix，如果内部服务失败，可能会中断 API 并破坏用户体验。

Hystrix 遵循一些基本的弹性原则，如下：

+   服务依赖的失败不应该对最终用户造成任何中断

+   在服务依赖失败的情况下，API 应该做出正确的反应

Hystrix 还有一个断路器回退机制，使用以下方法：

+   **自定义回退**：当客户端库提供回退或本地数据以生成响应时

+   **失败静默**：回退返回 null，在某些情况下很有帮助

+   **快速失败**：在特定情况下使用，如 HTTP 5XX 响应

# Netflix Turbine

Turbine 用于将所有**服务器发送事件**（SSE）JSON 数据流聚合成一个流，可用于仪表板目的。Turbine 工具用于 Hystrix 应用程序，该应用程序具有实时仪表板，可从多台机器中聚合数据。Turbine 可以与支持 JSON 格式的任何数据源一起使用。Turbine 是数据不可知的，并且能够将 JSON 块视为键值对的映射。

Netflix 使用 Turbine 与 Eureka 服务器插件来处理因各种原因加入和离开集群的实例，例如自动缩放、不健康等。

# HashiCorp Consul

Consul 是一个服务发现和配置工具，用于支持微服务。Consul 是由 Hashi Corp 于 2014 年发起的，主要专注于跨多个数据中心的分布式服务。此外，Consul 可以保护数据并与大型基础设施配合工作。通过使用键和值配置服务，并找到所需的服务，Consul 解决了微服务的核心问题。

Consul 有服务器和客户端，形成一个单一的 Consul 集群。在 Consul 集群中，节点将能够存储和复制数据。通过至少一个成员的地址的帮助，自动发现集群中的其他成员。此外，Consul 提供了动态基础设施，因此不需要额外的编码/开发来自动发现服务。

Consul 旨在为 DevOps 社区和应用程序开发人员提供支持现代和弹性基础设施的工具。

# Eclipse MicroProfile

Eclipse MicroProfile 是由 RedHat、IBM 等公司和其他团体发起的，旨在为构建微服务提供规范。该项目始于 2016 年，最近发布了 MicroProfile 的 1.2 版本。它主要专注于优化企业 Java 以适应微服务架构。Payara Micro 和 Payara Servers 都与 Eclipse MicroProfile 兼容。

Eclipse MicroProfile 1.2 版本配备了配置 API、健康检查、容错、度量和其他支持微服务的必要工具。

# 总结

在本章中，我们简要讨论了单体应用及其缺点。然后我们谈到了微服务及其优点以及相关主题。此外，我们还讨论了微服务的基本原则，包括弹性和容错。

在本章的后面部分，我们讨论了微服务组件，并涵盖了与微服务相关的工具，如 Netflix Eureka、Zuul 等。在下一章和最后一章中，我们将处理一个包括身份验证和授权在内的高级 CRUD 操作的实时票务管理场景。
