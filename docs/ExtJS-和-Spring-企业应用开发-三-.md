# ExtJS 和 Spring 企业应用开发（三）

> 原文：[`zh.annas-archive.org/md5/84CE5C4C4F19D0840640A27766EB042A`](https://zh.annas-archive.org/md5/84CE5C4C4F19D0840640A27766EB042A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：网络请求处理层

请求处理层是将 HTTP 客户端与应用程序提供的服务粘合在一起的胶水。这一层的领域是请求的解释和数据的传输。我们的重点将放在 Ext JS 4 客户端消耗和提交的数据上。这些数据是以 JSON 格式存在，因此我们将讨论使用 Java JSON 处理 API 进行 JSON 解析和生成。然而，需要注意的是，任何类型的数据都可以通过适当的请求处理实现来暴露。如果需要的话，实现 RMI 或 RESTful 接口同样容易。

# Web MVC 的简要历史

在历史背景下讨论**模型-视图-控制器**（MVC）范式可能看起来有些奇怪，因为大多数 Web 应用程序今天仍在使用这项技术。MVC 设计模式最早在 2000 年初就开始在开源的 Struts 框架中引起关注。这个框架鼓励使用 MVC 架构来促进处理和提供请求时的责任清晰划分。服务器端 Java 开发的 MVC 范式一直存在，以各种形式存在，最终演变成了设计良好且功能强大的 Spring MVC 框架。

使用 MVC 方法的理由非常简单。实现客户端和应用程序之间交互的 Web 层可以分为以下三种不同类型的对象：

+   代表数据的模型对象

+   负责显示数据的视图对象

+   响应操作并为视图对象提供模型数据的控制器对象

每个 MVC 对象都会独立行事，耦合度低。例如，视图技术对控制器来说并不重要。视图是由 FreeMarker 模板、XSLT 转换或 Tiles 和 JSP 的组合生成并不重要。控制器只是将处理模型数据的责任传递给视图对象。

在这个历史讨论中需要注意的一个重要点是，所有的 MVC 处理都是在服务器上进行的。随着 JavaScript 框架数量的增加，特别是 Ext JS 4，MVC 范式已经从服务器转移到客户端浏览器。这是 Web 应用程序开发方式的根本变化，也是你正在阅读本书的原因！

# 企业 Web 应用程序的请求处理

以下图表清楚地标识了请求处理层在整体应用架构中的位置：

![企业 Web 应用程序的请求处理](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_07_01.jpg)

请求处理层接受客户端请求，并将相应的操作转发给适当的服务层方法。返回的 DTO（或者在领域驱动设计中也称为值对象）被检查，然后适当的响应被发送给客户端。与历史上的服务器端 MVC 编程不同，请求处理层不了解展示，只是作为应用程序的请求处理接口。

# 构建请求处理层

Ext JS 4 客户端的网络请求处理层是服务层接口的 JSON 生成代理。在这一层内，领域实体被转换为 JSON 表示；因此我们的第一步是创建一些辅助代码来简化这个任务。

有几个优秀的开源 JSON 生成项目可以帮助完成这项任务，包括 Jackson（[`jackson.codehaus.org`](http://jackson.codehaus.org)）和 Google Gson（[`code.google.com/p/google-gson/`](http://code.google.com/p/google-gson/)）。这些库通过它们声明的字段将 POJO 解析为适当的 JSON 表示。随着 Java EE 7 的发布，我们不再需要第三方库。Java API for JSON Processing (JSR-353)在所有 Java EE 7 兼容的应用服务器中都可用，包括 GlassFish 4。我们将利用这个 API 来生成和解析 JSON 数据。

### 注意

如果您无法使用 Java EE 7 应用服务器，您将需要选择替代的 JSON 生成策略，例如 Jackson 或 Google Gson。

## 为 JSON 生成做准备

我们的第一个添加是一个新的领域接口：

```java
package com.gieman.tttracker.domain;

import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

public interface JsonItem{

    public JsonObject toJson();
    public void addJson(JsonObjectBuilder builder);

}
```

这个非常简单的接口定义了两个方法来帮助生成 JSON。`toJson`方法创建一个代表实体的`JsonObject`。`addJson`方法将实体属性添加到`JsonObjectBuilder`接口。我们很快就会看到这两种方法是如何使用的。

我们的每个领域实体都需要实现`JsonItem`接口，这可以通过简单地将接口添加到所有领域实体的抽象超类中来实现：

```java
package com.gieman.tttracker.domain;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
public abstract class AbstractEntity implements JsonItem, Serializable{

    @Override
 public JsonObject toJson() {

 JsonObjectBuilder builder = Json.createObjectBuilder();
 addJson(builder);
 return builder.build();
 }

}
```

`JsonObjectBuilder`接口定义了一组方法，用于向与构建器关联的 JSON 对象添加名称/值对。`builder`实例添加了实现`addJson`方法的后代类中定义的字段。我们将从`Company`对象开始。

### 实现 Company addJson 方法

需要添加到`Company`类的`addJson`方法如下：

```java
@Override
public void addJson(JsonObjectBuilder builder) {
  builder.add("idCompany", idCompany)
     .add("companyName", companyName);
}
```

`Company`实例的`JsonObject`表示是通过在超类中调用`builder.build()`方法创建的。然后，生成的`JsonObject`可以由`JsonWriter`实例写入输出源。

### 实现 Project addJson 方法

需要添加到`Project`类的`addJson`方法如下：

```java
@Override
public void addJson(JsonObjectBuilder builder) {

  builder.add("idProject", idProject)
     .add("projectName", projectName);

  if(company != null){
     company.addJson(builder);
  }
}   
```

请注意，在访问对象方法之前执行`null`对象测试始终是一个良好的做法。可以创建一个没有`company`实例的`project`对象，因此我们在向项目`builder`实例添加`company` JSON 属性之前执行`company != null`测试。我们可以直接使用以下代码将`company`属性添加到项目`builder`实例中：

```java
builder.add("idProject", idProject)
     .add("projectName", projectName)
.add("idCompany", company.getIdCompany() )
     .add("companyName", company.getCompanyName() );
```

然而，我们现在已经在两个类（`Company.addJson`和`Project.addJson`）中复制了`builder.add("idCompany"…)`的代码，这样未来的维护容易出现错误。例如，将 JSON 属性名称从`idCompany`更改为`companyId`将需要扫描代码以检查可能在所有类中使用，而不仅仅是`Company`类。`Company` JSON 的创建应该属于`Company`类，因为我们已经实现了。

### 实现 Task addJson 方法

这个`Task`类将实现如下的`addJson`方法：

```java
@Override
public void addJson(JsonObjectBuilder builder) {

  builder .add("idTask", idTask)
     .add("taskName", taskName);

  if(project != null){
     project.addJson(builder);

     Company company = project.getCompany();
     company.addJson(builder);
  }        
}
```

再次注意，我们如何将`project`和`company`类的`addJson`调用链接到任务的`builder`实例，以添加它们的 JSON 属性。

### 实现 User addJson 方法

`User.addJson`方法定义如下：

```java
@Override
public void addJson(JsonObjectBuilder builder) {

  builder.add("username", username)
      .add("firstName", firstName)
      .add("lastName", lastName)
      .add("email", email)
      .add("adminRole", adminRole + "")
      .add("fullName", firstName + " " + lastName);
}
```

`fullName`属性仅供方便使用；我们可以在我们的 Ext JS 代码中轻松地创建一个`fullName`字段，它连接`firstName`和`lastName`字段。然而，将这段代码保留在 JSON 生成的源头可以更容易地进行维护。考虑业务变更请求“向`User`实体添加`middleName`字段”。然后，`fullName`包含新的`middleName`字段就变得非常简单，并且可以在不进行任何进一步更改的情况下提供给 Ext JS 客户端。

### 实现 TaskLog addJson 方法

`addJson`方法将所有`TaskLog`字段添加到`builder`实例中。`DATE_FORMAT_yyyyMMdd`常量用于将`taskLogDate`格式化为年/月/日的 8 位表示，并添加到`TaskLog`类中，如下所示：

```java
static final SimpleDateFormat DATE_FORMAT_yyyyMMdd = new SimpleDateFormat("yyyyMMdd");
```

`addJson`方法将使用`SimpleDateFormat`实例来格式化`taskLogDate`字段：

```java
public void addJson(JsonObjectBuilder builder) {

  builder.add("idTaskLog", idTaskLog)
    .add("taskDescription", taskDescription)
    .add("taskLogDate", taskLogDate == null ? "" : DATE_FORMAT_yyyyMMdd.format(taskLogDate))
    .add("taskMinutes", taskMinutes);

  if (user != null) {
    user.addJson(builder);
  }
  if (task != null) {
    task.addJson(builder);            
  }
}
```

`taskLogDate`字段的格式化方式在转换为 Ext JS 客户端的 JavaScript `Date`对象时不会被误解。如果没有使用`SimpleDateFormat`实例，`builder`实例将调用`taskLogDate`对象的默认`toString`方法来检索字符串表示，结果类似于以下内容：

```java
Wed Aug 14 00:00:00 EST 2013
```

使用配置为`yyyyMMdd`日期模式的`SimpleDateFormat`实例将确保这样的日期格式为`20130814`。

### 注意

在企业应用程序中，日期格式化可能会导致许多问题，如果没有采用标准策略。当我们开发应用程序供全球使用，涉及多个时区和不同语言时，这一点更加适用。日期应始终以一种可以在不同语言、时区和用户偏好设置下被解释的方式进行格式化。

## 关于 JSON 的说明

我们将使用 JSON 在 GlassFish 服务器和 Ext JS 客户端之间传输数据。传输是双向的；服务器将向 Ext JS 客户端发送 JSON 数据，而 Ext JS 客户端将以 JSON 格式将数据发送回服务器。服务器和客户端都将消耗*和*生成 JSON 数据。

只要符合规范（[`tools.ietf.org/html/rfc4627`](http://tools.ietf.org/html/rfc4627)），对于构造 JSON 数据没有规则。Ext JS 4 模型允许通过关联使用任何形式的有效 JSON 结构；我们的方法将 JSON 结构保持在其最简单的形式。先前定义的`addJson`方法返回简单的、扁平的数据结构，没有嵌套或数组。例如，`task`实例可以序列化为以下 JSON 对象（包含格式化以便阅读）：

```java
{
    success: true,
    data: {
        "idTask": 1,
        "taskName": "Write Chapter 7",
        "idProject": 1,
        "projectName": "My Book Project",
        "idCompany": 1,
        "companyName": "PACKT Publishing"
    }
}
```

`data`负载表示将被 Ext JS 4 客户端消耗的`task`对象。我们可以定义`task`对象的 JSON 表示如下：

```java
{
    success: true,
    data: {
        "idTask": 1,
        "taskName": "Write Chapter 7",
        "project": {
            "idProject": 1,
            "projectName": "My Book Project ",
            "company": {
                "idCompany": 1,
                "companyName": "PACKT Publishing"
            }
        }
    }
}
```

在这个结构中，我们看到`task`实例属于一个`project`，而`project`又属于一个`company`。这两种 JSON 表示都是合法的；它们都包含相同的`task`数据，以有效的 JSON 格式。然而，这两者中哪一个更容易解析？哪一个更容易调试？作为企业应用程序开发人员，我们应该始终牢记 KISS 原则。**保持简单，愚蠢**（KISS）原则指出，大多数系统如果保持简单，并避免不必要的复杂性，将能够发挥最佳作用。

### 注意

保持你的 JSON 简单！我们知道复杂的结构是可能的；这只是通过在定义 Ext JS 4 模型以及读取或写入 JSON 数据时附加复杂性来实现的。简单的 JSON 结构更容易理解和维护。

# 创建请求处理程序

我们现在将构建用于为我们的 Ext JS 客户端提供 HTTP 请求的处理程序。这些处理程序将被添加到一个新的`web`目录中，如下截图所示：

![创建请求处理程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_07_02.jpg)

每个处理程序都将使用 Spring Framework 的`@Controller`注解来指示该类充当“控制器”的角色。严格来说，我们将要定义的处理程序在传统意义上并不是 Spring MVC 应用程序的控制器。我们只会使用非常小部分可用的 Spring 控制器功能来处理请求。这将确保我们的请求处理层非常轻量且易于维护。和往常一样，我们将首先创建一个所有处理程序都将实现的基类。

## 定义 AbstractHandler 超类

`AbstractHandler`超类定义了几个重要的方法，用于简化 JSON 生成。由于我们正在与 Ext JS 4 客户端集成，我们处理程序生成的 JSON 对象的结构特定于 Ext JS 4 组件期望的数据结构。我们将始终生成一个具有`success`属性的 JSON 对象，该属性包含一个布尔值`true`或`false`。同样，我们将始终生成一个名为`data`的有效负载属性的 JSON 对象。这个`data`属性将具有一个有效的 JSON 对象作为其值，可以是一个简单的 JSON 对象，也可以是一个 JSON 数组。

### 注意

请记住，所有生成的 JSON 对象都将以一种格式呈现，可以被 Ext JS 4 组件消费，而无需额外的配置。

`AbstractHandler`类的定义如下：

```java
package com.gieman.tttracker.web;

import com.gieman.tttracker.domain.JsonItem;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.List;
import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonNumber;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.json.JsonWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractHandler {

    protected final Logger logger = LoggerFactory.getLogger(this.getClass());

    public static String getJsonSuccessData(List<? extends JsonItem> results) {

        final JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("success", true);
        final JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();

        for (JsonItem ji : results) {

            arrayBuilder.add(ji.toJson());
        }

        builder.add("data", arrayBuilder);

        return toJsonString(builder.build());
    }

    public static String getJsonSuccessData(JsonItem jsonItem) {

        final JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("success", true);
        builder.add("data", jsonItem.toJson());

        return toJsonString(builder.build());

    }

    public static String getJsonSuccessData(JsonItem jsonItem, int totalCount) {

        final JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("success", true);
        builder.add("total", totalCount);
        builder.add("data", jsonItem.toJson());

        return toJsonString(builder.build());
    }

    public static String getJsonErrorMsg(String theErrorMessage) {

        return getJsonMsg(theErrorMessage, false);

    }

    public static String getJsonSuccessMsg(String msg) {

        return getJsonMsg(msg, true);
    }
    public static String getJsonMsg(String msg, boolean success) {

        final JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("success", success);
        builder.add("msg", msg);

        return toJsonString(builder.build());

    }

    public static String toJsonString(JsonObject model) {

        final StringWriter stWriter = new StringWriter();

        try (JsonWriter jsonWriter = Json.createWriter(stWriter)) {
            jsonWriter.writeObject(model);
        }

        return stWriter.toString();
    }

    protected JsonObject parseJsonObject(String jsonString) {

        JsonReader reader = Json.createReader(new StringReader(jsonString));
        return reader.readObject();

    }
    protected Integer getIntegerValue(JsonValue jsonValue) {

        Integer value = null;

        switch (jsonValue.getValueType()) {

            case NUMBER:
                JsonNumber num = (JsonNumber) jsonValue;
                value = num.intValue();
                break;
            case NULL:
                break;
        }

        return value;
    }
}
```

重载的`getJsonSuccessData`方法将分别生成一个 JSON 字符串，其中`success`属性设置为`true`，并且包含适当的`data` JSON 有效负载。`getJsonXXXMsg`变体也将生成一个 JSON 字符串，其中包含适当的`success`属性（对于成功的操作为`true`，对于失败的操作为`false`），以及一个包含适当消息的`msg`属性，供 Ext JS 组件使用。

`parseJsonObject`方法将使用`JsonReader`实例将 JSON 字符串解析为`JsonObject`。`toJsonString`方法将使用`JsonWriter`实例将`JsonObject`写入其 JSON 字符串表示。这些类是 Java EE 7 `javax.json`包的一部分，它们使得使用 JSON 非常容易。

`getIntegerValue`方法用于将`JsonValue`对象解析为`Integer`类型。`JsonValue`对象可以是由`javax.json.jsonValue.ValueType`常量定义的几种不同类型，对值进行适当检查后，才尝试将`JsonValue`对象解析为`Integer`。这将允许我们以以下形式从 Ext JS 客户端发送 JSON 数据：

```java
{
    success: true,
    data: {
        "idCompany":null,
        "companyName": "New Company"
    }
}
```

请注意，`idCompany`属性的值为`null`。`getIntegerValue`方法允许我们解析可能为`null`的整数，这是使用默认的`JsonObject.getInt(key)`方法时不可能的（如果遇到`null`值，它会抛出异常）。

现在让我们定义我们的第一个处理程序类，用于处理用户身份验证。

## 定义 SecurityHandler 类

我们首先定义一个简单的辅助类，用于验证用户会话是否处于活动状态：

```java
package com.gieman.tttracker.web;

import com.gieman.tttracker.domain.User;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class SecurityHelper {
    static final String SESSION_ATTRIB_USER = "sessionuser";

    public static User getSessionUser(HttpServletRequest request) {
        User user = null;
        HttpSession session = request.getSession(true);
        Object obj = session.getAttribute(SESSION_ATTRIB_USER);

        if (obj != null && obj instanceof User) {
            user = (User) obj;
        }
        return user;
    }
}
```

静态常量`SESSION_ATTRIB_USER`将被用作保存经过身份验证的用户的会话属性的名称。所有处理程序类将调用`SecurityHelper.getSessionUser`方法从会话中检索经过身份验证的用户。用户会话可能因为不活动而超时，然后 HTTP 会话将被应用服务器移除。当这种情况发生时，`SecurityHelper.getSessionUser`方法将返回`null`，3T 应用程序必须优雅地处理这种情况。

`SecurityHandler`类用于验证用户凭据。如果用户成功验证，`user`对象将使用`SESSION_ATTRIB_USER`属性存储在 HTTP 会话中。用户也可以通过单击**注销**按钮从 3T 应用程序注销。在这种情况下，用户将从会话中移除。

验证和注销功能的实现如下：

```java
package com.gieman.tttracker.web;

import com.gieman.tttracker.domain.User;
import com.gieman.tttracker.service.UserService;
import com.gieman.tttracker.vo.Result;
import static com.gieman.tttracker.web.AbstractHandler.getJsonErrorMsg;
import static com.gieman.tttracker.web.SecurityHelper.SESSION_ATTRIB_USER;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/security")
public class SecurityHandler extends AbstractHandler {

    @Autowired
    protected UserService userService;

    @RequestMapping(value = "/logon", method = RequestMethod.POST, produces = {"application/json"})
    @ResponseBody
    public String logon(
            @RequestParam(value = "username", required = true) String username,
            @RequestParam(value = "password", required = true) String password,
            HttpServletRequest request) {

        Result<User> ar = userService.findByUsernamePassword(username, password);

        if (ar.isSuccess()) {
            User user = ar.getData();
            HttpSession session = request.getSession(true);
            session.setAttribute(SESSION_ATTRIB_USER, user);            
            return getJsonSuccessData(user);
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }

    @RequestMapping(value = "/logout", produces = {"application/json"})
    @ResponseBody
    public String logout(HttpServletRequest request) {

        HttpSession session = request.getSession(true);
        session.removeAttribute(SESSION_ATTRIB_USER);
        return getJsonSuccessMsg("User logged out...");
    }
}
```

`SecurityHandler`类引入了许多新的 Spring 注解和概念，需要详细解释。

### @Controller 和@RequestMapping 注解

`@Controller`注解表示这个类充当 Spring 控制器的角色。由`@Controller`注释的类将被 Spring 组件扫描自动检测到，其配置在本章后面定义。但是控制器到底是什么？

Spring 控制器是 Spring MVC 框架的一部分，通常与模型和视图一起处理请求。我们既不需要模型也不需要视图；事实上，我们的处理生命周期完全由控制器本身管理。每个控制器负责一个 URL 映射，如类级`@RequestMapping`注释中定义的。这个映射将 URL 路径映射到控制器。在我们的 3T 应用程序中，任何以`/security/`开头的 URL 将被定向到`SecurityHandler`类进行进一步处理。然后将使用任何子路径来匹配方法级`@RequestMapping`注释。我们定义了两种方法，每种方法都有自己独特的映射。这导致以下 URL 路径到方法的映射：

+   `/security/logon`将映射到`logon`方法

+   `/security/logout`将映射到`logout`方法

任何其他以`/security/`开头的 URL 都不会匹配已定义的方法，并且会产生`404`错误。

方法的名称并不重要；重要的是`@RequestMapping`注释定义了用于处理请求的方法。

在`logon`的`@RequestMapping`注释中定义了两个额外的属性。`method=RequestMethod.POST`属性指定了`/security/logon`登录请求 URL 必须以`POST`请求提交。如果对`/security/logon`提交使用了其他请求类型，将返回`404`错误。Ext JS 4 使用 AJAX 存储和模型默认提交`POST`请求。然而，读取数据的操作将使用`GET`请求提交，除非另有配置。在 RESTful web 服务中使用的其他可能方法包括`PUT`和`DELETE`，但我们只会在我们的应用程序中定义`GET`和`POST`请求。

### 注意

确保每个`@RequestMapping`方法都有适当的`RequestMethod`定义被认为是最佳实践。修改数据的操作应始终使用`POST`请求提交。持有敏感数据（例如密码）的操作也应使用`POST`请求提交，以确保数据不以 URL 编码格式发送。根据您的应用程序需求，读取操作可以作为`GET`或`POST`请求发送。

`produces = {"application/json"}`属性定义了映射请求的可生产媒体类型。我们所有的请求都将生成具有`application/json`媒体类型的 JSON 数据。每个由浏览器提交的 HTTP 请求都有一个`Accept`头，例如：

```java
text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
```

如果`Accept`请求不包括`produces`属性媒体类型，则 GlassFish 4 服务器将返回以下`406 Not Acceptable`错误：

```java
The resource identified by this request is only capable of generating responses with characteristics not acceptable according to the request "accept" headers.
```

所有现代浏览器都将接受`application/json`内容类型。

### @ResponseBody 注释

Spring 使用此注释来标识应直接将内容返回到 HTTP 响应输出流的方法（不放置在模型中或解释为视图名称，这是默认的 Spring MVC 行为）。实现这一点将取决于方法的返回类型。我们所有的请求处理方法都将返回 Java 字符串，Spring 将在内部使用`StringHttpMessageConverter`实例将字符串写入 HTTP 响应输出流，并使用值为`text/plain`的`Content-Type`。这是将 JSON 数据对象字符串返回给 HTTP 客户端的一种非常简单的方法，因此使得请求处理成为一个微不足道的过程。

### @RequestParam 注释

此方法参数上的注释将请求参数映射到参数本身。在`logon`方法中，我们有以下定义：

```java
@RequestParam(value = "username", required = true) String username,
@RequestParam(value = "password", required = true) String password,
```

假设`logon`方法是`GET`类型（在`SecurityHandler`类中设置为`POST`，因此以下 URL 编码将无法工作），例如以下 URL 将调用具有`username`值为`bjones`和`password`值为`admin`的方法：

`/security/logon.json?username=bjones&password=admin`

我们也可以用以下定义来编写这个方法：

```java
@RequestParam(value = "user", required = true) String username,
@RequestParam(value = "pwd", required = true) String password,
```

然后将映射以下形式的 URL：

`/security/logon.json?user=bjones&pwd=admin`

请注意，`@RequestParam`注解的`value`属性映射到请求参数名称。

`@RequestParam`注解的`required`属性定义了该参数是否为必填字段。以下 URL 将导致异常：

`/security/logon.json?username=bjones`

显然缺少密码参数，这不符合`required=true`的定义。

请注意，`required=true`属性仅检查是否存在与`@RequestParam`注解的`value`匹配的请求参数。请求参数为空是完全有效的。以下 URL 不会引发异常：

`/security/logon.json?username=bjones&password=`

可选参数可以通过使用`required=false`属性进行定义，也可以包括`defaultValue`。考虑以下方法参数：

```java
@RequestParam(value = "address", required = false, defaultValue = "Unknown address") String address
```

还考虑以下三个 URL：

+   `/user/address.json?address=Melbourne`

+   `/user/address.json?address=`

+   `/user/address.json?`

第一个 URL 将导致地址值为`墨尔本`，第二个 URL 将具有空地址，第三个 URL 将具有“未知地址”。请注意，仅当请求没有有效的地址参数时，`defaultValue`才会被使用，而不是地址参数为空时。

### 认证用户

我们的`SecurityHandler`类中的`logon`方法非常简单，这要归功于我们对服务层业务逻辑的实现。我们调用`userService.findByUsernamePassword(username, password)`方法并检查返回的`Result`。如果`Result`成功，`SecurityHandler.logon`方法将返回经过身份验证的用户的 JSON 表示。这是通过`getJsonSuccessData(user)`这一行实现的，它将导致以下输出被写入 HTTP 响应：

```java
{
    "success": true,
    "data": {
        "username": "bjones",
        "firstName": "Betty",
        "lastName": "Jones",
        "email": "bj@tttracker.com",
        "adminRole": "Y",
        "fullName": "Betty Jones"
    }
}
```

请注意，上述格式仅用于可读性。实际响应将是一系列字符。然后将经过身份验证的用户添加到具有属性`SESSION_ATTRIB_USER`的 HTTP 会话中。然后，我们可以通过在我们的请求处理程序中调用`SecurityHelper.getSessionUser(request)`来识别经过身份验证的用户。

失败的`Result`实例将调用`getJsonErrorMsg(ar.getMsg())`方法，这将导致在 HTTP 响应中返回以下 JSON 对象：

```java
{
    "success": false,
    "msg": "Unable to verify user/password combination!"
}
```

`msg`文本在`UserServiceImpl.findByUsernamePassword`方法中设置在`Result`实例上。根据`success`属性，Ext JS 前端将以不同方式处理每个结果。

### 登出

此方法中的逻辑非常简单：从会话中删除用户并返回成功的 JSON 消息。由于没有在`@RequestMapping`注解中定义`RequestMethod`，因此可以使用任何`RequestMethod`来映射此 URL（`GET`，`POST`等）。从此方法返回的 JSON 对象如下：

```java
{
    "success": true,
    "msg": "User logged out..."
}
```

## 定义 CompanyHandler 类

此处理程序处理公司操作，并映射到`/company/` URL 模式。

```java
package com.gieman.tttracker.web;

import com.gieman.tttracker.domain.*;
import com.gieman.tttracker.service.CompanyService;
import com.gieman.tttracker.service.ProjectService;

import com.gieman.tttracker.vo.Result;
import static com.gieman.tttracker.web.SecurityHelper.getSessionUser;

import java.util.List;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/company")
public class CompanyHandler extends AbstractHandler {

    @Autowired
    protected CompanyService companyService;
    @Autowired
    protected ProjectService projectService;
    @RequestMapping(value = "/find", method = RequestMethod.GET, produces = {"application/json"})
    @ResponseBody
    public String find(
            @RequestParam(value = "idCompany", required = true) Integer idCompany,
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);
        if (sessionUser == null) {
            return getJsonErrorMsg("User is not logged on");
        }

        Result<Company> ar = companyService.find(idCompany, sessionUser.getUsername());

        if (ar.isSuccess()) {

            return getJsonSuccessData(ar.getData());

        } else {

            return getJsonErrorMsg(ar.getMsg());

        }
    }

    @RequestMapping(value = "/store", method = RequestMethod.POST, produces = {"application/json"})
    @ResponseBody
    public String store(
            @RequestParam(value = "data", required = true) String jsonData,
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);
        if (sessionUser == null) {
            return getJsonErrorMsg("User is not logged on");
        }

        JsonObject jsonObj = parseJsonObject(jsonData);

        Result<Company> ar = companyService.store(
                getIntegerValue(jsonObj.get("idCompany")), 
                jsonObj.getString("companyName"), 
                sessionUser.getUsername());

        if (ar.isSuccess()) {

            return getJsonSuccessData(ar.getData());

        } else {

            return getJsonErrorMsg(ar.getMsg());

        }
    }

    @RequestMapping(value = "/findAll", method = RequestMethod.GET, produces = {"application/json"})
    @ResponseBody
    public String findAll(HttpServletRequest request) {

        User sessionUser = getSessionUser(request);
        if (sessionUser == null) {
            return getJsonErrorMsg("User is not logged on");
        }

        Result<List<Company>> ar = companyService.findAll(sessionUser.getUsername());

        if (ar.isSuccess()) {

            return getJsonSuccessData(ar.getData());

        } else {

            return getJsonErrorMsg(ar.getMsg());

        }
    }

    @RequestMapping(value = "/remove", method = RequestMethod.POST, produces = {"application/json"})
    @ResponseBody
    public String remove(
            @RequestParam(value = "data", required = true) String jsonData,
            HttpServletRequest request) {
        User sessionUser = getSessionUser(request);
        if (sessionUser == null) {
            return getJsonErrorMsg("User is not logged on");
        }

        JsonObject jsonObj = parseJsonObject(jsonData);

        Result<Company> ar = companyService.remove(
                getIntegerValue(jsonObj.get("idCompany")), 
                sessionUser.getUsername());

        if (ar.isSuccess()) {

            return getJsonSuccessMsg(ar.getMsg());

        } else {

            return getJsonErrorMsg(ar.getMsg());

        }
    }
}
```

每个方法都根据方法级`@RequestMapping`注解定义的不同子 URL 进行映射。因此，`CompanyHandler`类将映射到以下 URL：

+   `/company/find`将使用`GET`请求将其映射到`find`方法

+   `/company/store`将使用`POST`请求将其映射到`store`方法

+   `/company/findAll`将使用`GET`请求将其映射到`findAll`方法

+   `/company/remove`将使用`POST`请求将其映射到`remove`方法

以下是一些需要注意的事项：

+   每个处理程序方法都使用`RequestMethod.POST`或`RequestMethod.GET`进行定义。`GET`方法用于查找方法，`POST`方法用于修改数据的方法。这些方法类型是 Ext JS 用于每个操作的默认值。

+   每个方法通过调用`getSessionUser(request)`从 HTTP 会话中检索用户，然后测试`user`值是否为`null`。如果用户不在会话中，则在 JSON 编码的 HTTP 响应中返回消息"`用户未登录`"。

+   `POST`方法具有一个保存 Ext JS 客户端提交的 JSON 数据的请求参数。然后在使用所需参数调用适当的服务层方法之前，将此 JSON 字符串解析为`JsonObject`。

添加新公司的典型 JSON 数据有效负载如下：

```java
{"idCompany":null,"companyName":"New Company"}
```

请注意，`idCompany`值为`null`。如果要修改现有公司记录，则 JSON 数据有效负载必须包含有效的`idCompany`值：

```java
{"idCompany":5,"companyName":"Existing Company"}
```

还要注意，JSON 数据仅包含一个公司记录。可以配置 Ext JS 客户端通过提交类似以下数组的 JSON 数组来提交每个请求的多个记录：

```java
[
  {"idCompany":5,"companyName":"Existing Company"},
  {"idCompany":4,"companyName":"Another Existing Company"}
]
```

但是，我们将限制我们的逻辑以处理每个请求的单个记录。

## 定义 ProjectHandler 类

`ProjectHandler`类处理项目操作，并将其映射到`/project/` URL 模式如下：

```java
package com.gieman.tttracker.web;

import com.gieman.tttracker.domain.*;
import com.gieman.tttracker.service.ProjectService;
import com.gieman.tttracker.vo.Result;
import static com.gieman.tttracker.web.SecurityHelper.getSessionUser;

import java.util.List;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/project")
public class ProjectHandler extends AbstractHandler {

    @Autowired
    protected ProjectService projectService;

    @RequestMapping(value = "/find", method = RequestMethod.GET, produces = {"application/json"})
    @ResponseBody
    public String find(
            @RequestParam(value = "idProject", required = true) Integer idProject,
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);
        if (sessionUser == null) {
            return getJsonErrorMsg("User is not logged on");
        }

        Result<Project> ar = projectService.find(idProject, sessionUser.getUsername());

        if (ar.isSuccess()) {
            return getJsonSuccessData(ar.getData());
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }

    @RequestMapping(value = "/store", method = RequestMethod.POST, produces = {"application/json"})
    @ResponseBody
    public String store(
            @RequestParam(value = "data", required = true) String jsonData,
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);
        if (sessionUser == null) {
            return getJsonErrorMsg("User is not logged on");
        }
        JsonObject jsonObj = parseJsonObject(jsonData);

        Result<Project> ar = projectService.store(
                getIntegerValue(jsonObj.get("idProject")),
                getIntegerValue(jsonObj.get("idCompany")),
                jsonObj.getString("projectName"),
                sessionUser.getUsername());

        if (ar.isSuccess()) {
            return getJsonSuccessData(ar.getData());
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }

    @RequestMapping(value = "/remove", method = RequestMethod.POST, produces = {"application/json"})
    @ResponseBody
    public String remove(
            @RequestParam(value = "data", required = true) String jsonData,
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);
        if (sessionUser == null) {
            return getJsonErrorMsg("User is not logged on");
        }

        JsonObject jsonObj = parseJsonObject(jsonData);

        Result<Project> ar = projectService.remove(
                getIntegerValue(jsonObj.get("idProject")), 
                sessionUser.getUsername());

        if (ar.isSuccess()) {
            return getJsonSuccessMsg(ar.getMsg());
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }

    @RequestMapping(value = "/findAll", method = RequestMethod.GET, produces = {"application/json"})
    @ResponseBody
    public String findAll(
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);
        if (sessionUser == null) {
            return getJsonErrorMsg("User is not logged on");
        }

        Result<List<Project>> ar = projectService.findAll(sessionUser.getUsername());

        if (ar.isSuccess()) {
            return getJsonSuccessData(ar.getData());
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }
}
```

`ProjectHandler`类将被映射到以下 URL：

+   `/project/find`将使用`GET`请求映射到`find`方法

+   `/project/store`将使用`POST`请求映射到`store`方法

+   `/project/findAll`将使用`GET`请求映射到`findAll`方法

+   `/project/remove`将使用`POST`请求映射到`remove`方法

请注意，在`store`方法中，我们再次从解析的`JsonObject`中检索所需的数据。添加新项目时，JSON`data`有效负载的结构如下：

```java
{"idProject":null,"projectName":"New Project","idCompany":1}
```

更新现有项目时，JSON 结构如下：

```java
{"idProject":7,"projectName":"Existing Project with ID=7","idCompany":1}
```

您还会注意到，我们在每个方法中再次复制了相同的代码块，就像在`CompanyHandler`类中一样：

```java
if (sessionUser == null) {
  return getJsonErrorMsg("User is not logged on");
}
```

每个剩余处理程序中的每个方法也将需要相同的检查；用户*必须*在会话中才能执行操作。这正是为什么我们将通过引入 Spring 请求处理程序拦截器的概念来简化我们的代码。

# Spring HandlerInterceptor 接口

Spring 的请求处理映射机制包括使用处理程序拦截器拦截请求的能力。这些拦截器用于对请求应用某种功能，例如我们的示例中检查用户是否在会话中。拦截器必须实现`org.springframework.web.servlet`包中的`HandlerInterceptor`接口，可以通过以下三种方式应用功能：

+   在实现`preHandle`方法之前执行处理程序方法

+   通过实现`postHandle`方法执行处理程序方法后

+   通过实现`afterCompletion`方法执行完整请求后

通常使用`HandlerInterceptorAdapter`抽象类以及每个方法的预定义空实现来实现自定义处理程序。我们的`UserInSessionInterceptor`类定义如下：

```java
package com.gieman.tttracker.web;

import com.gieman.tttracker.domain.User;
import static com.gieman.tttracker.web.SecurityHelper.getSessionUser;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter;

public class UserInSessionInterceptor extends HandlerInterceptorAdapter {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {

        logger.info("calling preHandle with url=" + request.getRequestURI());

        User sessionUser = getSessionUser(request);

        if (sessionUser == null) {
            String json = "{\"success\":false,\"msg\":\"A valid user is not logged on!\"}";
            response.getOutputStream().write(json.getBytes());
            return false;
        } else {
            return true;
        }
    }
}
```

当使用`UserInSessionInterceptor`拦截请求时，`preHandle`方法中的代码检查是否有用户在会话中。如果找到`sessionUser`，处理程序将返回`true`，表示应继续正常处理。正常处理可能导致调用其他处理程序拦截器（如果已配置），最终到达映射的处理程序方法之前。

如果未找到`sessionUser`，则立即向响应输出流发送一个简单的 JSON 字符串。然后，`preHandle`方法返回`false`，表示拦截器已经处理了响应，不需要进一步处理。

通过将`UserInSessionInterceptor`应用于需要用户会话测试的每个请求，我们可以从每个处理程序方法中删除以下代码：

```java
if (sessionUser == null) {
  return getJsonErrorMsg("User is not logged on");
}
```

我们如何将拦截器应用于适当的处理程序方法？这是在我们自定义 Spring MVC 配置时完成的。

# Spring MVC 配置

Spring MVC 框架可以使用 XML 文件或 Java 配置类进行配置。我们将使用 Spring MVC 配置类来配置我们的应用程序，首先是`WebAppConfig`类：

```java
package com.gieman.tttracker.web;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@EnableWebMvc
@Configuration
@ComponentScan("com.gieman.tttracker.web")
public class WebAppConfig extends WebMvcConfigurerAdapter {

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new UserInSessionInterceptor())
                .addPathPatterns(new String[]{
                    "/**"
                }).excludePathPatterns("/security/**");
    }
}
```

`WebAppConfig`类扩展了`WebMvcConfigurerAdapter`，这是一个方便的基类，为`WebMvcConfigurer`接口的每个方法提供了空实现。我们重写`addInterceptors`方法来注册我们的`UserInSessionInterceptor`并定义将用于应用拦截器的处理程序映射。路径模式`/**`将拦截*所有*映射，我们从中*排除*`/security/**`映射。安全映射*不*应包含用户会话检查，因为用户尚未经过身份验证并且不会在会话中。

`@ComponentScan("com.gieman.tttracker.web")`注解将触发对`com.gieman.tttracker.web`包中`@Controller`注释类的扫描。然后，Spring 将识别和加载我们的处理程序类。`@EnableWebMvc`注解将此类标识为 Spring Web MVC 配置类。此注释导致 Spring 加载所需的`WebMvcConfigurationSupport`配置属性。剩下的`@Configuration`注解在 Spring 应用程序启动期间将此类标识为组件扫描的候选类。然后，`WebAppConfig`类将自动加载以在 Spring MVC 容器中使用。

`WebAppConfig`类配置了 MVC 环境；`WebApp`类配置了`servlet`容器：

```java
package com.gieman.tttracker.web;

import org.springframework.web.servlet.support.AbstractAnnotationConfigDispatcherServletInitializer;

public class WebApp extends AbstractAnnotationConfigDispatcherServletInitializer {

    @Override 
    protected String[] getServletMappings() {
        return new String[]{
            "/ttt/*"
        };
    }

    @Override
    protected Class<?>[] getRootConfigClasses() {
        return new Class<?>[0];
    }

    @Override
    protected Class<?>[] getServletConfigClasses() {
        return new Class<?>[]{WebAppConfig.class};
    }
}
```

`AbstractAnnotationConfigDispatcherServletInitializer`类在 Spring 3.2 中作为`WebApplicationInitializer`实现的基类引入。这些实现注册使用`WebAppConfig`类中定义的注释类配置的`DispatcherServlet`（请注意，此类在`getServletConfigClasses`方法中返回）。

感兴趣的最终配置项是`getServletMappings`方法，它将传入的请求映射到通过`@ComponentScan`注解发现的`WebAppConfig`处理程序集。我们应用程序中以`/ttt/`开头的每个 URL 都将被定向到适当的请求处理程序进行处理。从 Ext JS 4 客户端提交的一些示例 URL 可能包括以下内容：

+   `/ttt/company/findAll.json`将映射到`CompanyHandler.findAll`方法

+   `/ttt/project/find.json?idProject=5`将映射到`ProjectHandler.find`方法

请注意，URL 中的`/ttt/`前缀定义了我们 Spring MVC 组件的*入口点*。不以`/ttt/`开头的 URL 将*不*由 Spring MVC 容器处理。

我们现在将实现一个处理程序来介绍 Spring 控制器中的数据绑定。

# 定义`TaskLogHandler`类

`TaskLogHandler`类处理任务日志操作，并映射到`/taskLog/` URL 模式：

```java
package com.gieman.tttracker.web;

import com.gieman.tttracker.domain.*;
import com.gieman.tttracker.service.TaskLogService;
import com.gieman.tttracker.vo.Result;
import static com.gieman.tttracker.web.SecurityHelper.getSessionUser;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.List;
import javax.json.JsonObject;
import javax.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.propertyeditors.CustomDateEditor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/taskLog")
public class TaskLogHandler extends AbstractHandler {

    static final SimpleDateFormat DATE_FORMAT_yyyyMMdd = new SimpleDateFormat("yyyyMMdd");

    @Autowired
    protected TaskLogService taskLogService;
    @InitBinder
    public void initBinder(WebDataBinder binder) {

        binder.registerCustomEditor(Date.class, new CustomDateEditor(DATE_FORMAT_yyyyMMdd, true));

    }

    @RequestMapping(value="/find", method = RequestMethod.GET, produces = {"application/json"})
    @ResponseBody
    public String find(
            @RequestParam(value = "idTaskLog", required = true) Integer idTaskLog,
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);

        Result<TaskLog> ar = taskLogService.find(idTaskLog, sessionUser.getUsername());

        if (ar.isSuccess()) {
            return getJsonSuccessData(ar.getData());
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }
    @RequestMapping(value = "/store", method = RequestMethod.POST, produces = {"application/json"})
    @ResponseBody
    public String store(
            @RequestParam(value = "data", required = true) String jsonData,
            HttpServletRequest request) throws ParseException {

        User sessionUser = getSessionUser(request);

        JsonObject jsonObj = parseJsonObject(jsonData);

        String dateVal = jsonObj.getString("taskLogDate");

        Result<TaskLog> ar = taskLogService.store(
                getIntegerValue(jsonObj.get("idTaskLog")),
                getIntegerValue(jsonObj.get("idTask")),
                jsonObj.getString("username"),
                jsonObj.getString("taskDescription"),
                DATE_FORMAT_yyyyMMdd.parse(dateVal),
                jsonObj.getInt("taskMinutes"),
                sessionUser.getUsername());

        if (ar.isSuccess()) {
            return getJsonSuccessData(ar.getData());
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }

    @RequestMapping(value = "/remove", method = RequestMethod.POST, produces = {"application/json"})
    @ResponseBody
    public String remove(
            @RequestParam(value = "data", required = true) String jsonData,
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);

        JsonObject jsonObj = parseJsonObject(jsonData);

        Result<TaskLog> ar = taskLogService.remove(
                getIntegerValue(jsonObj.get("idTaskLog")), 
                sessionUser.getUsername());
        if (ar.isSuccess()) {
            return getJsonSuccessMsg(ar.getMsg());
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }

    @RequestMapping(value = "/findByUser", method = RequestMethod.GET, produces = {"application/json"})
    @ResponseBody
    public String findByUser(
            @RequestParam(value = "username", required = true) String username,
            @RequestParam(value = "startDate", required = true) Date startDate,
            @RequestParam(value = "endDate", required = true) Date endDate,
            HttpServletRequest request) {

        User sessionUser = getSessionUser(request);

        Result<List<TaskLog>> ar = taskLogService.findByUser(
                username,
                startDate,
                endDate,
                sessionUser.getUsername());

        if (ar.isSuccess()) {
            return getJsonSuccessData(ar.getData());
        } else {
            return getJsonErrorMsg(ar.getMsg());
        }
    }
 }
```

因此，`TaskLogHandler`类将映射到以下 URL：

+   `/taskLog/find`将使用`GET`请求映射到`find`方法

+   `/taskLog/store`将使用`POST`请求映射到`store`方法

+   `/taskLog/findByUser`将使用`GET`请求映射到`findByUser`方法

+   `/taskLog/remove`将使用`POST`请求映射到`remove`方法

我们还引入了一个新的注解：`@InitBinder`注解。

## `@InitBinder`注解

`@InitBinder`注解用于将方法标记为“数据绑定感知”。该方法使用编辑器初始化`WebDataBinder`对象，这些编辑器用于将 String 参数转换为它们的 Java 等效形式。这种转换最常见的需求是日期的情况。

日期可以用许多不同的方式表示。以下所有日期都是等效的：

+   06-Dec-2013

+   2013 年 12 月 6 日

+   06-12-2013（英国日期，简写形式）

+   12-06-2013（美国日期，简写形式）

+   06-Dez-2013（德国日期）

+   2013 年 12 月 6 日

通过 HTTP 请求发送日期表示可能会令人困惑！我们都了解这些日期大部分代表什么，但是如何将这些日期转换为 `java.util.Date` 对象呢？这就是 `@InitBinder` 方法的用途。指定所需日期格式的代码涉及为 `Date` 类注册 `CustomDateEditor` 构造函数：

```java
binder.registerCustomEditor(Date.class, new CustomDateEditor(DATE_FORMAT_yyyyMMdd, true));
```

这将允许 Spring 使用 `DATE_FORMAT_yyyyMMdd` 实例来解析客户端以 `yyyyMMdd` 格式发送的日期。以下 URL 现在将正确转换为 `findByUser` 方法所需的参数：

`/taskLog/findByUser?username=bjones&startDate=20130719&endDate=20130812`

`CustomDateEditor` 构造函数中的 `true` 参数确保空日期被赋予值 `null`。

# 更多关于 Spring MVC

我们的处理程序方法和 Spring MVC 实现仅使用了 Spring MVC 框架的一小部分。在这一章节中未涵盖到的真实应用程序可能遇到的情景包括以下要求：

+   URI 模板模式用于通过路径变量访问 URL 的部分。它们特别有用于简化 RESTful 处理，并允许处理程序方法访问 URL 模式中的变量。公司 `find` 方法可以映射到诸如 `/company/find/5/` 的 URL，其中 `5` 代表 `idCompany` 的值。这是通过使用 `@PathVariable` 注解和形式为 `/company/find/{idCompany}` 的映射来实现的。

+   使用 `@SessionAttrribute` 注解在请求之间在 HTTP 会话中存储数据。

+   使用 `@CookieValue` 注解将 cookie 值映射到方法参数，以便将其绑定到 HTTP cookie 的值。

+   使用 `@RequestHeader` 注解将请求头属性映射到方法参数，以便将其绑定到请求头。

+   异步请求处理允许释放主 Servlet 容器线程并允许处理其他请求。

+   将 Spring MVC 与 Spring Security 集成（强烈推荐企业应用程序）。

+   解析多部分请求以允许用户从 HTML 表单上传文件。

应该考虑使用 Spring MVC 测试框架测试处理程序类。有关更多信息，请参阅[`docs.spring.io/spring/docs/3.2.x/spring-framework-reference/html/testing.html#spring-mvc-test-framework`](http://docs.spring.io/spring/docs/3.2.x/spring-framework-reference/html/testing.html#spring-mvc-test-framework)的全面指南。该框架提供了用于测试客户端和服务器端 Spring MVC 应用程序的 JUnit 支持。

Spring MVC 框架远不止一个章节能够涵盖的内容。我们建议用户从[`docs.spring.io/spring/docs/3.2.x/spring-framework-reference/html/mvc.html`](http://docs.spring.io/spring/docs/3.2.x/spring-framework-reference/html/mvc.html)这个在线资源中了解更多关于 Spring MVC 功能的信息。

# 练习

实现 `UserHandler` 和 `TaskHandler` 类，将请求映射到以下方法：

+   `/task/find` 将使用 `GET` 请求映射到 `TaskHandler.find` 方法

+   `/task/store` 将使用 `POST` 请求映射到 `TaskHandler.store` 方法

+   `/task/findAll` 将使用 `GET` 请求映射到 `TaskHandler.findAll` 方法

+   `/task/remove` 将使用 `POST` 请求映射到 `TaskHandler.remove` 方法

+   `/user/find` 将使用 `GET` 请求映射到 `UserHandler.find` 方法

+   `/user/store` 将使用 `POST` 请求映射到 `UserHandler.store` 方法

+   `/user/findAll` 将使用 `GET` 请求映射到 `UserHandler.findAll` 方法

+   `/user/remove` 将使用 `POST` 请求映射到 `UserHandler.remove` 方法

# 总结

我们的 Java Web 界面现在已经完成 - 我们已经创建了一个针对 Ext JS 4 客户端进行了优化的完全功能的请求处理层。HTTP 客户端可访问的 URL 通过类和方法级别的`@RequestMapping`注解映射到请求处理类。每个处理程序方法通过明确定义的接口与服务层交互，并在返回 HTTP 响应中的 JSON 数据之前处理`Result`数据传输对象。我们已经使用 Java 配置类配置了 Spring Web MVC 容器，并实现了一个 Spring 拦截器来检查用户是否已经经过身份验证。

在第八章中，“在 GlassFish 上运行 3T”，我们将完成我们的 Spring 配置，并在 GlassFish 4 服务器上部署 3T 应用程序。然后，我们应用程序堆栈中的每个层将准备好在为 Ext JS 4 客户端请求提供服务时发挥其作用。


# 第八章：在 GlassFish 上运行 3T

在本章中，我们将在 GlassFish 4 服务器上部署我们的 3T 应用程序。成功的部署将需要几个新的配置文件，以及对现有文件的更新。您可能已经熟悉一些来自第五章中定义的测试配置文件，但还会介绍一些特定于 GlassFish 的新文件。

我们还将配置 GlassFish 服务器，使其能够独立于 NetBeans IDE 运行。企业环境通常会有许多在不同主机上运行的 GlassFish 服务器实例。了解基本的 GlassFish 配置是一项重要的技能，我们将详细介绍连接池配置。

在本章的结尾，您将能够看到基于您在《第七章》中精心映射的 URL 的动态 HTTP 响应，*Web 请求处理层*。

# 配置 3T Web 应用程序

Web 应用程序配置需要几个新文件，需要将这些文件添加到`WEB-INF`目录中，如下截图所示。现在创建这些文件：

![配置 3T Web 应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_01.jpg)

请注意，`beans.xml`文件是由 NetBeans 创建的，但不是我们配置所必需的。现在让我们详细查看这些文件。

## Spring applicationContext.xml 文件

`applicationContext.xml`文件配置 Spring 容器，与我们在第五章中创建的`testingContext.xml`文件非常相似。文件的内容如下：

```java
<?xml version="1.0" encoding="UTF-8"?>
<beans 

  xsi:schemaLocation="
      http://www.springframework.org/schema/beans
      http://www.springframework.org/schema/beans/spring-beans-3.2.xsd
  http://www.springframework.org/schema/context
  http://www.springframework.org/schema/context/spring-context-3.2.xsd
  http://www.springframework.org/schema/tx
  http://www.springframework.org/schema/tx/spring-tx-3.2.xsd">
    <bean id="loadTimeWeaver" 
class="org.springframework.instrument.classloading.glassfish.GlassFishLoadTimeWeaver" />
    <bean id="entityManagerFactory" 
        p:persistenceUnitName="tttPU"
class="org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean" 
    />

    <!-- Transaction manager for JTA  -->
    <tx:jta-transaction-manager />
    <!-- enable the configuration of transactional behavior based on annotations -->
    <tx:annotation-driven />

    <!-- checks for @Autowired beans -->
    <context:annotation-config/>    

    <!-- Scan for Repository/Service annotations -->
    <context:component-scan base-package="com.gieman.tttracker.dao"/>
    <context:component-scan base-package="com.gieman.tttracker.service"/>
</beans>
```

此文件用于 Spring 初始化和配置 JPA `EntityManagerFactory`和`TransactionManager` DAO 和 Service 层对象。将`applicationContext.xml`文件与`testingContext.xml`文件进行比较，可以确定简单 Java 容器和企业应用服务器提供的 Java EE 容器之间的关键差异：

+   数据源通过**JNDI**（**Java 命名和目录接口**）从 GlassFish 应用服务器中检索，并且不是由 Spring 在`applicationContext.xml`文件中创建或管理。`persistence.xml`文件中的 JNDI 配置设置在本章后面定义。

+   加载时间织入器是特定于 GlassFish 的。

+   事务管理器是基于**JTA**（**Java 事务 API**）的，并由 GlassFish 服务器提供。它不是由 Spring 创建或管理的。`<tx:jta-transaction-manager />`和`<tx:annotation-driven />`定义是配置 Spring 容器内的事务行为所需的全部内容。

### 注意

您应该熟悉剩余的配置属性。请注意，组件扫描针对`dao`和`service`包执行，以确保在这些类中自动装配 Spring bean。

当 Spring 容器加载`applicationContext.xml`文件时，第七章中定义的 MVC 配置类会通过类路径扫描自动发现，并加载以配置 Web 应用程序组件。

## web.xml 文件

`web.xml` Web 应用程序部署描述符文件代表 Java Web 应用程序的配置。它用于配置 Servlet 容器并将 URL 映射到每个配置的 Servlet。每个 Java Web 应用程序在 Web 应用程序根目录的`WEB-INF`目录中必须有一个`web.xml`。

3T Web 应用程序需要以下`web.xml`定义：

```java
<?xml version="1.0" encoding="UTF-8"?>
<web-app version="3.0"   xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_3_0.xsd">
    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>/WEB-INF/applicationContext.xml</param-value>
    </context-param>
    <listener>
        <listener-class>
            org.springframework.web.context.ContextLoaderListener
        </listener-class>
    </listener>
    <session-config>
        <session-timeout>30</session-timeout>
        <cookie-config>
            <name>JSESSIONID_3T</name>
        </cookie-config>
    </session-config>
    <welcome-file-list>
        <welcome-file>index.html</welcome-file>
    </welcome-file-list>
</web-app>
```

以下是一些关键点：

+   定义`contextConfigLocation`值的`context-param`元素是可选的，如果 Spring 配置文件命名为`applicationContext.xml`（如果未提供，则这是预期的默认文件名）。但是，为了完整起见，我们总是包括此属性。它定义了主 Spring 配置文件的位置。

+   使用类`org.springframework.web.context.ContextLoaderListener`的监听器由 Spring 用于初始化加载应用程序上下文。这是启动 Spring 容器的入口点，并尝试加载`contextConfigLocation`文件。如果无法解析或无效，则会抛出异常。

+   `session-config`属性定义会话超时（30 分钟的不活动时间）和会话 cookie 名称。

+   `welcome-file-list`标识 GlassFish 将提供的文件，如果在 URL 中未明确指定。

## glassfish-web.xml 文件

`glassfish-web.xml`文件配置 GlassFish 与 GlassFish 服务器特定的其他 Web 应用程序属性：

```java
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE glassfish-web-app PUBLIC "-//GlassFish.org//DTD GlassFish Application Server 3.1 Servlet 3.0//EN" "http://glassfish.org/dtds/glassfish-web-app_3_0-1.dtd">
<glassfish-web-app>
<context-root>/</context-root>
</glassfish-web-app>
```

`context-root`属性标识部署的 Web 应用程序的服务器路径。我们将 3T 应用程序部署到服务器的上下文根。这意味着 3T 请求处理程序可以直接从 Web 应用程序的根目录访问，如下例所示：

`/ttt/company/findAll.json`

将`context-root`属性更改为`/mylocation`，例如，将需要以下格式的 URL：

`/mylocation/ttt/company/findAll.json`

# 配置 Maven 的 pom.xml 文件

在前几章中尝试依赖项和插件时，可能已更改了各种`pom.xml`设置。现在重访此文件并确认构建和部署项目的属性是否正确非常重要。您应该具有以下基本的`pom.xml`配置：

```java
<?xml version="1.0" encoding="UTF-8"?>
<project   xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.gieman</groupId>
    <artifactId>task-time-tracker</artifactId>
    <version>1.0</version>
    <packaging>war</packaging>
    <name>task-time-tracker</name>
    <properties>
        <endorsed.dir>
            ${project.build.directory}/endorsed
        </endorsed.dir>
        <project.build.sourceEncoding>
            UTF-8
        </project.build.sourceEncoding>
        <spring.version>3.2.4.RELEASE</spring.version>
        <logback.version>1.0.13</logback.version>
    </properties>
    <dependencies>
        <dependency>
            <groupId>org.eclipse.persistence</groupId>
            <artifactId>javax.persistence</artifactId>
            <version>2.1.0-SNAPSHOT</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.eclipse.persistence</groupId>
            <artifactId>eclipselink</artifactId>
            <version>2.5.0-SNAPSHOT</version>
            <scope>provided</scope>
        </dependency>        
        <dependency>
            <groupId>org.eclipse.persistence</groupId>
            <artifactId>
                org.eclipse.persistence.jpa.modelgen.processor
            </artifactId>
            <version>2.5.0-SNAPSHOT</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>javax</groupId>
            <artifactId>javaee-web-api</artifactId>
            <version>7.0</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>ch.qos.logback</groupId>
            <artifactId>logback-classic</artifactId>
            <version>${logback.version}</version>
        </dependency>    
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.11</version>
            <scope>test</scope>
        </dependency>        
        <dependency>
            <groupId>mysql</groupId>
            <artifactId>mysql-connector-java</artifactId>
            <version>5.1.26</version>
            <scope>provided</scope>
        </dependency>            
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-context</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-context-support</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-tx</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-jdbc</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-orm</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-instrument</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-webmvc</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-test</artifactId>
            <version>${spring.version}</version>
            <scope>test</scope>
        </dependency>

    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <version>3.1</version>
                <configuration>
                    <source>1.7</source>
                    <target>1.7</target>
                    <compilerArguments>
                        <endorseddirs>
                            ${endorsed.dir}
                        </endorseddirs>
                    </compilerArguments>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-war-plugin</artifactId>
                <version>2.3</version>
                <configuration>
                  <warName>${project.build.finalName}</warName>
                  <failOnMissingWebXml>false</failOnMissingWebXml>
                </configuration>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-dependency-plugin</artifactId>
                <version>2.6</version>
                <executions>
                    <execution>
                        <id>copy-endorsed</id>
                        <phase>validate</phase>
                        <goals>
                            <goal>copy</goal>
                        </goals>
                        <configuration>
                            <outputDirectory>
                                ${endorsed.dir}
                            </outputDirectory>
                            <silent>true</silent>
                            <artifactItems>
                                <artifactItem>
                                    <groupId>javax</groupId>
                                    <artifactId>
                                        javaee-endorsed-api
                                    </artifactId>
                                    <version>7.0</version>
                                    <type>jar</type>
                                </artifactItem>
                            </artifactItems>
                        </configuration>
                    </execution>
                    <execution>
                        <id>copy-all-dependencies</id>
                        <phase>compile</phase>
                        <goals>
                            <goal>copy-dependencies</goal>
                        </goals>
                        <configuration>
                            <outputDirectory>
                                ${project.build.directory}/lib
                            </outputDirectory>
                            <includeScope>compile</includeScope>
                        </configuration>                        
                    </execution>                  
                </executions>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>2.14.1</version>
                <configuration>
                    <skipTests>true</skipTests>
                    <includes>
                        <include>**/dao/*Test.java</include>
                        <include>**/service/*Test.java</include>
                    </includes>
                    <argLine>
-javaagent:target/lib/spring-instrument-${spring.version}.jar
                    </argLine>
                </configuration>
            </plugin>            

        </plugins>
    </build>
    <repositories>
        <repository>
          <url>
            http://download.eclipse.org/rt/eclipselink/maven.repo/
          </url>
          <id>eclipselink</id>
          <layout>default</layout>
          <name>
            Repository for library EclipseLink (JPA 2.1)
          </name>
        </repository>
    </repositories>
</project>
```

在反向工程过程中添加了几个依赖项，还添加了 EclipseLink 的`<repository>`定义。只需要进行一些更改：

+   **添加 MySQL 连接器**：应使用最新版本的`mysql-connector-java`依赖项。GlassFish 不提供 MySQL 连接器，并且将在本章后面的某个部分中将其复制到应用程序服务器中。范围设置为`provided`，以便在构建 WAR 文件时不包括此 JAR。

+   **关闭 Surefire 测试插件**：如果在构建过程中关闭测试，您的部署速度将会更快。将`maven-surefire-plugin`条目的`skipTests`更改为`true`。这将在本地构建和部署项目时跳过测试阶段。

### 注意

构建企业应用程序通常在专用的构建服务器上执行，该服务器执行测试用例并报告构建过程的成功或失败。禁用测试阶段应该只在开发人员的机器上进行，以加快构建和部署过程。开发人员不希望在每次更改类时等待 30 分钟来执行测试套件。测试阶段不应该在构建服务器上被禁用执行。

# 将 eclipselink.target-server 添加到 persistence.xml 文件

`persistence.xml`文件需要包含`eclipselink.target-server`属性才能完全启用事务行为。位于`src/main/resources/META-INF`的`persistence.xml`文件应如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<persistence version="2.1" 

  xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/persistence
  http://xmlns.jcp.org/xml/ns/persistence/persistence_2_1.xsd">

  <persistence-unit name="tttPU" transaction-type="JTA">
    <provider>
        org.eclipse.persistence.jpa.PersistenceProvider
    </provider>
    <jta-data-source>jdbc/tasktimetracker</jta-data-source>
    <exclude-unlisted-classes>false</exclude-unlisted-classes>
    <properties>
        <property name="eclipselink.target-server"
            value="SunAS9"/>
        <property name="eclipselink.logging.level" 
            value="INFO"/>
    </properties>
  </persistence-unit>
</persistence>
```

如果没有此添加，您的应用程序将无法使用事务。`eclipselink.logging.level`也可以更改以根据需要增加或减少日志输出。

# 将 logback.xml 文件添加到资源目录

`logback.xml`文件应该添加到`src/main/resources/`中，以便启用应用程序的日志记录。该文件的内容与测试`logback.xml`文件相同，如下所示：

```java
<?xml version="1.0" encoding="UTF-8"?>
<configuration scan="true" scanPeriod="30 seconds" >
    <contextName>TaskTimeTracker</contextName>
    <appender name="STDOUT"
        class="ch.qos.logback.core.ConsoleAppender">
        <encoder>
          <pattern>
           %d{HH:mm:ss.SSS} [%thread] %-5level %logger{5} - %msg%n
          </pattern>
        </encoder>
    </appender>
    <logger name="com.gieman.tttracker"
        level="DEBUG" additivity="false">
        <appender-ref ref="STDOUT" />
    </logger>
    <logger name="com.gieman.tttracker.dao"
        level="DEBUG" additivity="false">
        <appender-ref ref="STDOUT" />
    </logger>
    <logger name="com.gieman.tttracker.domain"
        level="DEBUG" additivity="false">
        <appender-ref ref="STDOUT" />
    </logger>
    <logger name="com.gieman.tttracker.service"
        level="DEBUG" additivity="false">
        <appender-ref ref="STDOUT" />
    </logger>
    <logger name="com.gieman.tttracker.web"
        level="DEBUG" additivity="false">
        <appender-ref ref="STDOUT" />
    </logger>
    <root level="INFO">
        <appender-ref ref="STDOUT" />
    </root>
</configuration>
```

# 配置 GlassFish 服务器

NetBeans 捆绑的 GlassFish 4 服务器在首次运行项目时会自动配置。这意味着根据项目的当前状态动态设置所需的任何资源。所有这些属性都会被复制到`setup`目录中的`glassfish-resources.xml`文件中，如下截图所示：

![配置 GlassFish 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_02.jpg)

在数据库反向工程过程中，`glassfish-resources.xml`文件被修改以包括 JPA 所需的数据库连接池和 JDBC 资源。因此，该文件的内容定义了所需的 GlassFish 连接池详细信息。

重要的是要了解，此文件由 NetBeans 用于动态配置分配给项目的 GlassFish 服务器。在现实世界的情况下，GlassFish 服务器是由管理员配置的，并且部署 Web 应用程序是通过命令行或通过 GlassFish 管理控制台完成的。在正常的企业环境中，您不会通过 NetBeans 部署应用程序，因此非常有必要对 GlassFish 从最基本的原则进行配置有一个基本的了解。本节专门用于配置用于 3T 的 GlassFish 服务器连接池。虽然在 NetBeans 上运行 3T 并不严格要求这样做，但我们强烈建议您花时间通过以下步骤完全配置您的 GlassFish 服务器。

这将确保您了解在不同物理服务器上为运行 3T 应用程序配置 GlassFish 服务器所需的内容。

1.  配置 GlassFish 服务器的第一步是执行**清理和构建**：![配置 GlassFish 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_03.jpg)

1.  构建完成后，导航到`target/lib`，如下截图所示，以查看项目所需的 JAR 文件：![配置 GlassFish 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_04.jpg)

1.  打开文件资源管理器窗口（Windows 资源管理器或 OS X Finder），导航到此目录，并将`mysql-connector-java-5.1.26.jar`文件复制到您的 GlassFish 域`libs`目录，如下截图所示：![配置 GlassFish 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_05.jpg)

## 重命名 setup 目录

`src/main/`目录中的`setup`目录包含`glassfish-resources.xml`文件，应将其重命名以确保 NetBeans 不会动态配置 GlassFish 的这些属性。我们建议将目录重命名为`setup-original`。

## 在 NetBeans 中启动 GlassFish 服务器

导航到**服务**选项卡；通过右键单击**GlassFish Server 4.0**节点，选择如下截图所示的**启动**：

![在 NetBeans 中启动 GlassFish 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_06.jpg)

您应该在 NetBeans IDE 底部看到服务器输出，并重新加载 GlassFish Server 4.0 节点。现在，您可以右键单击**GlassFish Server 4.0**节点，并选择**查看域管理控制台**：

![在 NetBeans 中启动 GlassFish 服务器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_07.jpg)

这将启动您的默认浏览器并加载**域管理控制台**。

## 配置 JDBC 连接池

本节将使用 GlassFish 管理控制台来配置 3T 应用程序所需的 JDBC 连接池和 JDBC 资源。

1.  打开**资源**节点，并导航到**JDBC 连接池**选项卡：![配置 JDBC 连接池](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_08.jpg)

### 注意

您可能会看到一个名为`mysql_task_time_tracker_rootPool`或类似的连接池，如前面的截图所示。这是由 NetBeans 在以前的运行中使用`glassfish-resources.xml`文件中指定的属性创建的。如果您希望继续使用此连接池，则可以跳过剩余部分。我们建议您删除此条目，并继续遵循以下步骤，以了解如何配置 GlassFish 连接池。

1.  单击**新建**按钮，然后在单击**下一步**按钮之前输入以下详细信息：![配置 JDBC 连接池](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_09.jpg)

1.  下一个屏幕看起来令人生畏，但只需要输入一些条目。一直向下滚动，直到您可以查看**附加属性**部分：![配置 JDBC 连接池](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_10.jpg)

1.  这里有很多属性！幸运的是，除非您熟悉 MySQL 数据库管理，否则只需要一些属性。您可以安全地删除所有列出的属性，以保持配置简单，然后输入与原始`glassfish-resources.xml`文件对应的以下属性：![配置 JDBC 连接池](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_11.jpg)

1.  所需的基本字段是**URL**、**用户**和**密码**。保存这些设置将返回到**JDBC 连接池**屏幕：![配置 JDBC 连接池](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_12.jpg)

1.  单击**3TPool**名称以再次打开设置，然后单击**Ping**按钮以测试连接。您现在应该看到以下结果：![配置 JDBC 连接池](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_13.jpg)

## 配置 JDBC 资源

最后一步是创建**JDBC 资源**。单击此节点以显示配置的资源：

![配置 JDBC 资源](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_14.jpg)

单击**新建…**按钮，然后输入以下详细信息：

![配置 JDBC 资源](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_15.jpg)

**JNDI 名称**必须与`persistence.xml`文件中定义的`<jta-data-source>`属性相同，因此设置为`jdbc/tasktimetracker`。单击**确定**按钮以保存资源配置。刷新后的节点现在应该显示新创建的资源。

您现在已经完成了 GlassFish JDBC 设置的配置。

# 运行 3T

现在我们建议您停止 GlassFish 并重新启动 NetBeans，以确保之前所做的所有更改在 IDE 中是最新的。最后一步是运行 3T 应用程序：

![运行 3T](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_16.jpg)

这应该导致大量输出，最终将 3T 应用程序部署到 GlassFish 服务器：

![运行 3T](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_17.jpg)

请注意，**GlassFish Server 4.0**输出中的最终**警告**可以忽略；这是在 NetBeans 中从根上下文部署应用程序时的已知问题。

NetBeans 的最后一个操作将是打开您的默认浏览器，显示第一章中显示的欢迎页面，*准备开发环境*。您应该注意浏览器中的 URL 现在是：

`http://localhost:8080/`

而不是原始的：

`http://localhost:8080/task-time-tracker`

这是由`glassfish-web.xml`中的`<context-root>/</context-root>`属性引起的，它定义了 Web 应用程序路径的根。3T Web 应用程序现在部署到上下文根，不需要前缀即可访问已部署的 3T 应用程序。

您现在可以尝试加载一个映射的 URL，例如`/ttt/company/findAll.json`。按照所示在浏览器中输入并按下*Enter*键。您应该看到以下结果：

![运行 3T](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_18.jpg)

这条消息来自我们在上一章实现的`UserInSessionInterceptor`。会话检查失败，因为我们当前没有登录，将前面的 JSON 消息返回给浏览器。该类中的`logger.info`消息也应该在 GlassFish 输出中可见：

![运行 3T](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_20.jpg)

您现在可以尝试使用以下截图中显示的参数进行登录操作：

![运行 3T](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_19.jpg)

这个结果可能会让你感到惊讶。请求 URL 被映射到`SecurityHandler.logon`方法，该方法在`@RequestMapping`注解中被定义为`method = RequestMethod.POST`。这将限制对该方法的访问仅限于`POST`请求，而浏览器提交的 URL 编码参数是一个`GET`请求。这导致了 GlassFish 返回 405 HTTP 状态消息。在第十章中，*登录和维护用户*，我们将使用适当的`POST`请求来实现登录过程。

您应该注意，所有处理程序 URL 将通过后续章节中开发的 Ext JS 4 应用程序的 AJAX 调用访问。您将不会像之前显示的那样在浏览器中看到这些 URL。

# 在没有 NetBeans 的情况下管理 GlassFish

在 NetBeans 中启动和停止 GlassFish 很容易和方便。然而，在企业环境中，停止/启动过程将由包装`asadmin`实用程序的脚本管理。您可以在*GlassFish 用户管理指南*中找到该实用程序的完整描述，网址为[`glassfish.java.net/docs/4.0/administration-guide.pdf`](https://glassfish.java.net/docs/4.0/administration-guide.pdf)。

`asadmin`实用程序用于从命令行或脚本执行 GlassFish 服务器的管理任务。您可以使用此实用程序代替本章前面使用的 GlassFish 管理控制台界面。几乎可以在管理控制台中执行的每个操作都有一个相应的命令可以使用`asadmin`执行。

`asadmin`实用程序位于`{as-install}/bin`目录中。如果没有提供`asadmin`的完整路径，则应该从该目录中运行命令。要启动域，可以执行以下命令：

```java
asadmin start-domain domain1

```

`domain1`参数表示要启动的域的名称。从 Windows 命令提示符中执行此命令将导致以下输出：

![在没有 NetBeans 的情况下管理 GlassFish](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_21.jpg)

停止运行中的 GlassFish 域同样简单。使用以下命令：

```java
asadmin stop-domain domain1

```

这将导致以下输出：

![在没有 NetBeans 的情况下管理 GlassFish](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457OS_08_22.jpg)

我们将继续在 NetBeans 中启动和停止 GlassFish，但将在第十三章中重新讨论`asadmin`，*将您的应用程序移至生产环境*。

# 总结

本章重点介绍了配置 3T Web 应用程序以部署到 GlassFish 4 服务器所需的步骤。定义了 Spring 配置文件，并配置了`web.xml`文件以在启动时加载 Spring 容器。您将被引导完成 GlassFish 连接池配置过程，并将 3T Web 应用程序部署到 GlassFish 4 服务器的上下文根。

这是我们企业应用程序开发过程中的关键点。我们现在已经完全涵盖了 Java 开发人员的领域，构建了一个功能齐全的后端系统，可以为任何 JSON 客户端提供动态请求。第九章，*开始使用 Ext JS 4*，将介绍强大的 Ext JS 4 框架，并开始我们的前端开发之旅。


# 第九章：开始使用 Ext JS 4

**Ext JS 4**是迄今为止最复杂的 JavaScript 库，并为几乎所有实际设计问题提供了惊人的小部件集。它可以满足我们开发需要的一切，以开发需要高度用户交互的复杂、跨浏览器兼容的应用程序。在本章中，我们将：

+   了解核心的 Ext JS 4 MVC 概念

+   探索实际项目设计和开发惯例

+   安装 Ext JS 4 开发框架并引入 Sencha Cmd

+   为 3T 应用程序生成一个 Ext JS 4 应用程序骨架

Ext JS 自从作为**Yahoo 用户界面**（**YUI**）库的扩展开始以来已经走过了很长的路。每个新版本都是对上一个版本的重大改进，Ext JS 4 也不例外。对于 Ext JS 的新手来说，他们会欣赏到优雅的框架设计和一致的 API，而那些从 Ext JS 3 过渡过来的人则会欣赏到许多方面的改进，包括 MVC 设计模式的引入。无论你的背景如何，本章都将帮助你在 Ext JS 4 上提高工作效率。

值得注意的是，Ext JS 4 并不是当今唯一可用的 JavaScript MVC 框架。例如，`Angular.js`和`Backbone.js`都是非常有能力的开发框架，具有类似于 Ext JS 4 的 MVC 功能。然而，它们没有 Ext JS 4 那样广泛的文档、构建工具和商业支持，这使得 Ext JS 4 非常适合企业应用程序开发。

# 应用程序设计的重要性

在开发企业应用程序时，除了技术之外，深思熟虑和一致的应用程序设计对于应用程序的可维护性、可扩展性和整体成本至关重要。良好设计的应用程序的好处包括以下几点：

+   应用程序将更容易理解。如果有一致的做事方式，新团队成员将很快上手。

+   应用程序将更容易维护。如果你有一致的应用程序设计准则，增强和新功能的实现将会更简单。

+   代码一致性。一个设计良好的应用程序将有良好的命名约定、目录结构和编码标准。

+   应用程序将更适合多开发人员。在大型项目中，许多人将参与其中，一致的设计策略将确保每个人都在同一页面上。

当你开始一个新项目并兴奋地为概念验证演示制作第一个原型时，往往会忽视一些无形的好处。能够从简单的开始重构和扩展项目往往是企业应用开发的关键因素。无论项目在最初阶段看起来多么小，你可以肯定，一旦业务用户熟悉应用程序，他们就会想要改变工作流程和布局。新功能将被请求，旧功能将被弃用。组件将随着应用程序的演变而移动和重新设计。一个一致和深思熟虑的应用程序设计将使这些项目生命周期过程变得不那么可怕。值得庆幸的是，Ext JS 4 应用程序架构本身鼓励正式和结构良好的应用程序设计。

# Ext JS 4 MVC 概念

当 MVC 设计模式首次在 Ext JS 4 中引入时，它彻底改变了 Ext JS 框架。虽然 MVC 作为一种设计模式是众所周知的，但这是第一次一个复杂的 JavaScript 框架实现了这种策略。以下是一些关键的好处：

+   MVC 设计模式将代码组织成逻辑领域或组件类型，使代码更易于理解

+   MVC 模块化可以简化组件测试和重构，因为每个对象都有明确定义的目的

+   MVC 设计模式架构鼓励更清晰的代码，明确分离数据访问、呈现和业务逻辑。

这些是前一版 Ext JS 3 的巨大优势，那里唯一真正的 MVC 组件是**V**（**视图**）。留给 Ext JS 3 开发人员去构建**M**（**模型**）和**C**（**控制器**）的工作，通常导致混乱和不一致的代码。现在让我们看看 Ext JS 4 如何定义 MVC 设计模式。

## 模型

Ext JS 4 模型是表示领域实体的属性集合。也许不足为奇的是，我们的 3T 应用程序将需要一个`Company`、`Project`、`Task`、`User`和`TaskLog`模型定义，就像它们在我们的 Java 领域层中所表示的那样。与我们的 Java 领域对象的主要区别是，Ext JS 4 模型等效物将具有持久性意识。由于 Ext JS 4 的`data`包，每个模型实例将知道如何持久化和管理其状态。

## 视图

Ext JS 4 视图代表一个逻辑视觉组件块，可能包括面板、工具栏、网格、表单、树和图表。Ext JS 4 视图始终驻留在自己的文件中，并且应尽可能“愚蠢”。这意味着视图中不应该有 JavaScript 业务逻辑；它的目的是呈现数据并为用户提供交互能力。

## 控制器

Ext JS 4 控制器可以被宽泛地描述为将应用程序逻辑粘合在一起的粘合剂。控制器在处理事件处理和跨视图交互方面起着核心作用，并定义应用程序工作流程。绝大多数 JavaScript 业务逻辑代码将驻留在控制器中。

## Ext JS 4 的灵活性

虽然我们对不同的 MVC 组件有清晰的定义，但在 Ext JS 4 框架本身中有相当大的实现灵活性。我们不需要使用控制器或模型；事实上，我们可以轻松地使用在 Ext JS 3 中遵循的相同策略构建一个完全可用的 Ext JS 4 应用程序。然而，这将是一个错误，应该尽量避免。利用 MVC 架构进行企业应用程序开发的好处是显著的，包括但不限于更简单和更健壮的代码库。

# Ext JS 4 设计约定和概念

Sencha Ext JS 4 团队在定义约定方面做了大量工作，您应该考虑遵循这些约定来构建企业应用程序。这些包括标准的目录结构、命名约定和详细的设计最佳实践。我们强烈建议您浏览*Sencha Ext JS 4 文档*网站上的许多教程和指南，以熟悉他们的应用程序设计建议。

本书将遵循 Ext JS 4 团队概述的常见设计策略，对于其相关部分中引入的细微差异进行注释和解释。本书的范围不包括基本的 Ext JS 4 概念，您可能需要参考*Sencha Ext JS 4 文档*来进一步理解。

# 实用约定

一个结构良好的 Ext JS 4 项目，具有一致的命名约定，将是一个令人愉快的工作。拥有数百个文件的企业应用程序应该以易于学习和维护的方式进行结构化。当你问同事，“显示 xyz 小部件的编辑工具栏的文件在哪里？”时，这应该是一个罕见的情况。

## 项目结构

Ext JS 4 的目录结构，包括顶级应用程序和名为`controller`、`model`、`store`和`view`的子目录，应始终使用。这是任何 Ext JS 4 应用程序的默认目录结构，并允许与 Sencha Cmd 构建工具的即插即用集成。

大型项目有数百个 JavaScript 文件，因此拥有一致的项目结构非常重要。实际的命名空间，特别是在`view`目录中，可以简化项目结构，使其更容易找到组件。例如，在第十章 *登录和维护用户*，第十一章 *构建任务日志用户界面*和第十二章 *3T 管理简单*中，我们将创建一个包含以下屏幕截图中显示的文件的`view`结构（在左侧）：

![项目结构](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_16.jpg)

前面的屏幕截图显示了同一目录中的所有视图（在其右侧）。哪种方式更好？这取决于项目的性质和文件数量。企业项目通常在模块级别进行命名空间划分，有许多子目录逻辑地分组相关组件。较小的项目也可以很容易地具有所有文件都在同一目录中的平面结构。无论选择哪种结构，都要保持一致！任何新开发人员都应该很容易找到组件，而不必搜索大量文件和目录。

## 命名约定

我们建议定义一个易于理解和遵循的一致的命名约定。应该很容易在文件系统和您正在使用的 IDE 中找到文件。

### 命名存储和模型

每个模型应该以它所代表的实体的单数形式命名（例如，`Company`、`Project`、`Task`、`TaskLog`和`User`）。每个存储应该以类似的单数方式命名。我们曾在 Ext JS 3 中看到存储名称后缀为`Store`（例如，`ProjectStore`），但这在 Ext JS 4 中不推荐。控制器会自动为每个存储创建一个`get`函数，通过在存储名称后添加`Store`。将存储命名为`ProjectStore`将导致在引用存储的每个控制器中生成一个名为`getProjectStoreStore`的函数。因此，我们建议您在不使用`Store`后缀的情况下使用存储名称。

存储名称通常以其单数形式替换为复数形式。例如，项目存储通常被命名为`Projects`。一致性再次是关键。如果决定使用复数形式，那么每个存储名称都应该使用复数形式。在我们的应用程序中，这将导致`Companies`、`Projects`、`Tasks`、`TaskLogs`和`Users`存储。这有时会导致拼写混淆；我们曾看到`Companies`和`Companys`都用于复数形式的`Company`。当英语不是您的第一语言时，可能很难知道实体的正确复数名称，例如领土、国家、公司、货币和状态。因此，我们更喜欢在命名存储时使用单数形式。

### 命名视图

考虑以下情况，我们一直在研究 Sencha Docs 网站上的面板：

![命名视图](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_10_10.jpg)

有四个不同的**Panel**文件打开（`Ext.grid.Panel`、`Ext.tab.Panel`、`Ext.form.Panel`和`Ext.panel.Panel`）。在这种情况下，尝试定位`Ext.grid.Panel`文件是令人沮丧的；在最坏的情况下，您将需要点击四个不同的选项卡项。在大型项目中，可能会有许多值得称为`Panel`的面板容器。我们建议为每个文件赋予一个唯一的名称，无论其命名空间如何。与模型和存储不同，模型和存储命名空间使用相同的文件名，我们不建议在视图类之间使用相同的文件名。例如，文件`app.view.user.List`和`app.view.tasklog.List`在 IDE 选项卡栏中很难区分。使这些文件名唯一要容易得多，即使它们可能存在于不同的命名空间中。

后缀类类型的使用是另一个值得讨论的问题。Ext JS 3 在类名后使用了类型后缀。这导致了`GridPanel`、`FormPanel`、`TabPanel`和`Panel`文件名。它们都是面板。通过检查文件名很容易确定类是什么。Ext JS 4 采用了命名空间方法，并放弃了描述性名称。前面的例子变成了`Ext.grid.Panel`、`Ext.tab.Panel`、`Ext.form.Panel`和`Ext.panel.Panel`。每个文件都被命名为`Panel`，如果不知道它所在的目录，这并不是很有帮助。

无论您实施何种命名约定，保持一致是很重要的。我们将使用以下命名约定：

+   所有命名空间文件夹名称都将是小写。

+   用于表示项目列表的任何类都将以`List`结尾。`List`的实现并不重要；我们不在乎列表是使用网格、简单模板还是数据视图创建的。

+   任何表单类都将以`Form`结尾。

+   任何树类都将以`Tree`结尾。

+   任何窗口类都将以`Window`结尾。

+   任何管理一组相关组件的定位和布局的组件都将以`Manage`为前缀。这样的类通常包含适当布局的工具栏、列表、表单和选项卡面板。

您可能希望引入适合您的开发环境的其他约定。这很好；重要的是要保持一致，并确保每个人都理解并遵守您的约定。

### 命名控制器

我们建议所有控制器类的名称都以`Controller`结尾。这样它们在任何 IDE 中都很容易识别。例如，负责用户维护的控制器将被命名为`UserController`。

### 命名 xtype

我们建议对每个类使用小写类名作为`xtype`。这是确保每个视图类的文件名唯一的另一个很好的理由。`UserList`的`xtype`是`userlist`，`UserForm`的`xtype`是`userform`，`ManageUsers`的`xtype`是`manageusers`。不会有混淆。

# Ext JS 4 开发环境

Ext JS 4 开发所需的两个核心组件如下：

+   **Sencha Cmd 工具**：这是一个跨平台的基于 Java 的命令行工具，提供许多选项来帮助管理应用程序的生命周期

+   **Ext JS 4 SDK（软件开发工具包）**：包含所有应用程序开发所需的源文件、示例、资源和压缩脚本

我们现在将检查并安装这些组件。

## 安装 Sencha Cmd

Sencha Cmd 工具可从[`www.sencha.com/products/sencha-cmd/download`](http://www.sencha.com/products/sencha-cmd/download)下载。该文件大小约为 46MB，需要在运行安装过程之前解压缩。

![安装 Sencha Cmd](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_02.jpg)

点击“下一步”查看“许可协议”部分。您需要接受协议后才能点击“下一步”按钮：

![安装 Sencha Cmd](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_03.jpg)

在下面的截图中显示的屏幕提示输入“安装目录”。我们建议您将 Sencha Cmd 工具安装在易于访问的目录中（Mac 用户为`/Users/Shared/`，Windows 用户为`C:\`）：

![安装 Sencha Cmd](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_04.jpg)

点击“下一步”继续。这将显示一个提示，指示安装程序现在准备开始在您的计算机上安装 Sencha Cmd。再次点击“下一步”继续安装。最后的提示将确认安装 Sencha Cmd：

![安装 Sencha Cmd](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_05.jpg)

您现在可以查看已安装的文件，如下面的截图所示：

![安装 Sencha Cmd](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_06.jpg)

要确认安装，打开命令提示符（Windows）或终端（Mac），输入`sencha`，然后按*Enter*键。这将确认 Sencha Cmd 已添加到系统路径，并应产生类似于以下截图所示的输出：

![安装 Sencha Cmd](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_07.jpg)

请注意，任何当前打开的控制台/终端窗口都需要关闭并重新打开，以确保重新加载安装路径更改。最后一步是通过输入来检查是否有可用的升级：

```java
sencha upgrade –-check

```

这个命令应该显示一个适当的消息，如下截图所示：

![安装 Sencha Cmd](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_08.jpg)

可以通过省略`––check`参数来升级 Sencha Cmd 的版本。有关 Sencha 命令行选项的完整列表，请参阅[`docs.sencha.com/extjs/4.2.2/#!/guide/command`](http://docs.sencha.com/extjs/4.2.2/#!/guide/command)。此页面还包含许多有用的故障排除提示和解释。此外，您还可以通过执行`sencha help`来使用命令行帮助。执行`sencha help`命令将显示详细的帮助选项：

![安装 Sencha Cmd](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_09.jpg)

## 安装 Ext JS 4 SDK

SDK 可以从[`www.sencha.com/products/extjs`](http://www.sencha.com/products/extjs)下载。上一步将在以下位置创建一个 Sencha 目录：

+   对于 Windows 用户，`C:\Sencha`

+   对于 Mac 用户，`/Users/Shared/Sencha`

下载 SDK 后，您应该在这个 Sencha 目录中创建一个`ext-xxx`目录，其中`xxx`代表 Ext JS 4 框架的版本。然后，您可以将 SDK 解压缩到此目录中，从而得到以下截图中显示的结构：

![安装 Ext JS 4 SDK](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_10.jpg)

现在，您可以初始化 Ext JS 4 3T 应用程序骨架。

# 生成 3T Ext JS 4 应用程序骨架

骨架生成命令的格式是：

```java
sencha -sdk /path/to/sdk generate app MyApp /path/to/MyApp

```

运行此命令将所有必需的 SDK 文件复制到`/path/to/MyApp`目录，并创建资源的骨架，准备进行开发。您必须为`SDK`和`MyApp`目录使用完整路径。

重要的是要记住 3T 应用程序是一个 Maven 项目，Web 内容根目录是 Maven 目录结构中的`webapp`目录。在第一章中创建的项目文件夹*准备开发环境*和`webapp`目录（在 Windows 上）可以在`C:\projects\task-time-tracker\src\main\webapp`找到。

在 Mac 上，它可以在`/Users/{username}/projects/task-time-tracker/src/main/webapp`找到。

现在可以通过执行以下命令（适用于 Windows 平台）生成 3T 应用程序骨架：

```java
sencha –sdk C:\Sencha\ext-4.2.2 generate app TTT C:\projects\task-time-tracker\src\main\webapp

```

请注意，此命令必须在一行上。`TTT`参数代表应用程序名称，并将用于生成应用程序命名空间。我们可以使用`TaskTimeTracker`，但缩写形式更容易书写！

从终端执行该命令应该会产生大量输出，最后显示一些红色错误：

![生成 3T Ext JS 4 应用程序骨架](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_11.jpg)

不要太担心**[ERR]**警告；Sencha Cmd 已经识别出`index.html`文件的存在，并用 Sencha Cmd 版本替换了它。原始文件被复制到`index.html.$old`。我们不需要备份文件（它是在 NetBeans 项目创建过程中创建的）；可以安全地删除它。

打开 NetBeans IDE 现在将在 3T 项目的`webapp`目录中显示许多新文件和目录：

![生成 3T Ext JS 4 应用程序骨架](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_12.jpg)

现在，您可以运行项目以在浏览器中查看输出：

![生成 3T Ext JS 4 应用程序骨架](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_13.jpg)

这是由`generate app`命令在构建项目骨架时在`index.html`页面中创建的默认 Ext JS 4 应用程序内容。现在让我们看看已生成的关键文件。

## index.html 文件

`index.html`文件包括以下列表：

```java
<!DOCTYPE HTML>
<html>
<head>
  <meta charset="UTF-8">
  <title>TTT</title>
  <!-- <x-compile> -->
    <!-- <x-bootstrap> -->
      <link rel="stylesheet" href="bootstrap.css">
      <script src="img/ext-dev.js"></script>
      <script src="img/bootstrap.js"></script>
    <!-- </x-bootstrap> -->
    <script src="img/app.js"></script>
  <!-- </x-compile> -->
</head>
<body></body>
</html>
```

请注意页面内容中的`x-compile`和`x-bootstrap`标记。这些标记由 Sencha Cmd 工具使用，并允许编译器识别应用程序根目录中的脚本（默认文件始终为`app.js`）。编译器还会忽略仅在开发过程中使用的框架的引导部分。在生成生产应用程序时，所有所需的文件都将在构建过程中被拉取。这将在第十三章中详细介绍，*将您的应用程序移至生产环境*。

您应该注意，`ext-dev.js`文件是唯一需要的 Ext JS 4 框架资源。该文件用于在开发阶段进行动态 JavaScript 类加载。然后框架将动态检索应用程序所需的任何 JavaScript 资源。

## app.js 和 Application.js 文件

`app.js`文件是应用程序的入口点。文件的内容，包括生成的注释，如下所示：

```java
/*
    This file is generated and updated by Sencha Cmd. You can edit this file as needed for your application, but these edits will have to be merged by Sencha Cmd when upgrading.
*/
Ext.application({
  name: 'TTT',
  extend: 'TTT.Application',
  autoCreateViewport: true
});
```

`Ext.application`扩展了`TTT.Application`类，该类在`app/Application.js`文件中定义如下：

```java
Ext.define('TTT.Application', {
  name: 'TTT',
  extend: 'Ext.app.Application',
  views: [
    // TODO: add views here
  ],
  controllers: [
    // TODO: add controllers here
  ],
  stores: [
    // TODO: add stores here
  ]
});
```

`Application.js`文件将包含我们 3T 应用程序特定的代码。

### 注意

您应该注意，这与之前的 Ext JS 4 教程中描述的设置不同，其中`app.js`文件包含特定于应用程序的属性（视图、控制器、存储和应用程序函数）。之前概述的方法将所有特定于应用程序的代码保留在`app`目录中。

我们对自动生成的`Application.js`文件的第一个更改是添加`launch`函数：

```java
Ext.define('TTT.Application', {
    name: 'TTT',
    extend: 'Ext.app.Application',
    views: [
        // TODO: add views here
    ],
    controllers: [
        // TODO: add controllers here
    ],
    stores: [
        // TODO: add stores here
    ],
    launch: function() {
 Ext.create('TTT.view.Viewport');
 }
});
```

现在我们可以从`app.js`文件中删除`autoCreateViewport:true`，因为创建视图的逻辑现在在`launch`函数中。`launch`函数本身将在下一章中进行增强，以实现用户登录，所以还有很多代码要写！更新后的`app.js`文件如下：

```java
Ext.application({
    name: 'TTT',
    extend: 'TTT.Application'    
});
```

## bootstrap.js 和 bootstrap.css 文件

`bootstrap.js`和`bootstrap.css`文件是由 Sencha Cmd 生成的，不应该被编辑。它们在内部用于初始化和配置开发环境。

## app/Viewport.js 和 app/view/Main.js 文件

Ext JS 4 视图端口是一个容器，它会调整自身大小以使用整个浏览器窗口。`Viewport.js`的定义如下：

```java
Ext.define('TTT.view.Viewport', {
    extend: 'Ext.container.Viewport',
    requires:[
        'Ext.layout.container.Fit',
        'TTT.view.Main'
    ],
    layout: {
        type: 'fit'
    },
    items: [{
        xtype: 'app-main'
    }]
});
```

`items`数组中只添加了一个视图；`TTT.view.Main`函数，其中有一个名为`app-main`的`xtype`函数：

```java
Ext.define('TTT.view.Main', {
    extend: 'Ext.container.Container',
    requires:[
        'Ext.tab.Panel',
        'Ext.layout.container.Border'
    ],
    xtype: 'app-main',
    layout: {
        type: 'border'
    },
    items: [{
        region: 'west',
        xtype: 'panel',
        title: 'west',
        width: 150
    },{
        region: 'center',
        xtype: 'tabpanel',
        items:[{
            title: 'Center Tab 1'
        }]
    }]
});
```

前面的文件定义了在浏览器中显示的两个区域的边框布局和文本内容。

### 注意

对于 Ext JS 视图、xtypes、视图端口、边框布局或面板不太自信？我们建议浏览和审查[`docs.sencha.com/extjs/4.2.2/#!/guide/components`](http://docs.sencha.com/extjs/4.2.2/#!/guide/components)中的基本 Ext JS 4 组件概念。

## app/controller/Main.js 文件

我们将要检查的最终生成的文件是`Main.js`控制器：

```java
Ext.define('TTT.controller.Main', {
    extend: 'Ext.app.Controller'
});
```

这个类中没有功能，因为还没有要控制的东西。

# 使用 Sencha Cmd 创建组件

可以使用 Sencha Cmd 生成骨架组件。其中最有用的命令是用于生成基本模型的命令。

## 生成模型骨架

使用 Sencha Cmd 工具可以非常容易地生成模型骨架。语法如下：

```java
sencha generate model ModelName [field1:fieldType,field2:fieldType…]

```

此命令必须在应用程序根目录（即`app.js`文件所在的目录）中执行。请注意，逗号分隔的字段列表中不得有任何空格。可以通过执行以下命令生成公司模型骨架：

```java
sencha generate model Company idCompany:int,companyName:string

```

对于`companyName`字段，最终的`string`并不是严格要求的，因为默认属性类型是`string`，如果未指定。此命令的输出如下截图所示：

![生成模型骨架](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_14.jpg)

生成的`Company.js`文件写入`app/model`目录，并具有以下内容：

```java
Ext.define('TTT.model.Company', {
    extend: 'Ext.data.Model',
    fields: [
        { name: 'idCompany', type: 'int' },
        { name: 'companyName', type: 'string'}
    ]
});
```

这是一个非常简单的模型，符合预期的有两个字段。我们也可以使用不同的数据类型生成更复杂的模型：

```java
sencha generate model TaskLog idTaskLog:int,taskDescription:string,taskLogDate:date,taskMinutes:int,hours:float,username:string,userFullName:string,idTask:int,taskName:string,idProject:int,projectName:string,idCompany:int,companyName:string

```

上述命令将生成带有`int`、`string`、`date`和`float`类型字段的`TaskLog`模型。

```java
Ext.define('TTT.model.TaskLog', {
    extend: 'Ext.data.Model',    
    fields: [
        { name: 'idTaskLog', type: 'int' },
        { name: 'taskDescription', type: 'string' },
        { name: 'taskLogDate', type: 'date' },
        { name: 'taskMinutes', type: 'int' },
        { name: 'hours', type: 'float' },
        { name: 'username', type: 'string' },
        { name: 'userFullName', type: 'string' },
        { name: 'idTask', type: 'int' },
        { name: 'taskName', type: 'string' },
        { name: 'idProject', type: 'int' },
        { name: 'projectName', type: 'string' },
        { name: 'idCompany', type: 'int' },
        { name: 'companyName', type: 'string' }
    ]
});
```

剩下的三个实体的模型骨架可以通过执行以下命令创建：

```java
sencha generate model Project idProject:int,projectName:string, idCompany:int,companyName:string
sencha generate model Task idTask:int,taskName:string,idProject:int,projectName:string, idCompany:int,companyName:string
sencha generate model User username:string,firstName:string,lastName:string,fullName:string,email:string,password:string,adminRole:string

```

请注意，每个模型都与相应的 Java 域类中`addJson`（`JsonObjectBuilder`）方法生成的 JSON 结构匹配。现在，您应该在`app/model`目录中看到以下截图中显示的文件：

![生成模型骨架](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/etp-app-dev-ext-spr/img/5457_09_15.jpg)

虽然我们使用 Sencha Cmd 工具生成了这些模型骨架，但在 NetBeans IDE 中创建适当的文件和定义同样容易。

## 使用 Sencha Cmd 生成视图和控制器

也可以生成基本的视图和控制器骨架，但这些文件的内容非常有限。以下命令将创建名为`ManageUsers`的视图：

```java
sencha generate view ManageUsers

```

`ManageUsers.js`文件将写入`app/view`目录，并具有以下内容：

```java
Ext.define("TTT.view.ManageUsers", {
    extend: 'Ext.Component',
    html: 'Hello, World!!'
});
```

类似地，您可以为`UserController`创建一个控制器骨架：

```java
sencha generate controller UserController

```

`UserController.js`文件将写入`app/controller`目录，并具有以下内容：

```java
Ext.define('TTT.controller.UserController', {
    extend: 'Ext.app.Controller'
});
```

我们相信在 NetBeans IDE 中创建视图和控制器更简单，因此不会使用 Sencha Cmd 来实现这一目的。

# 摘要

本章已配置了 Ext JS 4 开发环境，并介绍了实用的设计约定和概念。我们已安装了 Sencha Cmd 并生成了 3T 应用程序骨架，检查核心生成的文件以了解推荐的应用程序结构。我们的模型实体已使用 Sencha Cmd 生成，并准备在接下来的章节中进行增强。我们已经为构建 3T 应用程序的前端做好了准备。

在第十章*登录和维护用户*中，我们将开发 Ext JS 4 组件，用于登录 3T 应用程序并维护用户。我们在**用户界面**（**UI**）设计方面的创意之旅刚刚开始！
