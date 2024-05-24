# Spring Security 3.x 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/805128EFB9E241233881DA578C0077AD`](https://zh.annas-archive.org/md5/805128EFB9E241233881DA578C0077AD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Vaadin 的 Spring Security

在本章中，我们将涵盖：

+   *使用 Vaadin 的 Spring Security - 基本身份验证*

+   *使用 Vaadin 的 Spring Security - Spring 基于表单的身份验证*

+   *使用 Vaadin 的 Spring Security - 自定义 JSP 基于表单的身份验证*

+   *使用 Vaadin 的 Spring Security - 使用 Vaadin 表单*

# 介绍

Vaadin 已成为当前项目中流行的框架。它提供了类似 GWT 的 RIA。它没有 RPC 调用和异步服务类。它的工作方式类似于 GWT 小部件。Vaadin 还很容易与 portlet 集成。在 GWT 中，我们必须安装与浏览器兼容的 GWT 插件，但在 Vaadin 中我们不需要这样做。在 Vaadin 开发的应用程序在所有现代浏览器上都兼容。Vaadin 可以编写为服务器端和客户端应用程序。Vaadin UI 组件实际上是一个 JavaServlet 组件，可以轻松运行在诸如 Tomcat 之类的 Web 服务器上，也可以运行在 JBOSS 和 Glassfish 等应用服务器上。在当前演示中，我正在使用 Tomcat 和 Eclipse Indigo。

在本章中，我们将演示使用各种方法集成 Spring Security 与 Vaadin。让我们首先进行基本设置。这就是下载插件并创建一个示例 Vaadin 项目。

# 使用 Vaadin 的 Spring Security - 基本身份验证

我们的目标是在 Vaadin 应用程序上进行简单的基本身份验证。当我们访问 Vaadin 应用程序的 URL 时，我希望出现一个登录对话框。我创建了一个简单的产品目录应用程序，它看起来与地址簿非常相似。

## 准备工作

+   在 Eclipse 上设置 Vaadin 应用程序：

+   下载 Vaadin [`vaadin.com/eclipse`](http://vaadin.com/eclipse) 适用于 Eclipse Indigo。

在本章中，我们将演示 Spring Security 与 Vaadin 两个版本（Vaadin 6 和 Vaadin 7）的集成。

+   在 Eclipse 中创建一个 Vaadin 7 的 Vaadin Web 项目 - 这将生成一个带有点击按钮的默认应用程序，我们将对其进行修改。

+   在 Tomcat 服务器上运行应用程序。

+   创建一个`applicationContext.xml`文件。必须将其命名为`applicationContext`，否则我们将在控制台中收到错误消息。

+   编辑`web.xml`文件，添加 spring 监听器。

+   将所有 jar 包添加到类路径中。

## 如何做...

以下步骤是为了将 Spring Security 与 Vaadin 集成以演示基本身份验证：

1.  使用 spring 监听器和 spring 过滤器更新`web.xml`文件，使用 Vaadin servlet：

```java
<display-name>Vaadin_Project1</display-name>
<filter>
  <filter-name>springSecurityFilterChain</filter-name>
  <filter-class>org.springframework.web.filter.
    DelegatingFilterProxy</filter-class>
</filter>

<filter-mapping>
  <filter-name>springSecurityFilterChain</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>

<listener>
  <listener-class>
    org.springframework.web.context.ContextLoaderListener
  </listener-class>
</listener>

  <context-param>
    <description>
    Vaadin production mode</description>
    <param-name>productionMode</param-name>
    <param-value>false</param-value>
  </context-param>

  <servlet>
    <servlet-name>Vaadin_Project1</servlet-name>
    <servlet-class>com.vaadin.server.VaadinServlet
      </servlet-class>
  <init-param>
    <description>
      Vaadin UI class to use</description>
    <param-name>UI</param-name>
    <param-value>com.example.vaadin_project1
      .Vaadin_project1UI</param-value>
  </init-param>
  <init-param>
    <description>
    Legacy mode to return the value of
       the property as a string from 
      AbstractProperty.toString()</description>
    <param-name>legacyPropertyToString</param-name>
    <param-value>false</param-value>
  </init-param>
</servlet>
<servlet-mapping>
  <servlet-name>Vaadin_Project1</servlet-name>
  <url-pattern>/*</url-pattern>
</servlet-mapping>
```

1.  您可以观察到我们没有像在以前的应用程序中那样配置`<context-param>`。Spring 将自动查找`applicationContext.xml`文件。为了设置 Vaadin，我们需要使用两个参数`PropertyToString`和一个名为`com.example.vaadin_project1`的 UI 类来配置 Vaadin servlet 类。使用以下代码编辑`applicationContext.xml`文件：

```java
<http auto-config="true">
 <intercept-url pattern="/Vaadin_Project1/**"access="ROLE_EDITOR"/> 
 <intercept-url pattern="/Vaadin_Project1/*.*"access="ROLE_EDITOR"/> 
 <intercept-url pattern="/**" access="ROLE_EDITOR" />
 <http-basic /> 
</http>

<authentication-manager>
  <authentication-provider>
    <user-service>
      <user name="anjana" password="123456"authorities="ROLE_EDITOR" />
    </user-service>
  </authentication-provider>
</authentication-manager>
</beans:beans>
```

这是一个简单的基本身份验证配置。使用此配置，我们期望在显示 Vaadin 应用程序之前出现登录对话框。我创建了一个新的编辑器角色。

在这里，我们创建了一个`ProductList`组件来显示产品列表。

## 它是如何工作的...

在这个例子中，我们演示了 Vaadin 应用程序的基本身份验证机制。有时我们不需要为用户显示 jsp 页面或 Vaadin 登录表单，在这种情况下，我们选择基本身份验证，其中会弹出一个对话框要求用户输入他们的凭据。成功后，用户将获得对 Vaadin 应用程序的访问权限。应用程序的工作流程如下所示：

现在访问以下 URL：

`http://localhost:8086/Vaadin_Project1/`

您应该看到以下截图中显示的页面：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_01.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_02.jpg)

## 另请参阅

+   *使用 Vaadin 的 Spring Security - Spring 基于表单的身份验证*配方

+   *使用 Vaadin 的 Spring Security - 自定义 JSP 基于表单的身份验证*配方

+   *使用 Vaadin 的 Spring Security - 使用 Vaadin 表单*配方

# Spring Security with Vaadin – Spring 表单认证

我们将演示 Vaadin 中的基于表单的认证。这与我们在之前的配方中使用的认证非常相似。我们将编辑 `applicationContext.xml` 文件。我们不会创建任何自定义登录表单，我们希望使用 spring 内部登录表单。

## 准备工作

您必须在 `application-Context.xml` 文件中注释掉 `<http-basic/>` 标记。

## 如何做...

按照以下代码编辑 `applicationContext.xml` 文件：

```java
<http auto-config="true">
  <intercept-url pattern="/Vaadin_Project1/**"
     access="ROLE_EDITOR"/> 
  <intercept-url pattern="/Vaadin_Project1/*.*"
     access="ROLE_EDITOR"/> 
  <intercept-url pattern="/**" access="ROLE_EDITOR" />
</http>
<authentication-manager>
  <authentication-provider>
    <user-service>
       <user name="anjana" password="123456"
       authorities="ROLE_EDITOR" />
    </user-service>
  </authentication-provider>
</authentication-manager>
```

## 工作原理...

在这个例子中，调用了 spring 的内部登录表单来对 Vaadin 应用程序进行认证。这个配置是在 `applicationConext.xml` 文件中完成的。Spring 框架弹出了自己的内部 jsp 文件供用户使用。当用户输入凭据并点击 **提交** 时，他们将被重定向到 Vaadin 应用程序。运行 Tomcat 服务器。

现在访问以下 URL：

`http://localhost:8086/Vaadin_Project1/`

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_03.jpg)

这是 Spring 提供的内置登录表单。

输入登录用户名和密码，您将进入 Vaadin 产品列表。

同样，您可以通过编辑 authentication-manager 配置来使用数据库和 LDAP 进行认证。

## 另请参阅

+   *Spring Security with Vaadin – 自定义 JSP 表单认证* 配方

+   *Spring Security with Vaadin – 使用 Vaadin 表单* 配方

# Spring Security with Vaadin – 自定义 JSP 表单认证

到目前为止，我们已经演示了使用 Spring Security API 登录表单和登录弹出对话框的 Vaadin 7 应用程序。我们所做的一切都是在应用程序上下文文件中创建用户。

这次我们将为应用程序上下文赋予不同的名称，并提供一个自定义的登录表单，并使用 Vaadin 6 项目。

## 准备工作

+   创建一个示例 Vaadin 6 项目

+   在构建路径中添加与 Spring 相关的 jar 包

+   添加与 Spring Security 相关的 jar 包

+   添加 `vaadin-spring-security.xml` 文件

+   添加 `mybeans.xml` 文件

+   按照上一节中的示例编辑 `web.xml` 文件

+   还要在 `web-inf lib` 文件夹中添加与 Spring 相关的 jar 包

## 如何做...

以下步骤是使用自定义 JSP 实现基于表单的认证，使用 Vaadin 应用程序。

由于 Vaadin 6 应用程序的入口点是 `AbstractApplicationServlet`，我们将创建一个扩展 `AbstractApplicationServlet` 的类。这将给我们一个选择来重写类的方法。

我们还将创建一个扩展 `Application` 类的类。在这个类中，我们将创建一个窗口。例如，我们将在登录后添加一些文本。

我们还将在 `web.xml` 文件中添加 jsp 文件映射。

我们需要将 `MyAbstractApplicationServlet` 类映射为 `web.xml` 文件中的 Servlet。

我们还需要配置 Spring 上下文监听器和 Spring 过滤器。

1.  编辑 `web.xml` 文件：

```java
<display-name>Vaadin_Project3</display-name>
  <context-param>
    <description>Vaadin production mode</description>
    <param-name>productionMode</param-name>
    <param-value>true</param-value>
  </context-param>
  <context-param>
    <param-name>contextConfigLocation</param-name>
    <param-value>
      /WEB-INF/vaadin-spring-security.xml
      /WEB-INF/mybeans.xml
    </param-value>

  </context-param>

  <servlet>
    <servlet-name>login</servlet-name>
    <jsp-file>/jsp/login.jsp</jsp-file>
  </servlet>

  <servlet>
    <servlet-name>login_error</servlet-name>
    <jsp-file>/jsp/login_error.jsp</jsp-file>
  </servlet>

  <servlet-mapping>
    <servlet-name>login</servlet-name>
    <url-pattern>/jsp/login</url-pattern>
  </servlet-mapping>

  <servlet-mapping>
    <servlet-name>login_error</servlet-name>
    <url-pattern>/jsp/login_error</url-pattern>
  </servlet-mapping>

 <servlet>
 <servlet-name>Vaadin Application Servlet</servlet-name>
 <servlet-class>packt.vaadin.MyAbstractApplicationServlet</servlet-class>
 </servlet>

  <servlet-mapping>
    <servlet-name>Vaadin Application Servlet</servlet-name>
    <url-pattern>/*</url-pattern>

  </servlet-mapping>
```

1.  编辑 `vaadin-spring-security.xml` 文件：

```java
<global-method-security pre-post-annotations="enabled" />

<http auto-config='true'>
  <intercept-url pattern="/jsp/login*"access="IS_AUTHENTICATED_ANONYMOUSLY" />
  <intercept-url pattern="/jsp/login_error*"access="IS_AUTHENTICATED_ANONYMOUSLY" />
  <intercept-url pattern="/**" access="ROLE_USER" />
  <form-login login-page='/jsp/login'authentication-failure-url="/jsp/login_error" />
</http>

<authentication-manager>
  <authentication-provider>
    <user-service>
      <user name="raghu" password="anju"authorities="ROLE_USER,ROLE_ADMIN" />
      <user name="onju" password="bonju"authorities="ROLE_USER" />
    </user-service>
  </authentication-provider>
</authentication-manager>
```

1.  子类化并重写 `AbstractApplicationServlet` 方法。

`AbstractApplicationServlet` 类是一个抽象类，扩展了 `HttpServlet` 并实现了一个名为 *Constants* 的接口。 `Service()` 和 `init()` 方法是由 servlet 容器使用的 servlet 方法。我们创建了一个 `appContext` 对象，并在 `init()` 方法中对其进行了初始化。已重写 `getNewApplication()` 方法以获取扩展应用程序的类。已重写 `getApplication()` 方法。

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_04.jpg)

1.  实现如下：

`MyAbstractApplicationServlet`

```java
public class MyAbstractApplicationServlet extends AbstractApplicationServlet
{
  private WebApplicationContext appContext;
  private Class<? extends Application> applicationClass;

  @Override
  protected Application getNewApplication(HttpServletRequest httpServletRequest) throws ServletException {
      MainApplication mainApplication = (MainApplication)appContext.getBean("applicationBean");
      mainApplication.setWebApplicationContext(appContext);
      return  mainApplication;
    }

    @Override
    protected void service(HttpServletRequest request, HttpServletResponse response)throws ServletException, IOException {
      super.service(request, response); 
    }

    @Override
    public void init(ServletConfig servletConfig)throws ServletException {
      super.init(servletConfig);   
      appContext = WebApplicationContextUtils.getWebApplicationContext(servletConfig.getServletContext());
    }

    @Override
    protected Class<? extends Application>getApplicationClass() throws ClassNotFoundException {
    return MainApplication.class;
  }
}
```

1.  子类化并重写 `ApplicationClass` 方法。

`ApplicationClass` 是一个抽象类，实现了一些接口。我们已经重写了抽象类的 `init()` 方法。您需要创建 `HeaderHorizontalLayout` 类并将它们作为组件添加到窗口中。

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_05.jpg)

MainApplication

```java
@Component("applicationBean")
@Scope("prototype")

public class MainApplication extends Application {

  public WebApplicationContext webappContext;

  @Override
  public void init() {
    Window window;
    window = new Window("My Vaadin Application");
    window.addComponent(new HeaderHorizontalLayout(this));
    window.addComponent(new BodyHorizontalLayout(this));
    window.addComponent(new FooterHorizontalLayout(this));
    setMainWindow(window);
  }

  public void setWebApplicationContext(WebApplicationContext appContext){
  this.webappContext = webappContext;
  }

}
```

## 工作原理...

在此示例中，我们使用定制的 jsp 页面来处理对 Vaadin 应用程序的访问。当用户尝试访问 Vaadin 应用程序时，定制的 jsp 会显示给用户。用户输入用户名和密码，然后由 Spring 框架进行验证。验证成功后，Vaadin 页面将显示。

工作流程如下所示：

现在访问 URL：

`http://localhost:8086/Vaadin_Project3/`

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_06.jpg)

输入登录用户名和密码，您将被带到 Vaadin 页面。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_07.jpg)

## 另请参阅

+   *使用 Vaadin 表单的 Spring Security - 使用 Vaadin 表单*配方

# Spring Security 与 Vaadin - 使用 Vaadin 表单

到目前为止，我们已经使用了定制的 JSP 页面或 Spring 提供的登录弹出框或 JSP 文件。我们还演示了 Spring Security 与 Vaadin 6 和 Vaadin 7 的集成。因此，我很想提供一个完整的 Vaadin 与 Spring Security 实现。让我们创建一个 Vaadin 表单，并将其与 Spring Security 集成。

## 准备工作

+   在 Eclipse IDE 中创建一个 Vaadin 7 项目

+   创建一个扩展面板的`MyLoginView`类

+   创建一个扩展面板的`SecuredView`类

+   创建一个扩展`VaadinServlet`的`MyVaadinServlet`类

+   创建一个`VaadinRequestHolder`类

+   配置`web.xml`文件

+   编辑`applicationContext.xml`文件

+   为面板类实现`View`接口

## 如何做...

以下给出的步骤是为了创建一个 Vaadin 登录表单，并将其用于使用 Spring Security 对用户进行认证：

1.  `MyLoginView`将在应用程序启动时加载登录表单。

```java
public class MyLoginView extends Panel implements View {
  private Layout mainLayout;
  Navigator navigator;
  protected static final String CountView = "SecuredView";
  public MyLoginView() {
    final FormLayout loginlayout=new FormLayout();
    final TextField nameField=new TextField("name");
    final PasswordField passwordField=new PasswordField("password");
    loginlayout.addComponent(nameField);
    loginlayout.addComponent(passwordField);
    Button loginButton = new Button("Login");
    loginlayout.addComponent(loginButton);
    mainLayout = new VerticalLayout();
    mainLayout.addComponent(loginlayout);
    setContent(mainLayout);

    loginButton.addClickListener(new Button.ClickListener() {
      public void buttonClick(ClickEvent event) {
        try{
          ServletContext servletContext = VaadinRequestHolder.getRequest().getSession().getServletContext();
          UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(nameField.getValue(),passwordField.getValue());
            token.setDetails( new WebAuthenticationDetails(VaadinRequestHolder.getRequest()));
            WebApplicationContext wac = WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
            AuthenticationManager authManager = wac.getBean(AuthenticationManager.class);
            Authentication authentication = authManager.authenticate(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            if(authentication.isAuthenticated()){
              Notification.show("You are authenticated");
            navigator = new Navigator(getUI().getCurrent(), mainLayout);
            navigator.addView(CountView, new SecuredView());
            navigator.navigateTo(CountView);
          }

    } catch (BadCredentialsException e) {

      Notification.show("Bad credentials");
    }
  }
});

}
@Override
public void enter(ViewChangeEvent event) {
}
```

我们使用了表单布局，并添加了用户名和密码字段。我们添加了一个按钮。点击按钮时，我们进行认证。

我们在`requestHolder.UserNamePasswords`中捕获`VaadinRequest`对象。认证令牌接收来自用户名和密码字段的输入。然后将令牌传递给`AuthenticationManger`以验证字段。如果认证成功，它将导航到受保护的页面。它还会向用户发出通知。

1.  在认证后使用`Secured View`并提供注销功能。

```java
public class SecuredView extends Panel implements View {
  public static final String NAME = "count";
  private Layout mainLayout;
  Navigator navigator;
  protected static final String MainView = "LoginView";
  public SecuredView() {
    mainLayout = new VerticalLayout();
    mainLayout.addComponent(new Label("You are seeing a secured page"));
    Button logoutButton = new Button("Logout");
    mainLayout.addComponent(logoutButton);
    setContent(mainLayout);
    logoutButton.addClickListener(new Button.ClickListener() {
    public void buttonClick(ClickEvent event) {
    try{
      ServletContext servletContext = VaadinRequestHolder.getRequest().getSession().getServletContext();
      WebApplicationContext wac = WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
      LogoutHandler logoutHandler = wac.getBean(LogoutHandler.class);
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      logoutHandler.logout(VaadinRequestHolder.getRequest(), null, authentication);

 Notification.show("You are logged out");
 navigator = new Navigator(getUI().getCurrent(), mainLayout);
 navigator.addView(MainView, new MyLoginView());
 navigator.navigateTo(MainView);
    } catch (BadCredentialsException e) {

    Notification.show("Bad credentials");
    }
  }
});
}

public void enter(ViewChangeEvent event) {

}

}
```

受保护的视图有一个标签和一个注销按钮。注销按钮点击事件处理`springlogout`。注销时，用户将被重定向到登录页面。`LogoutHandler`类有一个`logout()`方法来处理认证。我使用了导航器类。您可以使用 UI 类`getUI.Current`创建导航器的实例，它会给出一个 UI 对象。

这种方法可以在您的面板类中使用。我还将布局对象传递给构造函数。

```java
navigator = new Navigator(getUI().getCurrent(),mainLayout);
navigator.addView(MainView, new MyLoginView());
navigator.navigateTo(MainView);
```

以下是两个类的图示表示：

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_08.jpg)

1.  扩展 Vaadin servlet 以捕获请求对象。

`MyVaadinServlet`

```java
public class MyVaadinServlet extends VaadinServlet {
  @Override
  protected void service(HttpServletRequest request,HttpServletResponse response) throws ServletException,IOException {
  SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
  VaadinRequestHolder.setRequest(request);
  super.service(request, response);
  VaadinRequestHolder.clean();
  SecurityContextHolder.clearContext();
  }
}
```

Vaadin servlet 在`web.xml`文件中进行配置。它接受 UI 类作为参数。在前面的代码中，我们扩展了 Vaadin servlet 并重写了`service()`方法，在其中我们将请求传递给`VaadinRequestHolder`类。通过这样做，我们将上下文对象传递给`SecurityContextHolder`以开始认证。

![如何做...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_09.jpg)

1.  在 UI 类中注册视图。

`Vaadin_project5UI`

```java
@SuppressWarnings("serial")
@Theme("vaadin_project5")
public class Vaadin_project5UI extends UI{
  private Layout mainLayout;
  Navigator navigator;
  protected static final String CountView = "main";
  @Override
  protected void init(VaadinRequest request) {
    getPage().setTitle("Navigation Example");
    // Create a navigator to control the views
    navigator = new Navigator(this, this);
    // Create and register the views
    navigator.addView("", new MyLoginView());
    navigator.addView(CountView, new SecuredView());
  }
}
```

在此代码中，我们注册了`LoginView`和`SecuredView`，默认登录视图将被调用。

1.  配置`web.xml`文件：

```java
<display-name>Vaadin_Project5</display-name>
<context-param>
  <description>
  Vaadin production mode</description>
  <param-name>productionMode</param-name>
  <param-value>false</param-value>
</context-param>
<servlet>
 <servlet-name>Vaadin_project5 Application</servlet-name>
 <servlet-class>com.example.vaadin_project5.MyVaadinServlet</servlet-class>
 <init-param>
 <description>
 Vaadin UI class to use</description>
 <param-name>UI</param-name>
 <param-value>com.example.vaadin_project5.Vaadin_project5UI</param-value>
 </init-param>
 <init-param>
 <description>
 Legacy mode to return the value of the propertyas a string from AbstractProperty.toString()</description>
 <param-name>legacyPropertyToString</param-name>
 <param-value>false</param-value>
 </init-param>
</servlet>
<servlet-mapping>
 <servlet-name>Vaadin_project5 Application</servlet-name>
 <url-pattern>/*</url-pattern>
</servlet-mapping>
<listener>
 <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
</listener>
</web-app>
```

我们在`web.xml`中配置了`MyVaadinServlet`。

1.  编辑`application-Context.xml`文件。

```java
<global-method-security pre-post-annotations="enabled" />
<authentication-manager>
  <authentication-provider>
    <user-service>
    <user name="anjana" password="123456"authorities="ROLE_EDITOR" />
    </user-service>
  </authentication-provider>
</authentication-manager>
<beans:bean class="org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler">
  <beans:property name="invalidateHttpSession"value="false" />
</beans:bean>
</beans:beans>
```

## 它是如何工作的...

在这个例子中，我们创建了一个 Vaadin 登录表单。如果开发人员不想使用外部 jsp，这是使用 Vaadin 框架类创建登录表单的另一个选项。这将使它成为一个纯 Vaadin 应用程序，其中包含一个 Spring Security 应用程序。在显示实际的产品目录页面之前，用户会通过 Spring Security 进行身份验证和授权。Vaadin 表单将用户的凭据提交给 Spring Security 框架，进行身份验证和授权。`MyVaadinServlet`类与 Spring Security 上下文通信，以在 Vaadin 应用程序中设置安全上下文。

Spring Security 与 Vaadin 的工作流程如下所示：

+   运行 Tomcat 服务器。

+   现在访问 URL：

`http://localhost:8086/Vaadin_Project5/`

以下截图显示了 Vaadin 登录表单：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_010.jpg)

它还会显示有关错误凭据的消息：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_011.jpg)

身份验证后，您将被导航到受保护的页面：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_012.jpg)

单击**注销**，您将被带回登录视图。以下截图显示了信息：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_06_013.jpg)


# 第七章：使用 Wicket 的 Spring Security

在本章中，我们将涵盖：

+   Spring Security 与 Wicket - 基本数据库身份验证

+   Spring Security 与 Wicket - Spring 基于表单的数据库身份验证

+   Spring Security 与 Wicket - 自定义 JSP 基于表单的数据库身份验证

+   使用 Wicket 授权的 Spring 身份验证

+   使用 Wicket 和 Spring Security 的多租户

# 介绍

在启动 Wicket 之前，我们正在检查可用版本。最新版本是 6.9。在 Apache Wicket 网站上明确指出，最新项目应该使用版本 6.9 作为基础。我们在下载了 NetBeans 7.1 后，发现 NetBeans Wicket 插件支持 Wicket 的 1.5 版本。

我们更喜欢使用最新的稳定版本；它将有许多错误修复和升级，并且将更容易开发。

Wicket 还使用*Wicket 过滤器*来分派请求和响应。就像 GWT 和 Vaadin 应用程序一样，它们有 servlet，期望一些参数，如 UI 类来初始化，我们需要提供一个扩展`Web Application`类的类名作为过滤器的参数。然后有一些类，它们扩展了`WebPage`类。创建一个与扩展`WebPage`类相同名称的 HTML 页面是一个很好的惯例和实践。

Wicket 使用多级继承方法。我们必须扩展`Wicket`类以实现各种场景。它还具有内置的身份验证和授权 API。

## 设置数据库

以下代码将设置数据库：

```java
CREATE TABLE `users1` (
  `USER_ID` INT(10) UNSIGNED NOT NULL,
  `USERNAME` VARCHAR(45) NOT NULL,
  `PASSWORD` VARCHAR(45) NOT NULL,
  `ENABLED` tinyint(1) NOT NULL,
  PRIMARY KEY (`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
CREATE TABLE `user_roles` (
  `USER_ROLE_ID` INT(10) UNSIGNED NOT NULL,
  `USER_ID` INT(10) UNSIGNED NOT NULL,
  `AUTHORITY` VARCHAR(45) NOT NULL,
  PRIMARY KEY (`USER_ROLE_ID`),
  KEY `FK_user_roles` (`USER_ID`),
  CONSTRAINT `FK_user_roles` FOREIGN KEY (`USER_ID`) REFERENCES `users` (`USER_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
```

## 设置 Wicket 应用程序

以下语句是需要执行的 Maven 命令。您应该在您的机器上安装 Maven，并且应该有一个本地存储库。默认情况下，它在`.m2\repository`中。运行命令后，您应该获得构建成功的信号，这将让我们开始 Wicket 实现：

```java
mvn archetype:generate -DarchetypeGroupId=org.apache.wicket -DarchetypeArtifactId=wicket-archetype-quickstart -DarchetypeVersion=6.9.1 -DgroupId=com.packt -DartifactId=spring-security-wicket -DarchetypeRepository=https://repository.apache.org/ -DinteractiveMode=false

```

在命令提示符上可见以下输出：

```java
[INFO] Parameter: groupId, Value: com.packt
[INFO] Parameter: artifactId, Value: spring-security-wicket
[INFO] Parameter: version, Value: 1.0-SNAPSHOT
[INFO] Parameter: package, Value: com.packt
[INFO] Parameter: packageInPathFormat, Value: com/packt
[INFO] Parameter: version, Value: 1.0-SNAPSHOT
[INFO] Parameter: package, Value: com.packt
[INFO] Parameter: groupId, Value: com.packt
[INFO] Parameter: artifactId, Value: spring-security-wicket
[INFO] project created from Archetype in dir: E:\spring-security-wicket
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time: 1:22.610s
[INFO] Finished at: Mon Jul 15 21:17:24 IST 2013
[INFO] Final Memory: 7M/13M
[INFO] ------------------------------------------------------------------------

```

以下命令将完成 Wicket 的完整设置。它们还将下载 Wicket 框架源文件到存储库中。

```java
Spring-security-wicket>mvn clean compile install
Spring-security-wicket>mvn tomcat:run
Spring-security-wicket>mvn eclipse: eclipse

```

访问以下 URL：

`http://localhost:8080/spring-security-wicket/`

该 URL 将显示 Wicket 应用程序的欢迎页面。Wicket 应用程序设置已准备就绪。

Wicket 还配备了自己的身份验证和授权 API。让我们看看如何使用它。

# Spring Security 与 Wicket - 基本数据库身份验证

我们的目标是在 Wicket 应用程序上进行简单的基本身份验证。当我们访问 Wicket 应用程序的 URL 时，我希望出现登录对话框。成功后，它应该重定向到主页。我们需要向`pom.xml`文件添加 Spring Security 依赖项并重新构建 Wicket 应用程序。下一步将是在`web.xml`文件中配置 spring 监听器。我们还需要添加`applicationContext.xml`文件。

## 准备工作

+   使用 Spring 依赖项更新`pom.xml`文件。

+   创建一个`applicationContext.xml`文件。必须将其命名为`applicationContext`，否则我们将在控制台中收到错误消息。

+   使用 Spring 监听器编辑`web.xml`。

+   创建一个`database-details.xml`文件并添加数据库详细信息。

+   将`db-details.xml`文件添加为`context-param`到 spring 监听器。

## 如何做...

以下是使用 Wicket 实现 Spring Security 以演示基本身份验证的步骤，其中凭据存储在数据库中：

1.  向`POM.xml`文件添加依赖项：

```java
<!-- Spring dependecncies -->
  <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-core</artifactId>
    <version>${spring.version}</version>
  </dependency>

  <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-web</artifactId>
    <version>${spring.version}</version>
  </dependency>

  <dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-webmvc</artifactId>
    <version>${spring.version}</version>
  </dependency>

  <!-- Spring Security -->
  <dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-core</artifactId>
    <version>${spring.version}</version>
  </dependency>

  <dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-web</artifactId>
    <version>${spring.version}</version>
  </dependency>

  <dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-config</artifactId>
    <version>${spring.version}</version>
  </dependency>
  <!-- WICKET DEPENDENCIES -->
  <dependency>
    <groupId>org.apache.wicket</groupId>
    <artifactId>wicket-core</artifactId>
    <version>${wicket.version}</version>
  </dependency>
  <!-- WICKET Authentication-DEPENDENCIES -->
  <dependency>
    <groupId>org.apache.wicket</groupId>
    <artifactId>wicket-auth-roles</artifactId>
    <version>6.9.1</version>
  </dependency>
```

1.  使用 Spring 监听器和 Spring 过滤器更新`Web.xml`文件与 Wicket 过滤器：

```java
<filter>
  <filter-name>springSecurityFilterChain</filter-name>
  <filter-class>
    org.springframework.web.filter.DelegatingFilterProxy
    </filter-class>
</filter>

<filter-mapping>
  <filter-name>springSecurityFilterChain</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>

<listener>
  <listener-class>
    org.springframework.web.context.ContextLoaderListener
    </listener-class>
</listener>

<filter>
  <filter-name>wicket.spring-security-wicket</filter-name>
<filter-class>
  org.apache.wicket.protocol.http.WicketFilter</filter-class>
  <init-param>
    <param-name>applicationClassName</param-name>
    <param-value>com.packt.WicketApplication</param-value>
  </init-param>
</filter>

<filter-mapping>
  <filter-name>wicket.spring-security-wicket</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

1.  编辑`applicationContext.xml`文件：

```java
<global-method-security pre-post-annotations="enabled" />

<http auto-config="true">
  <intercept-url pattern="/spring-security-wicket/**" 
    access="ROLE_SELLER"/> 
  <intercept-url pattern="/spring-security-wicket/*.*" 
    access="ROLE_SELLER"/> 
  <intercept-url pattern="/**"access="ROLE_SELLER" />
  <http-basic />
</http>

<authentication-manager>
  <authentication-provider>
    <jdbc-user-service data-source-ref="MySqlDS" 
      users-by-username-query=" 
      select username,password, enabled   
      from users1 where username=?"  
      authorities-by-username-query=" 
      select u.username, ur.role from users1 u,user_roles ur  
    where u.user_id = ur.user_id and u.username =?  " />
  </authentication-provider>
</authentication-manager>
```

这是一个简单的基本身份验证配置。通过此配置，我们期望在显示 Wicket 应用程序之前出现登录对话框。我创建了一个新角色，卖家。

## 它是如何工作的...

现在访问以下 URL：

`http://localhost:8080/spring-security-wicket/`

这是将 Spring Security 与 Wicket 集成的初始设置示例。我们已经演示了基本的身份验证机制。通过登录表单，Spring Security 中断对 Wicket 应用程序的访问。成功认证后，用户将获得对 Wicket 应用程序的访问权限。

显示的页面如下截图所示：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_01.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_02.jpg)

## 另请参阅

+   使用 Wicket 的 Spring Security-Spring 基于表单的身份验证

+   使用 Wicket 的 Spring Security-定制的 JSP 基于表单的身份验证

+   使用 Wicket 授权的 Spring 身份验证

+   使用 Wicket 和 Spring Security 的多租户

# 使用 Wicket 的 Spring Security-Spring 基于表单的数据库身份验证

在我们之前的示例中，我们发现 Wicket 6.9 与 Spring Security 非常兼容，并且很容易集成。我们所做的就是添加 spring 依赖项并配置`applicationContext.xml`文件。

在本节中，我们将使用 Spring 表单进行身份验证。我们期望 Spring 表单出现在对话框的位置，并为我们进行身份验证。

## 准备工作

+   创建一个 Maven Wicket 项目：`spring-security-wicket_springform`。

+   使用 Spring 依赖项更新`pom.xml`文件。

+   创建一个`applicationContext.xml`文件。必须将其命名为`applicationContext`，否则我们将在控制台中收到错误消息。

+   编辑`web.xml`，使用 Spring 监听器。

+   创建一个数据库`details.xml`文件，并添加数据库详细信息。

+   将文件添加为 Spring 监听器的上下文参数。

## 如何做...

使用以下代码编辑`applicationContext.xml`文件：

```java
<global-method-security pre-post-annotations="enabled" />

<http auto-config="true">
  <intercept-url pattern="/spring-security-wicket/**" 
    access="ROLE_SELLER"/> 
  <intercept-url pattern="/spring-security-wicket/*.*" 
    access="ROLE_SELLER"/> 
  <intercept-url pattern="/**" access="ROLE_SELLER" />
</http>

<authentication-manager> 
  <authentication-provider> 
    <jdbc-user-service data-source-ref="MySqlDS" 
    users-by-username-query=" 
    select username,password, enabled   
    from users1 where username=?"  

    authorities-by-username-query=" 
    select u.username, ur.role from users1 u, user_roles ur  
    where u.user_id = ur.user_id and u.username =?  " /> 
  </authentication-provider>
</authentication-manager>
```

这是一个简单的表单身份验证配置。使用此配置，我们期望在显示 Wicket 应用程序之前有一个**登录页面**。唯一的变化是我们已经删除了先前应用程序的`<http-basic>`标签。还要注意 URL，它将具有会话 ID。

## 它是如何工作的...

现在访问以下 URL：

`http://localhost:8080/spring-security-wicket_springform/`

在这个示例中，我们展示了如何在 Wicket 应用程序中调用 Spring 的内部登录表单。当我们访问 Wicket 应用程序时，我们将被重定向到 Spring 自己的登录页面。用户输入他们的用户名和密码，这将由 Spring 的身份验证提供者进行验证和授权。成功后，用户将获得对 Wicket 应用程序的访问权限。

当您访问上述 URL 时，您应该看到以下屏幕：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_03.jpg)

## 另请参阅

+   使用 Wicket 的 Spring Security-定制的 JSP 基于表单的身份验证

+   使用 Wicket 授权的 Spring 身份验证

+   使用 Wicket 和 Spring Security 进行多租户

# 使用 Wicket 的 Spring Security-定制的 JSP 基于表单的数据库身份验证

前两个示例是为了测试 Wicket 与 Spring Security 的兼容性。它还演示了将 Spring 与 Wicket 集成的简单性。我们从我们的两个 Wicket 示例中学到，我们可以很容易地使用基于 Spring 和基于表单的身份验证与数据库，并且同样可以扩展到 LDAP。

在这个示例中，我们将添加一个定制的 JSP 表单。我们期望 Wicket 应用程序调用我们的 JSP 表单进行登录。如果开发人员不想创建一个 Wicket 表单，他们可以使用这种方法。这种方法也适用于 GWT 和 Vaadin。

您还需要为登录页面提供匿名访问权限。

## 准备工作

+   创建一个 Maven Wicket 项目：`spring-security-wicket_customized_jsp`。

+   使用 Spring 依赖项更新`pom.xml`文件。

+   创建一个`applicationContext.xml`文件。必须将其命名为`applicationContext`，否则我们将在控制台中收到错误消息。

+   编辑`web.xml`，使用 Spring 监听器。

+   还要将`login.js`p 配置添加为`web.xml`中的 servlet。

+   创建一个数据库，`details.xml`文件，并添加数据库详细信息。

+   将文件添加为 Spring 监听器的上下文参数。

+   此外，您需要添加一个`login.jsp`；您可以使用上一章中使用的`login.jsp`文件。

## 操作步骤...

以下步骤是为了将 Spring Security 与 Wicket 框架集成，以演示使用自定义 JSP 的基于表单的身份验证：

1.  编辑`applicationContext.xml`文件：

```java
<global-method-security pre-post-annotations="enabled" />

<http auto-config='true'>
  <intercept-url pattern="/jsp/login*" 
    access="IS_AUTHENTICATED_ANONYMOUSLY" />
  <intercept-url pattern="/jsp/login_error*" 
    access="IS_AUTHENTICATED_ANONYMOUSLY" />
  <intercept-url pattern="/**" access="ROLE_SELLER" />
  <form-login login-page='/jsp/login' 
    authentication-failure-url="/jsp/login_error" />
</http> 
<authentication-manager> 
  <authentication-provider> 
    <jdbc-user-service data-source-ref="MySqlDS" 
    users-by-username-query=" 
    select username,password, enabled   
    from users1 where username=?"  

    authorities-by-username-query=" 
    select u.username, ur.role from users1 u, user_roles ur  
    where u.user_id = ur.user_id and u.username =?  " /> 
  </authentication-provider>
</authentication-manager>
```

`login.jsp`已在`applicationContext.xml`文件中配置为匿名用户。

1.  编辑`web.xml`文件：

```java
<servlet>
  <servlet-name>login</servlet-name>
  <jsp-file>/jsp/login.jsp</jsp-file>
</servlet>

<servlet>
  <servlet-name>login_error</servlet-name>
  <jsp-file>/jsp/login_error.jsp</jsp-file>
</servlet>

<servlet-mapping>
  <servlet-name>login</servlet-name>
  <url-pattern>/jsp/login</url-pattern>
</servlet-mapping>

<servlet-mapping>
  <servlet-name>login_error</servlet-name>
  <url-pattern>/jsp/login_error</url-pattern>
</servlet-mapping>
```

`login.jsp`已配置为一个 servlet。

## 工作原理...

现在访问以下 URL：

`http://localhost:8080/spring-security-wicket_springform/`

在这个示例中，我们将 Wicket 应用与我们自己的`login.jsp`文件集成，以进行身份验证和授权。当用户尝试访问 Wicket 应用时，Spring Security 会阻止用户访问提供在`applicationContext.xml`中创建和配置的 jsp 页面的应用。提交后，将触发 Spring Security 身份验证操作，进行身份验证和授权。成功后，用户将获得访问 Wicket 应用的权限。

访问此 URL 时，您应该看到以下屏幕截图：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_03.jpg)

## 另请参阅

+   *使用 Wicket 授权的 Spring 身份验证*示例

+   *使用 Wicket 和 Spring Security 进行多租户*示例

# 使用 Wicket 授权的 Spring 身份验证

到目前为止，我们已经看到了在 Wicket 应用之外使用 Spring Security 的各种选项。现在我们将看到如何在 wicket 框架中创建安全表单，并在 Spring 框架中使用它来实现两种不同的角色。该示例还演示了如何在 Wicket 应用中使用 Spring bean。

## 准备工作完成。

+   创建一个 Maven Wicket 项目：`spring-security-wicket`。

+   使用 Spring 依赖项更新`pom.xml`文件。

+   创建`applicationContext.xml`文件。必须将其命名为`applicationContext`，否则将在控制台中收到错误消息。

+   添加一个`spring-wicket-security`依赖项。

+   使用 Spring 监听器编辑`web.xml`。

+   分别创建`EditorPage.html`和`AuthorPage.html`以及相应的`EditorPage.java`和`AuthorPage.java`。作者页面和编辑页面是相似的页面，但根据角色调用。

+   创建`HomePage.java`和`HomePage.html`。

+   创建`SignInPage.html`和`SignInPage.java`。

+   子类化`AuthenticatedWebSession`类，并覆盖超类中的方法。默认情况下，它使用 Wicket 身份验证，因此覆盖它以使用 Spring 身份验证。

## 操作步骤...

1.  下一步是使用 Spring 安全进行身份验证和使用 spring Wicket 进行授权，编辑`application-Context.xml`。

```java
<!-- Enable annotation scanning -->
<context:component-scan base-package="com.packt.wicket" />

</beans>
```

1.  编辑`spring-wicket-security.xml`文件：

```java
<security:authentication-manager alias="springauthenticationManager">
  <security:authentication-provider>
<!--  TODO change this to reference a real production environment user service -->
    <security:user-service>
      <security:user name="jimmy" password="jimmy" authorities="ROLE_EDITOR, ROLE_AUTHOR"/>
      <security:user name="tommy" password="tommy" authorities="ROLE_EDITOR"/>
    </security:user-service>
  </security:authentication-provider>
</security:authentication-manager>

<security:global-method-security secured-annotations="enabled" />
```

1.  编辑`AuthorPage.java`文件：

```java
@AuthorizeInstantiation("ROLE_AUTHOR")
public class AuthorPage extends WebPage {

  @SpringBean
  private SomeInterfaceImpl someInterfaceImpl;

  public AuthorPage(final PageParameters parameters) {
    super(parameters);
    add(new Label("msg", someInterfaceImpl.method1()));
    add(new Link("Editor"){
      @Override
      public void onClick() {
        Page next = new EditorPage();
        setResponsePage(next);
      }
    });
    add(new Link("Logout"){
      @Override
      public void onClick() {
        getSession().invalidate();
        Page next = new HomePage(parameters);
        setResponsePage(next);
      }
    });
  }
}
```

1.  编辑`SigInPage.java`文件：

```java
public final class SignInPage extends WebPage
{
  /**
  * Constructor
  */
  public SignInPage()
  {
    final SignInForm form = new SignInForm("signinForm");
    add(form);
  }

  /**
  * Sign in form
  */
  public final class SignInForm extends Form<Void>
  {
    private String username;
    private String password;

    public SignInForm(final String id)
    {
      super(id);
      setModel(new CompoundPropertyModel(this));
      add(new RequiredTextField("username"));
      add(new PasswordTextField("password"));
      add(new FeedbackPanel("feedback"));
    }

    @Override
    public final void onSubmit()
    {
      MyWebSession session = getMySession();
      if (session.signIn(username,password))
      {

        setResponsePage(getApplication().getHomePage());

      }
      else
      {
        String errmsg = getString("loginError", null,
           "Unable to sign you in");

      }
    }
    private MyWebSession getMySession()
    {
      return (MyWebSession)getSession();
    }
  }
}
```

1.  编辑`HomePage.java`文件：

```java
public class HomePage extends WebPage {
  private static final long serialVersionUID = 1L;
  @SpringBean
  private SomeInterfaceImpl someInterfaceImpl;
  public HomePage(final PageParameters parameters) {
    super(parameters);
    add(new Label("version", getApplication()
      .getFrameworkSettings().getVersion()));
    add(new Label("msg", someInterfaceImpl.method1()));
    add(new Link("click if you are Editor"){
      @Override
      public void onClick() {
        Page next = new EditorPage();
        setResponsePage(next);
      }
    });

    add(new Link("Click if You are Author"){
      @Override
      public void onClick() {
        Page next = new AuthorPage(parameters);
        setResponsePage(next);
      }
    });

  }

}
```

1.  编辑`MyWebSession.java`文件：

```java
public class HomePage extends WebPage {
  private static final long serialVersionUID = 1L;
  @SpringBean
  private SomeInterfaceImpl someInterfaceImpl;
  public HomePage(final PageParameters parameters) {
    super(parameters);
    add(new Label("version", getApplication()
      .getFrameworkSettings().getVersion()));
    add(new Label("msg", someInterfaceImpl.method1()));
    add(new Link("click if you are Editor"){
      @Override
      public void onClick() {
        Page next = new EditorPage();
        setResponsePage(next);
      }
    });

    add(new Link("Click if You are Author"){
      @Override
      public void onClick() {
        Page next = new AuthorPage(parameters);
        setResponsePage(next);
      }
    });

  }

}
```

## 工作原理...

实现非常简单；我们需要做的就是拥有一个 Wicket 登录表单。单击**提交**后，我们需要获得经过身份验证的会话，这种方法将为我们提供一个选项，将 Spring 安全集成到我们使用 Wicket 应用创建的登录表单中。成功后，Spring 将验证用户凭据，并与 Wicket 框架通信以显示相应的授权页面。

Wicket 应用与 Spring 安全集成的工作流程如下所述。

当用户单击 URL：`http://localhost:8080/spring-security-wicket/`时，允许用户访问主页。主页显示两个链接，表示两个不同的角色和用户。成功验证后，用户将被授权使用基于角色的相应页面。这些页面显示在以下屏幕截图中：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_06.jpg)

应用启动时的主页

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_07.jpg)

登录页面

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_05.jpg)

作者页面

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_08.jpg)

## 另请参阅

+   使用 Wicket 和 Spring Security 实现多租户

# 使用 Wicket 和 Spring Security 实现多租户

多租户已成为云中的流行词。在多租户设置中，每个租户将有一个单独的数据源。我们需要为数据源创建两个不同的数据源和查找。让我们使用一个简单的 Wicket 应用程序和一个自定义的 JSP，其中将有一个租户下拉菜单。用户从下拉菜单中选择一个租户，将设置与租户对应的数据源。

我正在使用 NetBeans IDE，它可以轻松识别 Maven 项目。NetBeans 还带有 glassfish 应用服务器和 derby 数据库。

## 准备工作

+   更新`login.jsp`文件

+   使用 derby 数据库依赖更新`pom.xml`文件

+   编辑`applicationContext.xml`

+   编辑`spring-security.xml`

+   编辑`web.xml`文件

+   创建一个过滤器来捕获租户 ID

+   还在 derby 中创建两个数据库

+   在两个数据库中创建两个表`USERS`和`USER_ROLES`

+   在`USERS`（`USER_ID`，`USERNAME`和`PASSWORD`）中添加列

+   在`USER_ROLES`（`USER_ID`，`USER_ROLE_ID`和`AUTHORITY`）中添加列

## 如何做...

以下步骤用于在 Wicket 应用程序中使用 Spring Security API 实现多租户：

1.  在`application-Context.xml`文件中编辑两个数据源：

```java
<!-- Enable annotation scanning -->
<context:component-scan base-package="com.packt.wicket" />

  <bean id="derbydataSource" class="com.packt.wicket.TenantRoutingDataSource ">
    <property name="targetDataSources">
      <map>
        <entry key="Tenant1" value-ref="tenant1DataSource"/>
        <entry key="Tenant2" value-ref="tenant2DataSource"/>
      </map>
    </property>
  </bean>
 <bean id="tenant1DataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
 <property name="driverClassName" value="org.apache.derby.jdbc.EmbeddedDriver" />
 <property name="url" value="jdbc:derby://localhost:1527/client1" />
 <property name="username" value="client1" />
 <property name="password" value="client1" />

 </bean>
<bean id="tenant2DataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
 <property name="driverClassName" value="org.apache.derby.jdbc.EmbeddedDriver" />
 <property name="url" value="jdbc:derby://localhost:1527/client2" />
 <property name="username" value="client2" />
 <property name="password" value="client2" />

</bean>

```

1.  编辑`spring-wicket-security.xml`文件，并添加`ExceptionMappingAuthenticationFailureHandler` bean 来捕获 SQL 异常：

```java
<bean id="authenticationFailureHandler"
  class="org.springframework.security.web.authentication.ExceptionMappingAuthenticationFailureHandler">
  <property name="exceptionMappings">
    <props>
      <prop key="org.springframework.security.authentication.BadCredentialsException">/jsp/login?error='badCredentials'</prop>
      <prop key="org.springframework.security.authentication.CredentialsExpiredException">/jsp/login?error='credentialsExpired'</prop>
      <prop key="org.springframework.security.authentication.LockedException">/jsp/login?error='accountLocked'</prop>
      <prop key="org.springframework.security.authentication.DisabledException">/jsp/login?error='accountDisabled'</prop>
      </props>
    </property>
  </bean>
  <security:http auto-config='true'>
    <security:intercept-url pattern="/jsp/login*" access="IS_AUTHENTICATED_ANONYMOUSLY" />
    <security:intercept-url pattern="/jsp/login_error*"access="IS_AUTHENTICATED_ANONYMOUSLY" />
    <security:intercept-url pattern="/**" access="ROLE_SELLER" />
    <security:form-login login-page='/jsp/login' authentication-failure-handler-ref="authenticationFailureHandler" />
  </security:http>
  <security:authentication-manager>
    <security:authentication-provider>
      <security:jdbc-user-service data-source-ref="derbydataSource"
          users-by-username-query=" select username,password,'true'as enabled from users where username=?"  

          authorities-by-username-query=" 
          select u.username as username, ur.authority as authority from users u, user_roles ur  
          where u.user_id = ur.user_id and u.username =?"
      /> 
    </security:authentication-provider>  
  </security:authentication-manager>

<security:global-method-security secured-annotations="enabled" />
```

1.  编辑`login.jsp`文件：

```java
Login here--customized---login page
<form action="/ /Multitenant-spring-security-
  wicket//j_spring_security_check" method="post">
  <table>
    <tr>
      <td>
        User
      </td>
      <td>
        <input name="j_username">
      </td>
    </tr>
    <tr>
      <td>
        Password
      </td>
      <td>
        <input type="password" name="j_password"/>
      </td>
    </tr>

    <tr><td><label>Tenant:&nbsp;</label></td><td> 
      <select style="width:146px" id="tenant" name="tenant">
      <option value="">Choose Tenant</option>
      <option value="Tenant1">Tenant 1</option>
      <option value="Tenant2">Tenant 2</option></select></td>
    </tr>
    <tr>
      <td>
        <input type="submit" value="login">
      </td>
    </tr>
  </table>
</form>
</div>
```

1.  编辑`TenantRoutingDataSource.java`文件以将租户路由到不同的数据源。该类是 spring 的`AbstractRoutingDataSource`的子类。它用于设置数据源。

URL：[`docs.spring.io/spring/docs/3.1.x/javadoc-api/org/springframework/jdbc/datasource/lookup/AbstractRoutingDataSource.html`](http://docs.spring.io/spring/docs/3.1.x/javadoc-api/org/springframework/jdbc/datasource/lookup/AbstractRoutingDataSource.html)。

```java
public class TenantRoutingDataSource extends AbstractRoutingDataSource {
  protected final Log logger = LogFactory.getLog(this.getClass());

  protected Object determineCurrentLookupKey() {

    String lookupKey = (String)ThreadLocalContextUtil.getTenantId();
    System.out.println(lookupKey+"------lookupKey");

    return lookupKey;
  }
}
```

1.  编辑`MultitenantFilter`以捕获租户类型并设置数据源：

```java
public void doFilter(ServletRequest request,
   ServletResponse response,FilterChain chain)
   throws IOException, ServletException {
  if (null == filterConfig) {
    return;
  }
  HttpServletRequest httpRequest = (HttpServletRequest)
     request;

  ThreadLocalContextUtil.clearTenant();
  if (httpRequest.getRequestURI()
    .endsWith(SPRING_SECURITY_LOGOUT_MAPPING)) {
    httpRequest.getSession()
      .removeAttribute(TENANT_HTTP_KEY);
  }

  String tenantID = null;
  if (httpRequest.getRequestURI()
    .endsWith(SPRING_SECURITY_CHECK_MAPPING)) {
    tenantID = request.getParameter(TENANT_HTTP_KEY);
    httpRequest.getSession().setAttribute
      (TENANT_HTTP_KEY, tenantID);
  } else {
    tenantID = (String) httpRequest.getSession()
      .getAttribute(TENANT_HTTP_KEY);
  }

  if (null != tenantID) {
    ThreadLocalContextUtil.setTenantId(tenantID);
    if (logger.isInfoEnabled()) logger.info
      ("Tenant context set with Tenant ID: " + tenantID);
    }

  chain.doFilter(request, response);
}
```

## 工作原理...

当用户尝试访问应用程序时，他们将被重定向到登录表单，在该表单中用户输入他们的用户名和密码并选择租户。这也可以是根据业务需求的公司名称或位置。根据所选的租户，Spring 设置认证提供程序。`MultitenantFilter`与`TenantRoutingDataSource`类在`threadLocalUtil`中设置租户信息。用户使用租户数据源进行身份验证，并进入主页。

应用程序启动时的登录页面将如下截图所示：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_10.jpg)

登录页面

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_11.jpg)

如果租户不存在，则出现异常

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_07_12.jpg)

显示选择的错误凭证异常


# 第八章：使用 ORM 和 NoSQL DB 的 Spring 安全

在本章中，我们将涵盖：

+   Spring Security 与 Hibernate 一起使用@preAuthorize 注释

+   Spring Security 与 Hibernate 一起使用身份验证提供程序和@preAuthorize 注释

+   Spring Security 与 Hibernate 一起使用用户详细信息服务和 Derby 数据库

+   Spring Security 与 MongoDB

# 介绍

Spring 框架已经设计成可以轻松集成类似于 Mybatis、Hibernate 等 ORM 框架。Hibernate 教程非常详细，并且可以在 JBoss 网站上找到。Hibernate 为我们提供了数据持久性。

在本章中，我们将看到如何将 Spring Security 与 ORM 框架集成。我们还将将 Spring Security 与最新的 MongoDB 集成。

我们将首先进行一些与 Hibernate 和 Spring 相关的基本设置。由于本章涉及数据库相关内容，我们需要为本章中使用的所有食谱创建一个数据库。我正在使用带有 maven 的 NetBeans IDE。我觉得 NetBeans IDE 与其他 IDE 相比非常先进。

## 设置 Spring Hibernate 应用程序

我们将创建一个简单的恐怖电影应用程序，该应用程序将在 UI 中显示一系列恐怖电影，并具有一些**CRUD**（**创建、读取、更新和删除**）功能。设置*Spring Hibernate*应用程序涉及以下步骤：

1.  在 Derby 中创建一个`horrormoviedb`数据库。您可以使用 NetBeans。

1.  单击**服务**选项卡，您将看到**数据库**。

1.  右键单击**JavaDB**以查看**创建数据库...**选项。选择**创建数据库...**选项。![设置 Spring Hibernate 应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_01.jpg)

1.  在数据库`horrormovie`中创建一个表。![设置 Spring Hibernate 应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_02.jpg)

1.  在表中创建列，并将列命名为`horrormovie_id`、`horrormovie_name`和`horrormovie_director`。

1.  创建一个 maven 项目，更新 POM 文件以包含 Spring、Hibernate、Derby 和 Spring Security 依赖项，并在 NetBeans IDE 中打开它。

1.  使用`@table`和`@column`注释创建实体类。

1.  创建`DAO`和`DAOImpl`类来处理 Hibernate 操作。

1.  创建`Service`和`ServiceImpl`类，以在`DAO`和 UI 之间充当中间管理器。

1.  创建一个控制器来处理 UI 部分。

# Spring Security 与 Hibernate 一起使用@preAuthorize 注释

在当前演示中，我们使用了两个不同的数据库。身份验证管理器配置为`tenant1DataSource`，它连接到一个 Derby 数据库，其中保存了用户和角色信息。使用此数据源，我们将进行身份验证和授权。

为显示`horrormovie`列表，我们在 Derby 中创建了另一个数据源，该数据源与 Hibernate 配置文件一起使用。

在`DAOImpl`类的方法中，我们使用了`@preAuthorize`注释。

让我们使用 GlassFish 应用服务器来运行应用程序。

## 准备工作

+   编辑`application-security.xml`。

+   编辑`horrormovie-servlet.xml`。

+   在`DAOImpl`中使用`@preAuthorize`注释。Spring Security 在调用方法时授权用户。

## 如何做...

以下步骤将使用 Hibernate 应用程序进行身份验证和授权：

1.  使用数据源详细信息和 Bean 信息编辑`application-security.xml`文件。

```java
<global-method-security pre-post-annotations="enabled" />

  <http auto-config="false"  use-expressions="true">
    <intercept-url pattern="/login" access="permitAll" />
    <intercept-url pattern="/logout" access="permitAll" />
    <intercept-url pattern="/accessdenied" access="permitAll" />
    <intercept-url pattern="/**"access="hasRole('ROLE_EDITOR')" />
    <form-login login-page="/login" default-target-url="/list" authentication-failure-url="/accessdenied" />
    <logout logout-success-url="/logout" />
  </http>

  <authentication-manager alias="authenticationManager">
    <authentication-provider>
      <jdbc-user-service data-source-ref="tenant1DataSource"
        users-by-username-query=" select username,password ,'true' as enabled from users where username=?"  
        authorities-by-username-query=" 
        select u.username as username, ur.authority as authority from users u, user_roles ur  
        where u.user_id = ur.user_id and u.username =?"
        /> 
    </authentication-provider>
  </authentication-manager>

  <beans:bean id="horrorMovieDAO" class="com.packt.springsecurity.dao.HorrorMovieDaoImpl" />
  <beans:bean id="horrorMovieManager" class="com.packt.springsecurity.service.HorrorMovieManagerImpl" />
  <beans:bean id="tenant1DataSource" class="org.springframework.jdbc.datasource.DriverManagerDataSource">
  <beans:property name="driverClassName" value="org.apache.derby.jdbc.EmbeddedDriver" />
  <beans:property name="url" value="jdbc:derby://localhost:1527/client1" />
  <beans:property name="username" value="client1" />
  <beans:property name="password" value="client1" />

</beans:bean>
```

1.  使用控制器信息编辑`horrormovie-servlet.xml`文件。

```java
<global-method-security pre-post-annotations="enabled" />

  <http auto-config="true">
    <intercept-url pattern="/spring-security-wicket/**" access="ROLE_SELLER"/>
    <intercept-url pattern="/spring-security-wicket/*.*" access="ROLE_SELLER"/> 
    <intercept-url pattern="/**" access="ROLE_SELLER" />
  <http-basic />
</http>
<authentication-manager> 
  <authentication-provider> 
    <jdbc-user-service data-source-ref="MySqlDS" 
      users-by-username-query=" 
      select username,password, enabled   
      from users1 where username=?"  
      authorities-by-username-query=" 
      select u.username, ur.role from users1 u, user_roles ur  
      where u.user_id = ur.user_id and u.username =?  " /> 
  </authentication-provider>
</authentication-manager>
```

它使用 JDBC 进行身份验证服务。

1.  在执行`addHorrorMovie`方法时使用注释，Spring 会检查安全上下文对象的凭据，并进行身份验证和授权；以下是代码：

```java
@Repository
public class HorrorMovieDaoImpl implements HorrorMovieDAO  {

  @Autowired
  private SessionFactory sessionFactory;

  @PreAuthorize("hasRole('ROLE_AUTHOR')")
  @Override
  public void addHorrorMovie(HorrorMovieEntity horrormovie) {
    this.sessionFactory.getCurrentSession().save(horrormovie);
  }

  @SuppressWarnings("unchecked")
  @Override
  public List<HorrorMovieEntity> getAllHorrorMovies() {
    return this.sessionFactory.getCurrentSession().createQuery("from HORRORMOVIE").list();
  }

  @Override
  public void deleteHorrorMovie(Integer horrorMovieId) {
    HorrorMovieEntity horrorMovie = (HorrorMovieEntity)sessionFactory.getCurrentSession().load(HorrorMovieEntity.class, horrorMovieId);
    if (null != horrorMovie) {
      this.sessionFactory.getCurrentSession().delete(horrorMovie);
    }
  }
}
```

1.  以下是一些 SQL 命令：

```java
create table HORRORMOVIE
 (HORRORMOVIE_ID int generated by default as identity 
 (START WITH 2, INCREMENT BY 1),
 HORRORMOVIE_NAME char(50),HORRORMOVIE_DIRECTOR char(50));

insert into HORRORMOVIE values 
 (1, 'EVILDEAD','Fede Alvarez');
insert into HORRORMOVIE values 
 (DEFAULT, 'EVILDEAD2','Fede Alvarez');

```

## 它是如何工作的...

在这个例子中，我们创建了一个 Hibernate 应用程序，并使用了 JDBC 服务进行身份验证。Spring 框架中断了访问应用程序的请求，并要求用户输入凭据。使用`application-security.xml`文件中提供的 JDBC 详细信息对凭据进行验证。

成功后，用户将被重定向到显示电影列表的应用程序。

现在访问以下网址：

`http://localhost:8080/login`

使用 JDBC 服务进行身份验证和授权以及在方法上应用 Spring Security 的截图如下：

示例的工作流程显示在以下截图中：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_03.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_04.jpg)

## 另请参阅

+   *使用身份验证提供程序的 Spring Security 与 Hibernate*配方

+   *使用 Derby 数据库的用户详细信息服务的 Spring Security 与 Hibernate*配方

+   *使用 MongoDB 的 Spring Security*配方

# 使用身份验证提供程序和@preAuthorize 注释的 Spring Security 与 Hibernate

我们正在使用示例`horrormovie`应用程序来演示使用自定义身份验证提供程序和`@preAuthorize`注释的 Spring Security 与 Hibernate。

在这个配方中，我们将创建自己的自定义身份验证提供程序并实现接口身份验证提供程序。我们将在`controller`方法上应用注释，而不是在`hibernate`方法上。

## 准备工作

+   创建一个实现`AuthenticationProvider`接口的新类，并将 Bean 定义添加到`application-security.xml`文件中

+   编辑`application-security.xml`文件

+   在控制器中使用`@preAuthorize`注释

## 如何做...

使用`AuthenticationProvider`接口实现 Spring Security 的以下步骤：

1.  编辑`application-security.xml`文件，添加数据源详细信息和 Bean 信息。

```java
<global-method-security pre-post-annotations="enabled" />

<http auto-config="false"  use-expressions="true">
  <intercept-url pattern="/login" access="permitAll" />
  <intercept-url pattern="/logout" access="permitAll" />
  <intercept-url pattern="/accessdenied" access="permitAll"/>
  <intercept-url pattern="/list" access="hasRole('ROLE_EDITOR')" />
  <intercept-url pattern="/add" access="hasRole('ROLE_EDITOR')" />
  <form-login login-page="/login" default-target-url="/list" authentication-failure-url="/accessdenied" />
  <logout logout-success-url="/logout" />
</http>

  <authentication-manager alias="authenticationManager">
 <authentication-provider ref="MyCustomAuthenticationProvider" />
 </authentication-manager>

  <beans:bean id="horrorMovieDAO" class="com.packt.springsecurity.dao.HorrorMovieDaoImpl" />
  <beans:bean id="horrorMovieManager" class="com.packt.springsecurity.service.HorrorMovieManagerImpl"/>

 <beans:bean id="MyCustomAuthenticationProvider" class="com.packt.springsecurity.controller" />
</beans:beans>
```

1.  编辑`MyCustomAuthenticationProvider`文件。

```java
public class MyCustomAuthenticationProvider implements AuthenticationProvider {
  @Override
  public boolean supports(Class<? extends Object>authentication)
{
    return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }

 private static Map<String, String> APP_USERS= new HashMap<String, String>(2);
 private static List<GrantedAuthority> APP_ROLES= new ArrayList<GrantedAuthority>();
 static
 {
 APP_USERS.put("ravi", "ravi123");
 APP_USERS.put("chitra", "chitra123");
 APP_ROLES.add(new SimpleGrantedAuthority("ROLE_EDITOR"));
 }

  @Override
  public Authentication authenticate(Authentication auth)
  {
 if (APP_USERS.containsKey(auth.getPrincipal())
 && APP_ROLES.get(auth.getPrincipal()).equals(auth.getCredentials()))
 {
 return new UsernamePasswordAuthenticationToken(auth.getName(), auth.getCredentials(),
 AUTHORITIES);
 }
 throw new BadCredentialsException("Username/Password does not match for "
      + auth.getPrincipal());
    }
  }
}
```

1.  在控制器中使用注释。

```java
AddHorrorMovieController
@PreAuthorize("hasRole('ROLE_EDITOR')")
@RequestMapping(value = "/add", method = RequestMethod.POST)
public String addHorrorMovie(
  @ModelAttribute(value = "horrorMovie") HorrorMovieEntity horrorMovie,
    BindingResult result) {
    horrorMovieManager.addHorrorMovie(horrorMovie);
    return "redirect:/list";
  }
```

## 它是如何工作的...

现在访问以下网址：

`http://localhost:8080/login`

在中断请求后，Spring Security 调用`MyCustomAuthenticationProvider`，该提供程序具有用于身份验证和用户信息的重写 authenticate 方法。用户凭据在`APP_Users`映射中进行验证和授权，成功验证和授权后，用户将被重定向到`spring-security.xml`文件中配置的成功 URL。

使用自定义身份验证提供程序进行身份验证和授权，并在控制器方法上应用 Spring Security 的截图如下：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_05.jpg)![它是如何工作的...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_06.jpg)

## 另请参阅

+   *使用@preAuthorize 注释的 Spring Security 与 Hibernate*配方

+   *使用自定义身份验证提供程序和@preAuthorize 注释的 Spring Security 与 Hibernate*配方

+   *使用 Derby 数据库的用户详细信息服务的 Spring Security 与 Hibernate*配方

+   *使用 MongoDB 的 Spring Security*配方

# 使用 Derby 数据库的 UserDetailsService 与 Spring Security 的 Hibernate

到目前为止，我们已经看到了使用各种身份验证提供程序的 Hibernate 和 Spring Security。在本节中，我们将使用 Hibernate 从数据库中检索用户和权限。

为此，我们将实现`UserDetailsService`接口并在接口中实现一个方法。首先，我们需要为用户和角色创建实体类。

我们还将`@preAuthorize`注释移到`controller`类中。

## 准备工作

+   创建一个实现`UserDetailsService`接口的新类，并将 Bean 定义添加到`application-security.xml`文件中

+   编辑`application-security.xml`文件

+   在控制器中使用`@preAuthorize`注释

+   在恐怖数据库中添加`USERS`和`USER_ROLE`表

+   插入角色`ROLE_EDITOR`和名为`ravi`和`ravi123`的用户

## 如何做...

通过实现与 Hibernate 交互的`UserDetailsService`接口来集成 Spring Security 身份验证的以下步骤：

1.  创建一个实现`UserDetailsService`接口的类`MyUserDetailsService`。

```java
public class MyUserDetails implements UserDetailsService {
  @Autowired
  private UsersDAO UsersDAO;
  public UserDetails loadUserByUsername(String userName)
  throws UsernameNotFoundException {

    Users users= UsersDAO.findByUserName(userName);
    boolean enabled = true;
    boolean accountNonExpired = true;
    boolean credentialsNonExpired = true;
    boolean accountNonLocked = true;
    return new User(
      users.getUserName(), 
      users.getUserPassword(), 
      enabled, 
      accountNonExpired, 
      credentialsNonExpired, 
      accountNonLocked,
      getAuthorities(users.getRole().getRoleId().intValue()));
    }

    public Collection<? extends GrantedAuthority>getAuthorities(Integer role) {
    List<GrantedAuthority> authList = getGrantedAuthorities(getRoles(role));
    System.out.println("authList----------->"+authList);
    return authList;
  }

  public List<String> getRoles(Integer role) {

    List<String> roles = new ArrayList<String>();

    if (role.intValue() == 1) {
      roles.add("ROLE_EDITOR");
    } else if (role.intValue() == 2) {
      roles.add("ROLE_AUTHOR");
    }
    return roles;
  }

  public static List<GrantedAuthority> getGrantedAuthorities(List<String> roles) {
  List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
  for (String role : roles) {
    System.out.println("role----------->"+role);
    authorities.add(new SimpleGrantedAuthority(role));
  }
  return authorities;
  }

}
```

1.  编辑`application-security.xml`文件。

```java
<authentication-manager alias="authenticationManager">
  <authentication-provider user-service-ref="MyUserDetails">
    <password-encoder hash="plaintext" />
  </authentication-provider>
</authentication-manager>

<beans:bean id="horrorMovieDAO" class="com.packt.springsecurity.dao.HorrorMovieDaoImpl" />
<beans:bean id="horrorMovieManager" class="com.packt.springsecurity.service.HorrorMovieManagerImpl" />
<beans:bean id="UsersDAO" class="com.packt.springsecurity.dao.UsersDAOImpl" />
<beans:bean id="UsersManager" class="com.packt.springsecurity.service.UsersManagerImpl" />
<beans:bean id="UserRoleDAO" class="com.packt.springsecurity.dao.UserRoleDAOImpl" />
<beans:bean id="UserRoleManager" class="com.packt.springsecurity.service.UserRoleManagerImpl" />

<beans:bean id="MyUserDetails" class="com.packt.springsecurity.service.MyUserDetails" />
</beans:beans>
```

1.  在控制器中使用注释。

```java
@PreAuthorize("hasRole('ROLE_EDITOR')")
@RequestMapping(value = "/add", method = RequestMethod.POST)
public String addHorrorMovie(
  @ModelAttribute(value = "horrorMovie")HorrorMovieEntity horrorMovie,
  BindingResult result) {
    horrorMovieManager.addHorrorMovie(horrorMovie);
    return "redirect:/list";
  }
```

## 它是如何工作的...

现在访问以下 URL：

`http://localhost:8080/login`

首先使用`UserDetailsService`和 Hibernate 进行身份验证和授权。 `UserDetailsService`是 Spring Security 接口，由`MyUserDetailsService`类实现。该类在`application-security.xml`文件中进行配置，以便 Spring Security 调用此实现类使用 Hibernate 加载用户详细信息。 `UsersDAO.findByUserName(userName)`是调用 Hibernate 获取基于传递的用户名的用户信息的方法。

在使用注释将 Spring Security 应用于控制器之后，我们应该能够使用用户名和密码（ravi 和 ravi123）登录。 `<password-encoder hash="plaintext" />`是 Spring Security 支持的哈希算法。成功验证后，用户将被重定向到授权页面。

应用程序的工作流程在以下屏幕截图中演示：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_07.jpg)![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_08.jpg)

## 另请参阅

+   使用@preAuthorize 注释的 Hibernate 的 Spring Security 配方

+   使用自定义身份验证提供程序和@preAuthorize 注释的 Hibernate 的 Spring Security 配方

+   使用 Derby 数据库的用户详细信息服务的 Spring Security 配方

+   使用 MongoDB 的 Spring Security 配方

# 使用 MongoDB 的 Spring Security

在本节中，让我们看看 Spring Security 如何与 MongoDB 配合使用。 MongoDB 是一种流行的 NOSQL 数据库。它是一个基于文档的数据库。 MongoDB 是用流行的 C++数据库编写的，这使它成为一种面向对象的基于文档的数据库。在 MongoDB 中，查询也是基于文档的，它还提供使用 JSON 样式进行索引以存储和检索数据。最新的 Spring 版本是版本 3.2，已包含在 POC 中。

## 准备工作

+   下载 MongoDB 数据库

+   配置数据文件夹

+   在命令提示符中启动 MongoDB

+   在另一个命令提示符中启动 MongoDB

+   通过向其中插入数据创建`horrordb`数据库

+   执行命令`use horrordb`

+   将 MongoDB 依赖项添加到 POM（项目对象模型）文件

+   将 JSON 依赖项添加到 POM 文件

+   将 Spring 版本升级到 3.2.0，将 Spring Security 升级到 1.4

+   创建一个`MongoUserDetails`类

+   编辑`horror-movie` servlet

+   编辑`Application-security.xml`文件

## 如何做...

以下步骤使用 Mongo 与 Spring Security 来实现`UserDetailsService`接口对用户进行身份验证和授权：

1.  在命令提示符中显示数据库操作如下：

```java
db.horrormovie.insert({horrormovie_id:1,horrormovie_name:
 "omen",horrormovie_director:"Richard Donner"})

db.horrormovie.insert({horrormovie_id:2,horrormovie_name:
 "the conjuring",horrormovie_director:"James Wan"})

db.horrormovie.insert({horrormovie_id:3,horrormovie_name:
 "The Lords of Salem",horrormovie_director:"Rob Zombie"})

db.horrormovie.insert({horrormovie_id:4,horrormovie_name:
 "Evil Dead",horrormovie_director: "Fede Alvarez"})

db.users.insert({id:1,username:"anjana",password:
 "123456",role:1})

db.users.insert({id:2,username:"raghu",password:
 "123456",role:2})

db.users.insert({id:3,username:"shami",password:
 "123456",role:3})

```

1.  创建一个实现`UserDetailsService`接口的`MongoUserDetailsService`类。

```java
@Service
public class MongoUserDetailsService implements UserDetailsService {

  @Autowired
  private UserManager userManager;
  private static final Logger logger = Logger.getLogger(MongoUserDetailsService.class);
  private org.springframework.security.core.userdetails.User userdetails;
  public UserDetails loadUserByUsername(String username)
  throws UsernameNotFoundException {
    boolean enabled = true;
    boolean accountNonExpired = true;
    boolean credentialsNonExpired = true;
    boolean accountNonLocked = true;
    Users users = getUserDetail(username);
    System.out.println(username);
    System.out.println(users.getPassword());
    System.out.println(users.getUsername());
    System.out.println(users.getRole());

    return new User(users.getUsername(), users.getPassword(),enabled,accountNonExpired,credentialsNonExpired,accountNonLocked,getAuthorities(users.getRole()));
  }

  public List<GrantedAuthority> getAuthorities(Integer role) {
    List<GrantedAuthority> authList = new ArrayList<GrantedAuthority>();
      if (role.intValue() == 1) {
        authList.add(new SimpleGrantedAuthority("ROLE_EDITOR"));

      } else if (role.intValue() == 2) {
        authList.add(new SimpleGrantedAuthority("ROLE_AUTHOR"));
    }
    return authList;
  }

  public Users getUserDetail(String username) {
  Users users = userManager.findByUserName(username);
  System.out.println(users.toString());
  return users;
}
```

1.  编辑`application-security.xml`。

```java
<global-method-security pre-post-annotations="enabled" />

<http auto-config="false"  use-expressions="true">
  <intercept-url pattern="/login" access="permitAll" />
  <intercept-url pattern="/logout" access="permitAll" />
  <intercept-url pattern="/accessdenied" access="permitAll" />
  <intercept-url pattern="/list" access="hasRole('ROLE_EDITOR')" />
<!--                <http-basic/>-->
  <form-login login-page="/login" default-target-url="/list" authentication-failure-url="/accessdenied" />
  <logout logout-success-url="/logout" />
</http>

<authentication-manager alias="authenticationManager">
<authentication-provider user-service-ref="mongoUserDetailsService">
<password-encoder hash="plaintext" />
</authentication-provider>
</authentication-manager>
```

1.  编辑`horrormovie-servlet.xml`。

```java
<context:annotation-config />
<context:component-scan base-package="com.packt.springsecurity.mongodb.controller" />
<context:component-scan base-package="com.packt.springsecurity.mongodb.manager" />
<context:component-scan base-package="com.packt.springsecurity.mongodb.dao" />
<context:component-scan base-package="com.packt.springsecurity.mongodb.documententity" />

<bean id="jspViewResolver"
  class="org.springframework.web.servlet.view.InternalResourceViewResolver">
  <property name="viewClass"
  value="org.springframework.web.servlet.view.JstlView" />
  <property name="prefix" value="/WEB-INF/view/" />
  <property name="suffix" value=".jsp" />
</bean>
<mongo:mongo host="127.0.0.1" port="27017" />
<mongo:db-factory dbname="horrordb" />

<bean id="mongoTemplate" class="org.springframework.data.mongodb.core.MongoTemplate">
<constructor-arg name="mongoDbFactory" ref="mongoDbFactory" />
</bean>

<bean id="horrorMovieDAO" class="com.packt.springsecurity.mongodb.dao.HorrorMovieDaoImpl" />
<bean id="horrorMovieManager" class="com.packt.springsecurity.mongodb.manager.HorrorMovieManagerImpl" />
<bean id="UsersDAO" class="com.packt.springsecurity.mongodb.dao.UsersDAOImpl" />
<bean id="userManager" class="com.packt.springsecurity.mongodb.manager.UserManagerImpl" />
<bean id="mongoUserDetailsService" class="com.packt.springsecurity.mongodb.controller.MongoUserDetailsService" />

<bean id="HorroMovieController" class="com.packt.springsecurity.mongodb.controller.HorrorMovieController" />
```

1.  在控制器中使用注释。

```java
@PreAuthorize("hasRole('ROLE_EDITOR')")
@RequestMapping(value = "/add", method = RequestMethod.POST)
public String addHorrorMovie(
@ModelAttribute(value = "horrorMovie")HorrorMovieEntity horrorMovie,
  BindingResult result) {
  horrorMovieManager.addHorrorMovie(horrorMovie);
  return "redirect:/list";
}
```

## 工作原理...

首先使用`MongoDetailsService`和 Spring 数据进行身份验证和授权。 `MongoDetailsService`是`UserDetailsService`的实现，`getUserDetail`(string username)调用`springdata`类从 Mongo 数据库中获取基于传递的用户名的用户凭据。如果根据用户名存在数据，则意味着身份验证成功。然后我们使用注释在控制器方法上应用 Spring Security。

现在我们应该能够使用用户名和密码（ravi 和 123456）登录。

现在访问以下 URL：

`http://localhost:8080/login`

工作流程在以下屏幕截图中演示：

![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_09.jpg)![工作原理...](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/sprsec-3x-cb/img/7525OS_08_10.jpg)

## 另请参阅

+   使用@preAuthorize 注释的 Hibernate 的 Spring Security 配方

+   使用自定义身份验证提供程序和@preAuthorize 注释的 Hibernate 的 Spring Security 配方

+   使用 Derby 数据库的用户详细信息服务的 Spring Security 配方

+   使用 MongoDB 的 Spring Security 配方
