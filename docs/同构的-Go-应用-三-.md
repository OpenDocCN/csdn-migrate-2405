# 同构的 Go 应用（三）

> 原文：[`zh.annas-archive.org/md5/70B74CAEBE24AE2747234EE512BCFA98`](https://zh.annas-archive.org/md5/70B74CAEBE24AE2747234EE512BCFA98)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：等同态网络表单

在上一章中，我们专注于如何使服务器端应用程序将数据移交给客户端应用程序，以无缝地维护状态，同时实现购物车功能。在[第六章]（5759cf7a-e435-431d-b7ca-24a846d6165a.xhtml）*等同态移交*中，我们将服务器视为唯一的真相来源。服务器向客户端指示当前购物车状态。在本章中，我们将超越迄今为止考虑的简单用户交互，并步入接受通过等同态网络表单提交的用户生成数据的领域。

这意味着现在客户端有了发言权，可以决定应该存储在服务器上的用户生成数据，当然前提是有充分的理由（验证用户提交的数据）。使用等同态网络表单，验证逻辑可以在各个环境中共享。客户端应用程序可以参与并通知用户在提交表单数据到服务器之前已经犯了一个错误。服务器端应用程序拥有最终否决权，因为它将在服务器端重新运行验证逻辑（在那里，验证逻辑显然无法被篡改），并仅在成功验证结果时处理用户生成的数据。

除了提供共享验证逻辑和表单结构的能力外，等同态网络表单还提供了一种使表单更易访问的方法。我们必须解决网页客户端的可访问性问题，这些客户端可能没有 JavaScript 运行时，或者可能已禁用 JavaScript 运行时。为了实现这一目标，我们将为 IGWEB 的联系部分构建一个等同态网络表单，并考虑渐进增强。这意味着只有在实现了满足最低要求的表单功能，以满足禁用 JavaScript 的网页客户端场景后，我们才会继续实现在 JavaScript 配备的网页浏览器中直接运行的客户端表单验证。

到本章结束时，我们将拥有一个强大的等同态网络表单，使用单一语言（Go）实现，它将在各种环境中重用通用代码。最重要的是，等同态网络表单将对终端窗口中运行的最简化的网页客户端和具有最新 JavaScript 运行时的基于 GUI 的网页客户端都是可访问的。

在本章中，我们将涵盖以下主题：

+   了解表单流程

+   设计联系表单

+   验证电子邮件地址语法

+   表单界面

+   实现联系表单

+   可访问的联系表单

+   客户端考虑

+   联系表单 Rest API 端点

+   检查客户端验证

# 了解表单流程

*图 7.1*显示了一个图像，显示了仅具有服务器端验证的网页表单。表单通过 HTTP Post 请求提交到 Web 服务器。服务器提供完全呈现的网页响应。如果用户没有正确填写表单，错误将在网页响应中显示。如果用户正确填写了表单，将进行 HTTP 重定向到确认网页：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/10bb8e33-a740-4d65-a97b-553d9d223faf.png)

图 7.1：仅具有服务器端验证的网页表单

*图 7.2*显示了一个图像，显示了具有客户端和服务器端验证的 Web 表单。当用户提交 Web 表单时，表单中的数据将使用客户端验证进行验证。仅在成功的客户端验证结果时，表单数据将通过 XHR 调用提交到 Web 服务器的 Rest API 端点。一旦表单数据提交到服务器，它将经历第二轮服务器端验证。这确保了即使在客户端验证可能被篡改的情况下，表单数据的质量。客户端应用程序将检查从服务器返回的表单验证结果，并在成功提交表单时显示确认页面，或在提交表单不成功时显示联系表单错误：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/4decea16-9af6-4ee1-ac9d-937cceaca898.png)

图 7.2：在客户端和服务器端验证的 Web 表单

# 设计联系表单

联系表单将允许网站用户与 IGWEB 团队取得联系。成功完成联系表单将导致包含用户生成的表单数据的联系表单提交被持久化在 Redis 数据库中。*图 7.3*是描述联系表单的线框图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f6496bb6-b9b3-45f6-b271-c3464d1e1269.png)

图 7.3：联系表单的线框设计

*图 7.4*是线框图，描述了当用户未正确填写表单时显示表单错误的联系表单：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/b1bdc574-a9e3-4078-a195-bb5eff1ff568.png)

图 7.4：联系表单的线框设计，显示了错误消息

*图 7.5*是线框图，描述了成功提交联系表单后将显示给用户的确认页面：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/365ab4bf-f5c3-4ec6-88c3-a0416dad30fa.png)

图 7.5：确认页面的线框设计

联系表单将从用户那里征求以下必要信息：他们的名字，姓氏，电子邮件地址和给团队的消息。如果用户没有填写这些字段中的任何一个，点击表单上的联系按钮后，用户将收到特定于字段的错误消息，指示未填写的字段。

# 实施模板

在服务器端呈现联系页面时，我们将使用`contact_page`模板（在`shared/templates/contact_page.tmpl`文件中找到）：

```go
{{ define "pagecontent" }}
{{template "contact_content" . }}
{{end}}
{{template "layouts/webpage_layout" . }}
```

请记住，因为我们包含了`layouts/webpage_layout`模板，这将打印生成页面的`doctype`，`html`和`body`标记的标记。这个模板将专门在服务器端使用。

使用`define`模板操作，我们划定了`"pagecontent"`块，其中将呈现联系页面的内容。联系页面的内容在`contact_content`模板内定义（在`shared/template/contact_content.tmpl`文件中找到）：

```go
<h1>Contact</h1>

{{template "partials/contactform_partial" .}}
```

请记住，除了服务器端应用程序之外，客户端应用程序将使用`contact_content`模板在主要内容区域呈现联系表单。

在`contact_content`模板内，我们包含了包含联系表单标记的联系表单部分模板（`partials/contactform_partial`）：

```go
<div class="formContainer">
<form id="contactForm" name="contactForm" action="/contact" method="POST" class="pure-form pure-form-aligned">
  <fieldset>
{{if .Form }}
    <div class="pure-control-group">
      <label for="firstName">First Name</label>
      <input id="firstName" type="text" placeholder="First Name" name="firstName" value="{{.Form.Fields.firstName}}">
      <span id="firstNameError" class="formError pure-form-message-inline">{{.Form.Errors.firstName}}</span>
    </div>

    <div class="pure-control-group">
      <label for="lastName">Last Name</label>
      <input id="lastName" type="text" placeholder="Last Name" name="lastName" value="{{.Form.Fields.lastName}}">
      <span id="lastNameError" class="formError pure-form-message-inline">{{.Form.Errors.lastName}}</span>
    </div>

    <div class="pure-control-group">
      <label for="email">E-mail Address</label>
      <input id="email" type="text" placeholder="E-mail Address" name="email" value="{{.Form.Fields.email}}">
      <span id="emailError" class="formError pure-form-message-inline">{{.Form.Errors.email}}</span>
    </div>

    <fieldset class="pure-control-group">
      <textarea id="messageBody" class="pure-input-1-2" placeholder="Enter your message for us here." name="messageBody">{{.Form.Fields.messageBody}}</textarea>
      <span id="messageBodyError" class="formError pure-form-message-inline">{{.Form.Errors.messageBody}}</span>
    </fieldset>

    <div class="pure-controls">
      <input id="contactButton" name="contactButton" class="pure-button pure-button-primary" type="submit" value="Contact" />
    </div>
{{end}}
  </fieldset>
</form>
</div>
```

这个部分模板包含了实现*图 7.3*所示线框设计所需的 HTML 标记。访问表单字段值及其对应错误的模板操作以粗体显示。我们为给定的`input`字段填充`value`属性的原因是，如果用户在填写表单时出错，这些值将被预先填充为用户在上一次表单提交尝试中输入的值。每个`input`字段后面直接跟着一个`<span>`标记，其中将包含该特定字段的相应错误消息。

最后的`<input>`标签是一个`submit`按钮。点击此按钮，用户将能够将表单内容提交到 Web 服务器。

# 验证电子邮件地址语法

除了所有字段必须填写的基本要求之外，电子邮件地址字段必须是格式正确的电子邮件地址。如果用户未能提供格式正确的电子邮件地址，字段特定的错误消息将通知用户电子邮件地址语法不正确。

我们将使用`shared`文件夹中的`validate`包中的`EmailSyntax`函数。

```go
const EmailRegex = `(?i)^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,3})+$`

func EmailSyntax(email string) bool {
  validationResult := false
  r, err := regexp.Compile(EmailRegex)
  if err != nil {
    log.Fatal(err)
  }
  validationResult = r.MatchString(email)
  return validationResult
}
```

请记住，因为`validate`包被策略性地放置在`shared`文件夹中，该包旨在是等距的（跨环境使用）。`EmailSyntax`函数的工作是确定输入字符串是否是有效的电子邮件地址。如果电子邮件地址有效，函数将返回`true`，如果输入字符串不是有效的电子邮件地址，则函数将返回`false`。

# 表单接口

等距网络表单实现了`isokit`包中找到的`Form`接口：

```go
type Form interface {
 Validate() bool
 Fields() map[string]string
 Errors() map[string]string
 FormParams() *FormParams
 PrefillFields()
 SetFields(fields map[string]string)
 SetErrors(errors map[string]string)
 SetFormParams(formParams *FormParams)
 SetPrefillFields(prefillFields []string)
}
```

`Validate`方法确定表单是否已正确填写，如果表单已正确填写，则返回`true`的布尔值，如果表单未正确填写，则返回`false`的布尔值。

`Fields`方法返回了所有表单字段的`map`，其中键是表单字段的名称，值是表单字段的字符串值。

`Errors`方法包含了在表单验证时填充的所有错误的`map`。键是表单字段的名称，值是描述性错误消息。

`FormParams`方法返回表单的等距表单参数对象。表单参数对象很重要，因为它确定了可以获取表单字段的用户输入值的来源。在服务器端，表单字段值是从`*http.Request`获取的，在客户端，表单字段是从`FormElement`对象获取的。

这是`FormParams`结构的样子：

```go
type FormParams struct {
  FormElement *dom.HTMLFormElement
  ResponseWriter http.ResponseWriter
  Request *http.Request
  UseFormFieldsForValidation bool
  FormFields map[string]string
}
```

`PrefillFields`方法返回一个字符串切片，其中包含表单字段的所有名称，如果用户在提交表单时出错，应保留其值。

考虑到最后四个 getter 方法，`Fields`、`Errors`、`FormParams`和`PrefillFields`，都有相应的 setter 方法，`SetFields`、`SetErrors`、`SetFormParams`和`SetPrefillFields`。

# 实现联系表单

现在我们知道表单接口的样子，让我们开始实现联系表单。在我们的导入分组中，请注意我们包括了验证包和`isokit`包：

```go
import (
  "github.com/EngineerKamesh/igb/igweb/shared/validate"
  "github.com/isomorphicgo/isokit"
)
```

请记住，我们需要导入验证包，以便使用包中定义的`EmailSyntax`函数进行电子邮件地址验证功能。

我们之前介绍的实现`Form`接口所需的大部分功能都由`isokit`包中的`BasicForm`类型提供。我们将类型`BasicForm`嵌入到我们的`ContactForm`结构的类型定义中：

```go
type ContactForm struct {
  isokit.BasicForm
}
```

通过这样做，我们大部分实现`Form`接口的功能都是免费提供给我们的。但是，我们必须实现`Validate`方法，因为`BasicForm`类型中找到的默认`Validate`方法实现将始终返回`false`。

联系表单的构造函数接受一个`FormParams`结构，并返回一个新创建的`ContactForm`结构的指针：

```go
func NewContactForm(formParams *isokit.FormParams) *ContactForm {
  prefillFields := []string{"firstName", "lastName", "email", "messageBody", "byDateInput"}
  fields := make(map[string]string)
  errors := make(map[string]string)
  c := &ContactForm{}
  c.SetPrefillFields(prefillFields)
  c.SetFields(fields)
  c.SetErrors(errors)
  c.SetFormParams(formParams)
  return c
}
```

我们创建一个字符串切片，其中包含应保留其值的字段的名称，在`prefillFields`变量中。我们为`fields`变量和`errors`变量分别创建了`map[string]string`类型的实例。我们创建了一个新的`ContactForm`实例的引用，并将其分配给变量`c`。我们调用`ContactForm`实例`c`的`SetFields`方法，并传递`fields`变量。

我们调用`SetFields`和`SetErrors`方法，并分别传入`fields`和`errors`变量。我们调用`c`的`SetFormParams`方法来设置传入构造函数的表单参数。最后，我们返回新的`ContactForm`实例。

正如前面所述，`BasicForm`类型中的默认`Validate`方法实现总是返回`false`。因为我们正在实现自己的自定义表单，联系表单，我们有责任定义成功验证是什么，并通过实现`Validate`方法来实现。

```go
func (c *ContactForm) Validate() bool {
  c.RegenerateErrors()
  c.PopulateFields()

  // Check if first name was filled out
  if isokit.FormValue(c.FormParams(), "firstName") == "" {
    c.SetError("firstName", "The first name field is required.")
  }

  // Check if last name was filled out
  if isokit.FormValue(c.FormParams(), "lastName") == "" {
    c.SetError("lastName", "The last name field is required.")
  }

  // Check if message body was filled out
  if isokit.FormValue(c.FormParams(), "messageBody") == "" {
    c.SetError("messageBody", "The message area must be filled.")
  }

  // Check if e-mail address was filled out
  if isokit.FormValue(c.FormParams(), "email") == "" {
    c.SetError("email", "The e-mail address field is required.")
  } else if validate.EmailSyntax(isokit.FormValue(c.FormParams(), "email")) == false {
    // Check e-mail address syntax
    c.SetError("email", "The e-mail address entered has an improper syntax.")

  }

  if len(c.Errors()) > 0 {
    return false

  } else {
    return true
  }
}
```

我们首先调用`RegenerateErrors`方法来清除当前显示给用户的错误。这个方法的功能只适用于客户端应用程序。当我们在客户端实现联系表单功能时，我们将更详细地介绍这个方法。

我们调用`PopulateFields`方法来填充`ContactForm`实例的字段`map`。如果用户在填写表单时出现错误，这个方法负责预先填充用户已经输入的值，以免他们不得不再次输入这些值来重新提交表单。

在这一点上，我们可以开始进行表单验证。我们首先检查用户是否已经填写了名字字段。我们使用`isokit`包中的`FormValue`函数来获取表单字段`firstName`的用户输入值。我们传递给`FormValue`函数的第一个参数是联系表单的表单参数对象，第二个值是我们希望获取的表单字段的名称，即`"firstName"`。通过检查用户输入的值是否为空字符串，我们可以确定用户是否已经在字段中输入了值。如果没有，我们调用`SetError`方法，传递表单字段的名称，以及一个描述性错误消息。

我们执行完全相同的检查，以查看用户是否已经填写了必要的值，包括姓氏字段、消息正文和电子邮件地址。如果他们没有填写这些字段中的任何一个，我们将调用`SetError`方法，提供字段的名称和一个描述性错误消息。

对于电子邮件地址，如果用户已经输入了电子邮件表单字段的值，我们将对用户提供的电子邮件地址的语法进行额外检查。我们将用户输入的电子邮件值传递给验证包中的`EmailSyntax`函数。如果电子邮件不是有效的语法，我们调用`SetError`方法，传入表单字段名称`"email"`，以及一个描述性错误消息。

正如我们之前所述，`Validate`函数基于表单是否包含错误返回一个布尔值。我们使用 if 条件来确定错误的数量是否大于零，如果是，表示表单有错误，我们返回一个布尔值`false`。如果错误的数量为零，控制流将到达 else 块，我们返回一个布尔值`true`。

现在我们已经添加了联系表单，是时候实现服务器端的路由处理程序了。

# 注册联系路由

我们首先添加联系表单页面和联系确认页面的路由：

```go
  r.Handle("/contact", handlers.ContactHandler(env)).Methods("GET", "POST")
  r.Handle("/contact-confirmation", handlers.ContactConfirmationHandler(env)).Methods("GET")
```

请注意，我们注册的`/contact`路由将由`ContactHandler`函数处理，将接受使用`GET`和`POST`方法的 HTTP 请求。当首次访问联系表单时，将通过`GET`请求到`/contact`路由。当用户提交联系表单时，他们将发起一个`POST`请求到`/contact`路由。这解释了为什么这个路由接受这两种 HTTP 方法。

成功填写联系表单后，用户将被重定向到`/contact-confirmation`路由。这是有意为之，以避免重新提交表单错误，当用户尝试刷新网页时，如果我们仅仅使用`/contact`路由本身打印出表单确认消息。

# 联系路由处理程序

`ContactHandler`负责在 IGWEB 上呈现联系页面，联系表单将驻留在此处：

```go
func ContactHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
```

我们声明并初始化`formParams`变量为新初始化的`FormParams`实例，提供`ResponseWriter`和`Request`字段的值：

```go
    formParams := isokit.FormParams{ResponseWriter: w, Request: r}
```

然后我们声明并初始化`contactForm`变量，通过调用`NewContactForm`函数并传入对`formParams`结构的引用，使用新创建的`ContactForm`实例。

```go
    contactForm := forms.NewContactForm(&formParams)
```

我们根据 HTTP 请求方法的类型进行`switch`：

```go
    switch r.Method {

    case "GET":
      DisplayContactForm(env, contactForm)
    case "POST":
      validationResult := contactForm.Validate()
      if validationResult == true {
        submissions.ProcessContactForm(env, contactForm)
        DisplayConfirmation(env, w, r)
      } else {
        DisplayContactForm(env, contactForm)
      }
    default:
      DisplayContactForm(env, contactForm)
    }

  })
}
```

如果 HTTP 请求方法是`GET`，我们调用`DisplayContactForm`函数，传入`env`对象和`contactForm`对象。`DisplayContactForm`函数将在联系页面上呈现联系表单。

如果 HTTP 请求方法是`POST`，我们验证联系表单。请记住，如果使用`POST`方法访问`/contact`路由，这表明用户已经向路由提交了联系表单。我们声明并初始化`validationResult`变量，将其设置为调用`ContactForm`对象`contactForm`的`Validate`方法的结果的值。

如果`validationResult`的值为 true，表单验证成功。我们调用`submissions`包中的`ProcessContactForm`函数，传入`env`对象和`ContactForm`对象。`ProcessContactForm`函数负责处理成功的联系表单提交。然后我们调用`DisplayConfirmation`函数，传入`env`对象，`http.ResponseWriter`，`w`和`*http.Request`，`r`。

如果`validationResult`的值为`false`，控制流进入`else`块，我们调用`DisplayContactForm`函数，传入`env`对象和`ContactForm`对象`contactForm`。这将再次呈现联系表单，这次用户将看到与未填写或未正确填写的字段相关的错误消息。

如果 HTTP 请求方法既不是`GET`也不是`POST`，我们达到默认条件，简单地调用`DisplayContactForm`函数来显示联系表单。

这是`DisplayContactForm`函数：

```go
func DisplayContactForm(env *common.Env, contactForm *forms.ContactForm) {
  templateData := &templatedata.Contact{PageTitle: "Contact", Form: contactForm}
  env.TemplateSet.Render("contact_page", &isokit.RenderParams{Writer: contactForm.FormParams().ResponseWriter, Data: templateData})
}
```

该函数接受`env`对象和`ContactForm`对象作为输入参数。我们首先声明并初始化`templateData`变量，它将作为我们将要提供给`contact_page`模板的数据对象。我们创建一个新的`templatedata.Contact`结构的实例，并将其`PageTitle`字段填充为`"Contact"`，将其`Form`字段填充为传入函数的`ContactForm`对象。

这是`templatedata`包中的`Contact`结构的样子：

```go
type Contact struct {
  PageTitle string
  Form *forms.ContactForm
}
```

`PageTitle`字段代表网页的页面标题，`Form`字段代表`ContactForm`对象。

然后我们在`env.TemplateSet`对象上调用`Render`方法，并传入我们希望呈现的模板名称`contact_page`，以及等同模板呈现参数（`RenderParams`）对象。我们已经将`RenderParams`对象的`Writer`字段分配为与`ContactForm`对象相关联的`ResponseWriter`，并将`Data`字段分配为`templateData`变量。

这是`DisplayConfirmation`函数：

```go
func DisplayConfirmation(env *common.Env, w http.ResponseWriter, r *http.Request) {
  http.Redirect(w, r, "/contact-confirmation", 302)
}
```

这个函数负责执行重定向到确认页面。在这个函数中，我们简单地调用`http`包中可用的`Redirect`函数，并执行`302`状态重定向到`/contact-confirmation`路由。

现在我们已经介绍了联系页面的路由处理程序，是时候看看联系表单确认网页的路由处理程序了。

# 联系确认路由处理程序

`ContactConfirmationHandler`函数的唯一目的是呈现联系确认页面：

```go
func ContactConfirmationHandler(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    env.TemplateSet.Render("contact_confirmation_page", &isokit.RenderParams{Writer: w, Data: nil})
  })
}
```

我们调用`TemplateSet`对象的`Render`方法，并指定要呈现`contact_confirmation_page`模板，以及传入的`RenderParams`结构。我们已经将结构的`Writer`字段填充为`http.ResponseWriter`，并将`Data`对象的值分配为`nil`，以指示没有要传递给模板的数据对象。

# 处理联系表单提交

在联系表单成功完成后，我们在`submission`包中调用`ProcessContactForm`函数。如果填写联系表单的工作流程就像打棒球一样，那么对`ProcessContactForm`函数的调用可以被认为是到达本垒并得分。正如我们将在*联系表单 Rest API 端点*部分中看到的那样，这个函数也将被联系表单的 Rest API 端点调用。既然我们已经确定了这个函数的重要性，让我们继续并检查它：

```go
func ProcessContactForm(env *common.Env, form *forms.ContactForm) {

  log.Println("Successfully reached process content form function, indicating that the contact form was filled out properly resulting in a positive validation.")

  contactRequest := &models.ContactRequest{FirstName: form.GetFieldValue("firstName"), LastName: form.GetFieldValue("lastName"), Email: form.GetFieldValue("email"), Message: form.GetFieldValue("messageBody")}

  env.DB.CreateContactRequest(contactRequest)
}
```

我们首先打印出一个日志消息，指示我们已成功到达该函数，表明用户已正确填写了联系表单，并且用户输入的数据值得被处理。然后我们声明并初始化`contactRequest`变量，使用新创建的`ContactRequest`实例。

`ContactRequest`结构的目的是对从联系表单收集的数据进行建模。以下是`ContactRequest`结构的外观：

```go
type ContactRequest struct {
  FirstName string
  LastName string
  Email string
  Message string
}
```

正如您所看到的，`ContactRequest`结构中的每个字段对应于联系表单中存在的表单字段。我们通过在联系表单对象上调用`GetFieldValue`方法并提供表单字段的名称，将`ContactRequest`结构中的每个字段填充为其对应的用户输入值。

如前所述，成功的联系表单提交包括将联系请求信息存储在 Redis 数据库中：

```go
env.DB.CreateContactRequest(contactRequest)
```

我们调用我们自定义 Redis 数据存储对象`env.DB`的`CreateContactRequest`方法，并将`ContactRequest`对象`contactRequest`传递给该方法。这个方法将联系请求信息保存到 Redis 数据库中：

```go
func (r *RedisDatastore) CreateContactRequest(contactRequest *models.ContactRequest) error {

  now := time.Now()
  nowFormatted := now.Format(time.RFC822Z)

  jsonData, err := json.Marshal(contactRequest)
  if err != nil {
    return err
  }

  if r.Cmd("SET", "contact-request|"+contactRequest.Email+"|"+nowFormatted, string(jsonData)).Err != nil {
    return errors.New("Failed to execute Redis SET command")
  }

  return nil

}
```

`CreateContactRequest`方法接受`ContactRequest`对象作为唯一输入参数。我们对`ContactRequest`值进行 JSON 编组，并将其存储到 Redis 数据库中。如果 JSON 编组过程失败或保存到数据库失败，则返回错误对象。如果没有遇到错误，我们返回`nil`。

# 可访问的联系表单

此时，我们已经准备好测试联系表单了。但是，我们不是首先在基于 GUI 的网页浏览器中打开联系表单，而是首先看看使用 Lynx 网页浏览器对视障用户来说联系表单的可访问性如何。

乍一看，我们使用一个 25 年历史的纯文本网页浏览器来测试联系表单可能看起来有些奇怪。然而，Lynx 具有提供可刷新的盲文显示以及文本到语音功能的能力，这使得它成为了一个值得称赞的供视障人士使用的网页浏览技术。因为 Lynx 不支持显示图像和运行 JavaScript，我们可以很好地了解联系表单对于需要更大可访问性的用户来说的表现。

如果您在 Mac 上使用 Homebrew，可以轻松安装 Lynx，方法如下：

```go
$ brew install lynx
```

如果您使用 Ubuntu，可以通过发出以下命令安装 Lynx：

```go
$ sudo apt-get install lynx
```

如果您使用 Windows，可以从这个网页下载 Lynx：[`lynx.invisible-island.net/lynx2.8.8/index.html`](http://lynx.invisible-island.net/lynx2.8.8/index.html)。

您可以在维基百科上阅读有关 Lynx Web 浏览器的更多信息[`en.wikipedia.org/wiki/Lynx_(web_browser)`](https://en.wikipedia.org/wiki/Lynx_(web_browser))。

使用`--nocolor`选项启动 lynx 时，我们启动`igweb` Web 服务器实例：

```go
$ lynx --nocolor localhost:8080/contact
```

*图 7.6*显示了 Lynx Web 浏览器中联系表格的外观：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/aca3054b-b49a-4d85-8e0b-8615390a58de.png)

图 7.6：Lynx Web 浏览器中的联系表格

现在，我们将部分填写联系表格，目的是测试表单验证逻辑是否有效。在电子邮件字段的情况下，我们将提供一个格式不正确的电子邮件地址，如*图 7.7*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/77416de7-79e3-418c-b45b-cbb788fb5479.png)

图 7.7：联系表格填写不正确

点击“联系”按钮后，请注意我们收到有关未正确填写的字段的错误消息，如*图 7.8*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/33ca6e78-e8e4-45a4-b797-75997ac4d45f.png)

图 7.8：电子邮件地址字段和消息文本区域显示的错误消息

还要注意，我们收到了错误消息，告诉我们电子邮件地址格式不正确。

*图 7.9*显示了我们纠正所有错误后联系表格的外观：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e251ed95-8f60-4bce-a765-e70fdac4e943.png)

图 7.9：联系表格填写正确

提交更正的联系表格后，我们看到确认消息，通知我们已成功填写联系表格，如*图 7.10*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e061a763-d5c7-4fa5-871a-8026e37e2c1e.png)

图 7.10：确认页面

使用 redis-cli 命令检查 Redis 数据库，我们可以验证我们收到了表单提交，如*图 7.11*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/1ffb7e74-e596-4036-bb0b-0880aeca7ae1.png)

图 7.11：在 Redis 数据库中验证新存储的联系请求条目

在这一点上，我们可以满意地知道我们已经使我们的联系表格对视力受损用户可访问，并且我们的努力并不多。让我们看看在禁用 JavaScript 的 GUI 型 Web 浏览器中联系表格的外观。

# 联系表格可以在没有 JavaScript 的情况下运行

在 Safari Web 浏览器中，我们可以通过在 Safari 的开发菜单中选择禁用 JavaScript 选项来禁用 JavaScript：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/aa350d78-e4b2-4a08-8635-92a42f3d45e6.png)

图 7.12：使用 Safari 的开发菜单禁用 JavaScript

*图 7.13*显示了**图形用户界面**（**GUI**）-基于 Web 浏览器的联系表格的外观：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/442aef8b-1adc-467b-944c-d6c77989cba5.png)

图 7.13：GUI 型 Web 浏览器中的联系表格

我们遵循与 Lynx Web 浏览器上执行的相同的测试策略。我们部分填写表格并提供一个无效的电子邮件地址，如*图 7.14*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/cf094d58-b72a-4c86-89d3-a817729357c3.png)

图 7.14：联系表格填写不正确

点击“联系”按钮后，错误消息显示在有问题的字段旁边，如*图 7.15*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/0a5811f1-53f5-4575-a008-d21b9623dbbe.png)

图 7.15：错误消息显示在有问题的字段旁边

提交联系表格后，请注意我们收到有关填写不正确的字段的错误。纠正错误后，我们现在准备再次点击“联系”按钮提交表格，如*图 7.16*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/2e7c59e6-71c5-4980-a186-89aa445d881b.png)

图 7.16：准备重新提交的正确填写的联系表格

提交联系表格后，我们被转发到`/contact-confirmation`路由，并收到确认消息，联系表格已正确填写，如*图 7.17*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/a27ce314-b179-4a48-86d3-6480020ac679.png)

图 7.17：确认页面

我们已经实现的基于服务器端的联系表单即使在启用 JavaScript 的情况下也将继续运行。您可能会想为什么我们需要在客户端实现联系表单？我们不能只使用基于服务器端的联系表单并结束吗？

答案归结为为用户提供增强的用户体验。仅使用基于服务器端的联系表单，我们会破坏用户正在体验的单页应用架构。敏锐的读者会意识到，提交表单和重新提交表单都需要完整的页面重新加载。HTTP 重定向到`/contact-confirmation`路由也会破坏用户体验，因为它也会导致完整的页面重新加载。

为了在客户端实现联系表单，需要实现以下两个目标：

+   提供一致、无缝的单页应用体验

+   在客户端提供验证联系表单的能力

第一个目标，提供一致、无缝的单页应用体验，可以通过使用同构模板集来轻松实现，以将内容呈现到主要内容区域的`div`容器中，就像我们在之前的章节中展示的那样。

第二个目标是在客户端验证联系表单的能力，由于 Web 浏览器启用了 JavaScript，这是可能的。有了这个能力，我们可以在客户端验证联系表单本身。考虑这样一种情况，我们有一个用户，在填写联系表单时不断犯错。我们可以减少向 Web 服务器发出的不必要的网络调用。只有在用户通过第一轮验证（在客户端）之后，表单才会通过网络提交到 Web 服务器，在那里进行最终的验证（在服务器端）。

# 客户端考虑

令人惊讶的是，在客户端上启用联系表单并不需要我们做太多工作。让我们逐节检查`client/handlers`文件夹中找到的`contact.go`源文件：

```go
func ContactHandler(env *common.Env) isokit.Handler {
  return isokit.HandlerFunc(func(ctx context.Context) {
    contactForm := forms.NewContactForm(nil)
    DisplayContactForm(env, contactForm)
  })
}
```

这是我们的`ContactHandler`函数，它将为客户端上的`/contact`路由提供服务。我们首先声明并初始化`contactForm`变量，将其分配给通过调用`NewContactForm`构造函数返回的`ContactForm`实例。

请注意，当我们通常应该传递一个`FormParams`结构时，我们将`nil`传递给构造函数。在客户端，我们将填充`FormParams`结构的`FormElement`字段，以将网页上的表单元素与`contactForm`对象关联起来。然而，在呈现网页之前，我们遇到了一个“先有鸡还是先有蛋”的情况。我们无法填充`FormParams`结构的`FormElement`字段，因为网页上还不存在表单元素。因此，我们的首要任务是呈现联系表单，目前，我们将联系表单的`FormParams`结构设置为`nil`以实现这一点。稍后，我们将使用`contactForm`对象的`SetFormParams`方法设置`contactForm`对象的`FormParams`结构。

为了在网页上显示联系表单，我们调用`DisplayContactForm`函数，传入`env`对象和`contactForm`对象。这个函数对于我们保持无缝的单页应用用户体验是至关重要的。`DisplayContactForm`函数如下所示：

```go
func DisplayContactForm(env *common.Env, contactForm *forms.ContactForm) {
  templateData := &templatedata.Contact{PageTitle: "Contact", Form: contactForm}
  env.TemplateSet.Render("contact_content", &isokit.RenderParams{Data: templateData, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent, PageTitle: templateData.PageTitle})
  InitializeContactPage(env, contactForm)
}
```

我们声明并初始化`templateData`变量，这将是我们传递给模板的数据对象。`templateData`变量被分配一个新创建的`templatedata`包中的`Contact`实例，其`PageTitle`属性设置为“联系”，`Form`属性设置为`contactForm`对象。

我们调用`env.TemplateSet`对象的`Render`方法，并指定我们希望渲染`"contact_content"`模板。我们还向`Render`方法提供了等同渲染参数（`RenderParams`），将`Data`字段设置为`templateData`变量，并将`Disposition`字段设置为`isokit.PlacementReplaceInnerContents`，声明了我们将如何相对于关联元素渲染模板内容。通过将`Element`字段设置为`env.PrimaryContent`，我们指定主要内容`div`容器将是模板将要渲染到的关联元素。最后，我们将`PageTitle`属性设置为动态更改网页标题，当用户从客户端着陆在`/contact`路由时。

我们调用`InitializeContactPage`函数，提供`env`对象和`contactForm`对象。回想一下，`InitializeContactPage`函数负责为联系页面设置用户交互相关的代码（事件处理程序）。让我们检查`InitializeContactPage`函数：

```go
func InitializeContactPage(env *common.Env, contactForm *forms.ContactForm) {

  formElement := env.Document.GetElementByID("contactForm").(*dom.HTMLFormElement)
  contactForm.SetFormParams(&isokit.FormParams{FormElement: formElement})
  contactButton := env.Document.GetElementByID("contactButton").(*dom.HTMLInputElement)
  contactButton.AddEventListener("click", false, func(event dom.Event) {
    handleContactButtonClickEvent(env, event, contactForm)
  })
}
```

我们调用`env.Document`对象的`GetElementByID`方法来获取联系表单元素，并将其赋值给变量`formElement`。我们调用`SetFormParams`方法，提供一个`FormParams`结构，并用`formElement`变量填充其`FormElement`字段。此时，我们已经为`contactForm`对象设置了表单参数。我们通过调用`env.Document`对象的`GetElementByID`方法并提供`id`为`"contactButton"`来获取联系表单的`button`元素。

我们在联系`button`的点击事件上添加了一个事件监听器，它将调用`handleContactButtonClickEvent`函数，并传递`env`对象、`event`对象和`contactForm`对象。`handleContactButtonClickEvent`函数非常重要，因为它将在客户端运行表单验证，如果验证成功，它将在服务器端发起 XHR 调用到 Rest API 端点。以下是`handleContactButtonClickEvent`函数的代码：

```go
func handleContactButtonClickEvent(env *common.Env, event dom.Event, contactForm *forms.ContactForm) {

  event.PreventDefault()
  clientSideValidationResult := contactForm.Validate()

  if clientSideValidationResult == true {

    contactFormErrorsChannel := make(chan map[string]string)
    go ContactFormSubmissionRequest(contactFormErrorsChannel, contactForm)
```

我们首先抑制点击联系按钮的默认行为，这将提交整个网页表单。这种默认行为源于联系`button`元素是一个`input`类型为`submit`的元素，当点击时默认行为是提交网页表单。

然后我们声明并初始化`clientSideValidationResult`，一个布尔变量，赋值为调用`contactForm`对象的`Validate`方法的结果。如果`clientSideValidationResult`的值为`false`，我们进入`else`块，在那里调用`contactForm`对象的`DisplayErrors`方法。`DisplayErrors`方法是从`isokit`包中的`BasicForm`类型提供给我们的。

如果`clientSideValidationResult`的值为 true，这意味着表单在客户端成功验证。此时，联系表单提交已经通过了客户端的第一轮验证。

为了开始第二（也是最后）一轮验证，我们需要调用服务器端的 Rest API 端点，负责验证表单内容并重新运行相同的验证。我们创建了一个名为`contactFormErrorsChannel`的通道，这是一个我们将通过其发送`map[string]string`值的通道。我们将`ContactFormSubmissionRequest`函数作为一个 goroutine 调用，传入通道`contactFormErrorsChannel`和`contactForm`对象。`ContactFormSubmissionRequest`函数将在服务器端发起 XHR 调用，验证服务器端的联系表单。一组错误将通过`contactFormErrorsChannel`发送。

让我们在返回`handleContactButtonClickEvent`函数之前快速查看`ContactFormSubmissionRequest`函数：

```go
func ContactFormSubmissionRequest(contactFormErrorsChannel chan map[string]string, contactForm *forms.ContactForm) {

  jsonData, err := json.Marshal(contactForm.Fields())
  if err != nil {
    println("Encountered error: ", err)
    return
  }

  data, err := xhr.Send("POST", "/restapi/contact-form", jsonData)
  if err != nil {
    println("Encountered error: ", err)
    return
  }

  var contactFormErrors map[string]string
  json.NewDecoder(strings.NewReader(string(data))).Decode(&contactFormErrors)

  contactFormErrorsChannel <- contactFormErrors
}
```

在`ContactFormSubmissionRequest`函数中，我们对`contactForm`对象的字段进行 JSON 编组，并通过调用`xhr`包中的`Send`函数向 Web 服务器发出 XHR 调用。我们指定 XHR 调用将使用`POST` HTTP 方法，并将发布到`/restapi/contact-form`端点。我们将联系表单字段的 JSON 编码数据作为`Send`函数的最后一个参数传入。

如果在 JSON 编组过程中或在进行 XHR 调用时没有错误，我们获取从服务器检索到的数据，并尝试将其从 JSON 格式解码为`contactFormErrors`变量。然后我们通过通道`contactFormErrorsChannel`发送`contactFormErrors`变量。

现在，让我们回到`handleContactButtonClickEvent`函数：

```go
    go func() {

      serverContactFormErrors := <-contactFormErrorsChannel
      serverSideValidationResult := len(serverContactFormErrors) == 0

      if serverSideValidationResult == true {
        env.TemplateSet.Render("contact_confirmation_content", &isokit.RenderParams{Data: nil, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent})
      } else {
        contactForm.SetErrors(serverContactFormErrors)
        contactForm.DisplayErrors()
      }

    }()

  } else {
    contactForm.DisplayErrors()
  }
}
```

为了防止在事件处理程序中发生阻塞，我们创建并运行一个匿名的 goroutine 函数。我们将错误的`map`接收到`serverContactFormErrors`变量中，从`contactFormErrorsChannel`中。`serverSideValidationResult`布尔变量负责通过检查错误`map`的长度来确定联系表单中是否存在错误。如果错误的长度为零，表示联系表单提交中没有错误。如果长度大于零，表示联系表单提交中存在错误。

如果`severSideValidationResult`布尔变量的值为`true`，我们在等同模板集上调用`Render`方法，渲染`contact_confirmation_content`模板，并传入等同模板渲染参数。在`RenderParams`对象中，我们将`Data`字段设置为`nil`，因为我们不会向模板传递任何数据对象。我们为`Disposition`字段指定值`isokit.PlacementReplaceInnerContents`，表示我们将对关联元素执行替换内部 HTML 操作。我们将`Element`字段设置为关联元素，即主要内容`div`容器，因为这是模板将要渲染到的位置。

如果`serverSideValidationResult`布尔变量的值为`false`，这意味着表单仍然包含需要纠正的错误。我们在`contactForm`对象上调用`SetErrors`方法，传入`serverContactFormErrors`变量。然后我们在`contactForm`对象上调用`DisplayErrors`方法，将错误显示给用户。

我们几乎完成了，我们在客户端实现联系表单的唯一剩下的事项是实现服务器端的 Rest API 端点，对联系表单提交进行第二轮验证。

# 联系表单 Rest API 端点

在`igweb.go`源文件中，我们已经注册了`/restapi/contact-form`端点及其关联的处理函数`ContactFormEndpoint`：

```go
r.Handle("/restapi/contact-form", endpoints.ContactFormEndpoint(env)).Methods("POST")
```

`ContactFormEndpoint`函数负责为`/restapi/contact-form`端点提供服务：

```go
func ContactFormEndpoint(env *common.Env) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    var fields map[string]string

    reqBody, err := ioutil.ReadAll(r.Body)
    if err != nil {
      log.Print("Encountered error when attempting to read the request body: ", err)
    }

    err = json.Unmarshal(reqBody, &fields)
    if err != nil {
      log.Print("Encountered error when attempting to unmarshal json data: ", err)
    }

    formParams := isokit.FormParams{ResponseWriter: w, Request: r, UseFormFieldsForValidation: true, FormFields: fields}
    contactForm := forms.NewContactForm(&formParams)
    validationResult := contactForm.Validate()

    if validationResult == true {
      submissions.ProcessContactForm(env, contactForm)
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(contactForm.Errors())
  })
}
```

该函数的目的是提供联系表单的服务器端验证，并返回 JSON 编码的错误`map`。我们创建一个`fields`变量，类型为`map[string]string`，表示联系表单中的字段。我们读取请求体，其中包含 JSON 编码的字段`map`。然后我们将 JSON 编码的字段`map`解封到`fields`变量中。

我们创建一个新的`FormParams`实例，并将其分配给变量`formParams`。在`FormParams`结构中，我们为`ResponseWriter`字段指定了`http.ResponseWriter` `w`的值，为`Request`字段指定了`*http.Request` `r`的值。我们将`UseFormFieldsForValidation`字段设置为`true`。这样做将改变默认行为，从请求中获取特定字段的表单值，而是从联系表单的`formFields` `map`中获取表单字段的值。最后，我们将`FormFields`字段设置为`fields`变量，即我们从请求体中 JSON 解组得到的字段`map`。

我们通过调用`NewContactForm`函数并传入`formParams`对象的引用来创建一个新的`contactForm`对象。为了进行服务器端验证，我们只需在`contactForm`对象上调用`Validate`方法，并将方法调用的结果分配给`validationResult`变量。请记住，客户端上存在的相同验证代码也存在于服务器端，并且我们在这里并没有做什么特别的，只是从服务器端调用验证逻辑，假设它不会被篡改。

如果`validationResult`的值为`true`，这意味着联系表单已经通过了服务器端的第二轮表单验证，我们可以调用`submissions`包中的`ProcessContactForm`函数，传入`env`对象和`contactForm`对象。请记住，当成功验证联系表单时，调用`ProcessContactForm`函数意味着我们已经到达了本垒并得分。

如果`validationResult`的值为`false`，我们无需做任何特别的事情。在调用对象的`Validate`方法后，`contactForm`对象的`Errors`字段将被填充。如果没有错误，`Errors`字段将只是一个空的`map`。

我们向客户端发送一个头部，指示服务器将发送 JSON 对象响应。然后，我们将`contactForm`对象的`map`错误编码为其 JSON 表示，并使用`http.ResponseWriter` `w`将其写入客户端。

# 检查客户端验证

现在我们已经准备好联系表单的客户端验证。让我们打开启用了 JavaScript 的网络浏览器。同时打开网络检查器以检查网络调用，如*图 7.18*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/04e8698f-932b-4309-b907-865893dce865.png)

图 7.18：打开网络检查器的联系表单

首先，我们将部分填写联系表单，如*图 7.19*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f3669cae-46e7-40b5-9798-c6bdc4871dd7.png)

图 7.19：填写不正确的联系表单

点击联系按钮后，我们将在客户端触发表单验证错误，如*图 7.20*所示。请注意，当我们这样做时，无论我们点击联系按钮多少次，都不会向服务器发出网络调用：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/46be4e96-7be7-489e-a45e-c3c341c622e4.png)

图 7.20：执行客户端验证后显示错误消息。请注意，没有向服务器发出网络调用

现在，让我们纠正联系表单中的错误（如*图 7.21*所示）并准备重新提交：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e9b46ccf-8c67-429b-9be5-f65af141f8d3.png)

图 7.21：填写完整的联系表单，准备重新提交

重新提交表单后，我们收到确认消息，如*图 7.22*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/4cc80308-7acd-4d2f-a7ad-a8a6668cddb0.png)

图 7.22：进行 XHR 调用，包含表单数据，并在成功的服务器端表单验证后呈现确认消息

请注意，如*图 7.23*所示，发起了一个 XHR 调用到 Web 服务器。检查调用的响应，我们可以看到从端点响应返回的空对象（`{}`）表示`errors` `map`为空，表明表单提交成功：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/e687cd4e-0305-4735-aba2-9ba6cdec6b17.png)

图 7.23：XHR 调用返回了一个空的错误映射，表明表单成功通过了服务器端的表单验证

现在我们已经验证了客户端验证逻辑在联系表单上的工作，我们必须强调一个重要的观点，即在接受来自客户端的数据时非常重要的一点。服务器必须始终拥有否决权，当涉及到验证用户输入的数据时。在服务器端执行的第二轮验证应该是一个强制性的步骤。让我们看看为什么我们总是需要服务器端验证。

# 篡改客户端验证结果

让我们考虑这样一种情况，即我们有一个邪恶（而且聪明）的用户，他知道如何绕过我们的客户端验证逻辑。毕竟，这是 JavaScript，在 Web 浏览器中运行。没有什么能阻止一个恶意用户将我们的客户端验证逻辑抛到脑后。为了模拟这样的篡改事件，我们只需要在`contact.go`源文件中将`clientSideValidationResult`变量的布尔值赋值为`true`。

```go
func handleContactButtonClickEvent(env *common.Env, event dom.Event, contactForm *forms.ContactForm) {

  event.PreventDefault()
  clientSideValidationResult := contactForm.Validate()

  clientSideValidationResult = true

  if clientSideValidationResult == true {

    contactFormErrorsChannel := make(chan map[string]string)
    go ContactFormSubmissionRequest(contactFormErrorsChannel, contactForm)

    go func() {

      serverContactFormErrors := <-contactFormErrorsChannel
      serverSideValidationResult := len(serverContactFormErrors) == 0

      if serverSideValidationResult == true {
        env.TemplateSet.Render("contact_confirmation_content", &isokit.RenderParams{Data: nil, Disposition: isokit.PlacementReplaceInnerContents, Element: env.PrimaryContent})
      } else {
        contactForm.SetErrors(serverContactFormErrors)
        contactForm.DisplayErrors()
      }

    }()

  } else {
    contactForm.DisplayErrors()
  }
}
```

在这一点上，我们已经绕过了客户端验证的真正结果，强制客户端网络应用程序始终通过客户端进行的联系表单验证。如果我们仅在客户端执行表单验证，这将使我们陷入非常糟糕的境地。这正是为什么我们需要在服务器端进行第二轮验证的原因。

让我们再次打开 Web 浏览器，部分填写表单，如*图 7.24*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/b39c09da-a4a1-4b4b-85a2-c134c6b018b0.png)

图 7.24：即使禁用了客户端表单验证，服务器端表单验证也阻止了填写不正确的联系表单被提交

请注意，这一次，当单击联系按钮时，将发起 XHR 调用到服务器端的 Rest API 端点，返回联系表单中的错误`map`，如*图 7.25*所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/c04dd7ed-d608-4d0a-8f1a-08631d008d15.png)

图 7.25：服务器响应中的错误映射填充了一个错误，指示电子邮件地址字段中输入的值具有不正确的语法

在服务器端执行的第二轮验证已经启动，并阻止了恶意用户能够到达本垒并得分。如果客户端验证无法正常工作，服务器端验证将捕获到不完整或格式不正确的表单字段。这是为什么您应该始终为您的网络表单实现服务器端表单验证的一个重要原因。

# 总结

在本章中，我们演示了构建一个可访问的、同构的网络表单的过程。首先，我们演示了同构网络表单在禁用 JavaScript 和启用 JavaScript 的情况下的流程。

我们向您展示了如何创建一个同构的网络表单，它具有在各种环境中共享表单代码和验证逻辑的能力。在表单包含错误的情况下，我们向您展示了如何以有意义的方式向用户显示错误。创建的同构网络表单非常健壮，并能够在 Web 浏览器中禁用 JavaScript 或 JavaScript 运行时不存在的情况下（例如 Lynx Web 浏览器），以及在启用 JavaScript 的 Web 浏览器中运行。

我们演示了使用 Lynx 网络浏览器测试可访问的同构网络表单，以验证该表单对需要更大可访问性的用户是否可用。我们还验证了即使在一个配备了 JavaScript 运行时的网络浏览器中，该表单也能正常运行，即使 JavaScript 被禁用。

在 JavaScript 启用的情况下，我们向您展示了如何在客户端验证表单并在执行客户端验证后将数据提交到 Rest API 端点。即使在方便且具有更高能力的客户端验证表单的情况下，我们强调了始终在服务器端验证表单的重要性，通过演示服务器端表单验证启动的情景，即使在潜在的情况下，客户端验证结果被篡改。

用户与联系表单之间的交互非常简单。用户必须正确填写表单才能将数据提交到服务器，最终表单数据将被处理。在下一章中，我们将超越这种简单的交互，考虑用户和网络应用程序以一种几乎类似对话的方式进行交流的情景。在第八章中，《实时网络应用功能》，我们将实现 IGWEB 的实时聊天功能，允许网站用户与聊天机器人进行简单的问答对话。


# 第八章：实时 Web 应用功能

在上一章中，我们考虑了如何通过 Web 表单验证和处理用户生成的数据。当用户正确填写联系表单时，它成功通过了两轮验证，并且用户会收到确认消息。一旦表单被提交，工作流程就完成了。如果我们想考虑一个更有吸引力的工作流程，一个用户可以以对话的方式与服务器端应用程序进行交互的工作流程呢？

今天的 Web 与蒂姆·伯纳斯-李（Tim Berners-Lee）在 1990 年代初设计的起步阶段的 Web 大不相同。当时，Web 的重点是超链接连接的文档。客户端和服务器之间的 HTTP 事务一直意味着短暂存在。

在 21 世纪初，这种情况开始发生变化。研究人员展示了服务器如何能够与客户端保持持久连接的手段。客户端的早期原型是使用 Adobe Flash 创建的，这是当时唯一可用的技术之一，用于在 Web 服务器和 Web 客户端之间建立持久连接。

与这些早期尝试并行的是，一种效率低下的时代诞生了，即 AJAX（XHR）长轮询。客户端将继续向服务器发出调用（类似于心跳检查），并检查客户端感兴趣的某些状态是否发生了变化。服务器将返回相同的、疲惫的响应，直到客户端感兴趣的状态发生变化，然后可以将其报告给客户端。这种方法的主要低效性在于 Web 客户端和 Web 服务器之间必须进行的网络调用数量。不幸的是，AJAX 长轮询的低效做法变得如此流行，以至于今天仍被许多网站广泛使用。

实时 Web 应用功能的理念是通过几乎实时地提供信息来提供更好的用户体验。请记住，由于网络延迟和物理定律对信号的限制，没有任何通信是真正的“实时”，而是“几乎实时”。

实现实时 Web 应用功能的主要组成部分是 WebSocket，这是一种允许 Web 服务器和 Web 客户端之间进行双向通信的协议。由于 Go 具有用于网络和 Web 编程的内置功能，因此 Go 是实现实时 Web 应用程序的理想编程语言。

在本章中，我们将构建一个实时 Web 应用程序功能的实时聊天应用程序，这将允许网站用户与一个基本的聊天机器人进行对话。当用户向机器人提问时，机器人将实时回复，并且用户与机器人之间的所有通信都将通过 Web 浏览器和 Web 服务器之间的 WebSocket 连接进行。

在本章中，我们将涵盖以下主题：

+   实时聊天功能

+   实现实时聊天的服务器端功能

+   实现实时聊天的客户端功能

+   与代理进行对话

# 实时聊天功能

当今，很常见看到聊天机器人（也称为代理）为网站用户提供各种目的的服务，从决定购买什么鞋子到提供有关哪些股票适合客户投资组合的建议。我们将构建一个基本的聊天机器人，为 IGWEB 用户提供有关同构 Go 的友好提示。

一旦激活了实时聊天功能，用户可以继续访问网站的不同部分，而不会因为使用网站上的导航菜单或链接而中断与机器人的对话。在现实世界的场景中，这种功能对于产品销售和技术支持的使用场景都是一个有吸引力的选择。例如，如果用户对网站上列出的某个产品有疑问，用户可以自由浏览网站，而不必担心失去与代理人的当前聊天对话。

请记住，我们将构建的代理具有较低的智能水平。这里仅用于说明目的，并且在生产需求中应该使用更健壮的**人工智能**（**AI**）解决方案。通过本章您将获得的知识，应该可以相当轻松地用更健壮的代理的大脑替换当前的代理，以满足实时聊天功能中的特定需求。

# 设计实时聊天框

以下图是 IGWEB 顶部栏的线框设计。最右边的图标在点击时将激活实时聊天功能：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/8e3c6a10-56a1-4066-919b-6f8bd0060092.jpg)

图 8.1：IGWEB 顶部栏的线框设计

以下图是实时聊天框的线框设计。聊天框包括代理人“Case”的头像图像以及其姓名和职称。关闭按钮包括在聊天框的右上角。用户可以在底部文本区域输入他们的消息，该区域具有占位文本“在此输入您的消息”。与人类和机器人的对话将显示在聊天框的中间区域：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/882b8a7c-655f-4dd8-9e42-da1d856c53d8.png)

图 8.2：实时聊天框的线框设计

# 实现实时聊天框模板

为了在网站的所有部分中都有聊天框，我们需要将聊天框`div`容器放置在网页布局模板（`layouts/webpage_layout.tmpl`）中主要内容`div`容器的正下方：

```go
<!doctype html>
<html>
  {{ template "partials/header_partial" . }}

    <div id="primaryContent" class="pageContent">
      {{ template "pagecontent" . }}
    </div>

 <div id="chatboxContainer" class="containerPulse">
 </div>

  {{ template "partials/footer_partial" . }}
</html>
```

聊天框将作为`shared/templates/partials`文件夹中的`chatbox_partial.tmpl`源文件中的部分模板来实现：

```go
<div id="chatbox">
  <div id="chatboxHeaderBar" class="chatboxHeader">
    <div id="chatboxTitle" class="chatboxHeaderTitle"><span>Chat with {{.AgentName}}</span></div>
    <div id="chatboxCloseControl">X</div>
  </div>

  <div class="chatboxAgentInfo">
    <div class="chatboxAgentThumbnail"><img src="img/{{.AgentThumbImagePath}}" height="81px"></div>
    <div class="chatboxAgentName">{{.AgentName}}</div>
    <div class="chatboxAgentTitle">{{.AgentTitle}}</div>
  </div>

  <div id="chatboxConversationContainer">

  </div>

  <div id="chatboxMsgInputContainer">
 <input type="text" id="chatboxInputField" placeholder="Type your message here...">

 </input>
  </div>

  <div class="chatboxFooter">
    <a href="http://www.isomorphicgo.org" target="_blank">Powered by Isomorphic Go</a>
  </div>
</div>
```

这是实现实时聊天框*图 8.2*中所示线框设计所需的 HTML 标记。请注意，`input`文本字段具有 id`"chatboxInputField"`。这是用户将能够输入其消息的`input`字段。创建的每条消息，无论是用户编写的消息还是机器人编写的消息，都将使用`livechatmsg_partial.tmpl`模板：

```go
<div class="chatboxMessage">
 <div class="chatSenderName">{{.Name}}</div>
 <div class="chatSenderMsg">{{.Message}}</div>
</div>
```

每条消息都在自己的`div`容器中，其中有两个`div`容器（以粗体显示），分别包含消息发送者的姓名和消息本身。

在实时聊天功能中不需要按钮，因为我们将添加一个事件侦听器来监听按下 Enter 键以通过 WebSocket 连接将用户的消息提交到服务器。

现在我们已经实现了用于呈现聊天框的 HTML 标记，让我们来检查在服务器端实现实时聊天功能所需的功能。

# 实现实时聊天的服务器端功能

当实时聊天功能激活时，我们将在 Web 客户端和 Web 服务器之间创建一个持久的 WebSocket 连接。Gorilla Web Toolkit 在其`websocket`包中提供了对 WebSocket 协议的出色实现，该包可以在[`github.com/gorilla/websocket`](http://github.com/gorilla/websocket)找到。要获取`websocket`包，可以发出以下命令：

```go
$ go get github.com/gorilla/websocket
```

Gorilla Web Toolkit 还提供了一个有用的示例 Web 聊天应用程序：

[`github.com/gorilla/websocket/tree/master/examples/chat`](https://github.com/gorilla/websocket/tree/master/examples/chat)。

我们将重新利用大猩猩的示例网络聊天应用程序，而不是重新发明轮子，以实现实时聊天功能。从网络聊天示例中需要的源文件已经复制到`chat`文件夹中。

我们需要进行三个重大改变，以利用大猩猩提供的示例聊天应用程序实现实时聊天功能：

+   聊天机器人（代理）的回复应该针对特定用户，而不是发送给所有连接的用户

+   我们需要创建功能，允许聊天机器人向用户发送消息

+   我们需要在 Go 中实现聊天应用程序的前端部分

让我们更详细地考虑这三点。

首先，大猩猩的网络聊天示例是一个自由聊天室。任何用户都可以进来，输入消息，所有连接到聊天服务器的其他用户都能看到消息。实时聊天功能的一个主要要求是，聊天机器人和人之间的每次对话都应该是独占的。代理的回复必须针对特定用户，而不是所有连接的用户。

其次，大猩猩网络工具包中的示例网络聊天应用程序不会向用户发送任何消息。这就是自定义聊天机器人出现的地方。代理将直接通过已建立的 WebSocket 连接与用户通信。

第三，示例网络聊天应用程序的前端部分是作为包含内联 CSS 和 JavaScript 的 HTML 文档实现的。正如你可能已经猜到的那样，我们将在 Go 中实现实时聊天功能的前端部分，代码将驻留在`client/chat`文件夹中。

既然我们已经制定了使用大猩猩网络聊天示例作为起点来实现实时聊天功能的行动计划，让我们开始实施吧。

我们将创建的修改后的网络聊天应用程序包含两种主要类型：`Hub`和`Client`。

# 中心类型

聊天中心负责维护客户端连接列表，并指示聊天机器人向相关客户端广播消息。例如，如果 Alice 问了“什么是同构 Go?*”，聊天机器人的答案应该发给 Alice，而不是 Bob（他可能还没有问问题）。

`Hub`结构如下：

```go
type Hub struct {
  chatbot bot.Bot
  clients map[*Client]bool
  broadcastmsg chan *ClientMessage
  register chan *Client
  unregister chan *Client
}
```

`chatbot`是一个实现`Bot`接口的聊天机器人（代理）。这是将回答从客户端收到的问题的大脑。

`clients`映射用于注册客户端。存储在`map`中的键值对包括键，指向`Client`实例的指针，值包括一个布尔值，设置为`true`，表示客户端已连接。客户端通过`broadcastmsg`、`register`和`unregister`通道与中心通信。`register`通道向中心注册客户端。`unregister`通道向中心注销客户端。客户端通过`broadcastmsg`通道发送用户输入的消息，这是一个`ClientMessage`类型的通道。这是我们引入的`ClientMessage`结构：

```go
type ClientMessage struct {
  client *Client
  message []byte
}
```

为了实现我们之前提出的第一个重大变化，即代理和用户之间的对话的独占性，我们使用`ClientMessage`结构来存储`Client`实例的指针，以及用户的消息本身（一个`byte`切片）。

构造函数`NewHub`接受实现`Bot`接口的`chatbot`，并返回一个新的`Hub`实例：

```go
func NewHub(chatbot bot.Bot) *Hub {
  return &Hub{
    chatbot: chatbot,
    broadcastmsg: make(chan *ClientMessage),
    register: make(chan *Client),
    unregister: make(chan *Client),
    clients: make(map[*Client]bool),
  }
}
```

我们实现了一个导出的获取方法`ChatBot`，以便从`Hub`对象中访问`chatbot`：

```go
func (h *Hub) ChatBot() bot.Bot {
  return h.chatbot
}
```

当我们实现一个 Rest API 端点来将机器人的详细信息（名称、标题和头像图像）发送给客户端时，这个行动将是重要的。

`SendMessage`方法负责向特定客户端广播消息：

```go
func (h *Hub) SendMessage(client *Client, message []byte) {
  client.send <- message
}
```

该方法接受一个指向`Client`的指针和`message`，这是应该发送给特定客户端的`byte`切片。消息将通过客户端的`send`通道发送。

调用`Run`方法启动聊天 hub：

```go
func (h *Hub) Run() {
  for {
    select {
    case client := <-h.register:
      h.clients[client] = true
      greeting := h.chatbot.Greeting()
      h.SendMessage(client, []byte(greeting))

    case client := <-h.unregister:
      if _, ok := h.clients[client]; ok {
        delete(h.clients, client)
        close(client.send)
      }
    case clientmsg := <-h.broadcastmsg:
      client := clientmsg.client
      reply := h.chatbot.Reply(string(clientmsg.message))
      h.SendMessage(client, []byte(reply))
    }
  }
}
```

我们在`for`循环内使用`select`语句等待多个客户端操作。

如果通过 hub 的`register`通道传入了一个`Client`的指针，hub 将通过将`client`指针（作为键）添加到客户端`map`中并为其设置一个值为`true`来注册新客户端。我们将调用`chatbot`的`Greeting`方法获取要返回给客户端的`greeting`消息。一旦我们得到了问候语（字符串值），我们调用`SendMessage`方法，传入`client`和转换为`byte`切片的`greeting`。

如果通过 hub 的`unregister`通道传入了一个`Client`的指针，hub 将删除给定`client`的`map`中的条目，并关闭客户端的`send`通道，这表示该`client`不会再向服务器发送任何消息。

如果通过 hub 的`broadcastmsg`通道传入了一个`ClientMessage`的指针，hub 将把客户端的`message`（作为字符串值）传递给`chatbot`对象的`Reply`方法。一旦我们得到了来自代理的`reply`（字符串值），我们调用`SendMessage`方法，传入`client`和转换为`byte`切片的`reply`。

# 客户端类型

`Client`类型充当`Hub`和`websocket`连接之间的代理。

以下是`Client`结构的样子：

```go
type Client struct {
  hub *Hub
  conn *websocket.Conn
  send chan []byte
}
```

每个`Client`值都包含指向`Hub`的指针，指向`websocket`连接的指针以及用于出站消息的缓冲通道`send`。

`readPump`方法负责将通过`websocket`连接传入的入站消息中继到 hub：

```go
func (c *Client) readPump() {
  defer func() {
    c.hub.unregister <- c
    c.conn.Close()
  }()
  c.conn.SetReadLimit(maxMessageSize)
  c.conn.SetReadDeadline(time.Now().Add(pongWait))
  c.conn.SetPongHandler(func(string) error { c.conn.SetReadDeadline(time.Now().Add(pongWait)); return nil })
  for {
    _, message, err := c.conn.ReadMessage()
    if err != nil {
      if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway) {
        log.Printf("error: %v", err)
      }
      break
    }
    message = bytes.TrimSpace(bytes.Replace(message, newline, space, -1))
    // c.hub.broadcast <- message

    clientmsg := &ClientMessage{client: c, message: message}
 c.hub.broadcastmsg <- clientmsg

  }
}
```

我们不得不对这个函数进行轻微的更改，以满足实时聊天功能的要求。在 Gorilla Web 聊天示例中，仅仅是将消息中继到`Hub`。由于我们正在将聊天机器人的响应发送回发送它们的客户端，我们不仅需要将消息发送到 hub，还需要将发送消息的客户端也发送到 hub。我们通过创建一个`ClientMessage`结构来实现这一点：

```go
type ClientMessage struct {
  client *Client
  message []byte
}
```

`ClientMessage`结构包含字段，用于保存客户端的指针以及`message`，一个`byte`切片。

回到`client.go`源文件中的`readPump`函数，以下两行对于`Hub`知道哪个客户端发送了消息至关重要。

```go
    clientmsg := &ClientMessage{client: c, message: message}
    c.hub.broadcastmsg <- clientmsg
```

`writePump`方法负责从客户端的`send`通道中中继出站消息到`websocket`连接：

```go
func (c *Client) writePump() {
  ticker := time.NewTicker(pingPeriod)
  defer func() {
    ticker.Stop()
    c.conn.Close()
  }()
  for {
    select {
    case message, ok := <-c.send:
      c.conn.SetWriteDeadline(time.Now().Add(writeWait))
      if !ok {
        // The hub closed the channel.
        c.conn.WriteMessage(websocket.CloseMessage, []byte{})
        return
      }

      w, err := c.conn.NextWriter(websocket.TextMessage)
      if err != nil {
        return
      }
      w.Write(message)

      // Add queued chat messages to the current websocket message.
      n := len(c.send)
      for i := 0; i < n; i++ {
        w.Write(newline)
        w.Write(<-c.send)
      }

      if err := w.Close(); err != nil {
        return
      }
    case <-ticker.C:
      c.conn.SetWriteDeadline(time.Now().Add(writeWait))
      if err := c.conn.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
        return
      }
    }
  }
}
```

`ServeWS`方法旨在由 Web 应用程序注册为 HTTP 处理程序：

```go
func ServeWs(hub *Hub) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
      log.Println(err)
      return
    }
    client := &Client{hub: hub, conn: conn, send: make(chan []byte, 256)}
    client.hub.register <- client
    go client.writePump()
    client.readPump()
  })
}
```

该方法执行两个重要任务。该方法将普通的 HTTP 连接升级为`websocket`连接，并将客户端注册到 hub。

现在我们已经为我们的 Web 聊天服务器设置了代码，是时候在我们的 Web 应用程序中激活它了。

# 激活聊天服务器

在`igweb.go`源文件中，我们包含了一个名为`startChatHub`的函数，它负责启动`Hub`：

```go
func startChatHub(hub *chat.Hub) {
  go hub.Run()
}
```

我们在`main`函数中添加以下代码来创建一个新的 chatbot，将其与`Hub`关联并启动`Hub`：

```go
  chatbot := bot.NewAgentCase()
  hub := chat.NewHub(chatbot)
  startChatHub(hub)
```

当我们调用`registerRoutes`函数为服务器端 Web 应用程序注册所有路由时，请注意我们还向函数传递了`hub`值：

```go
  r := mux.NewRouter()
  registerRoutes(&env, r, hub)
```

在`registerRoutes`函数中，我们需要`hub`来为返回代理信息的 Rest API 端点注册路由处理程序：

```go
r.Handle("/restapi/get-agent-info", endpoints.GetAgentInfoEndpoint(env, hub.ChatBot()))
```

我们将在*向客户端公开代理信息*部分介绍这个端点。

`hub`还用于注册 WebSocket 路由`/ws`的路由处理程序。我们注册`ServeWS`处理程序函数，传入`hub`：

```go
  r.Handle("/ws", chat.ServeWs(hub))
```

现在我们已经准备好激活聊天服务器，是时候专注于实时聊天功能的明星——聊天代理了。

# 代理的大脑

我们将用于实现实时聊天功能的聊天机器人类型`AgentCase`将实现以下`Bot 接口`：

```go
type Bot interface {
  Greeting() string
  Reply(string) string
  Name() string
  Title() string
  ThumbnailPath() string
  SetName(string)
  SetTitle(string)
  SetThumbnailPath(string)
}
```

`Greeting`方法将用于向用户发送初始问候，诱使他们与聊天机器人互动。

`Reply`方法接受一个问题（字符串），并返回给定问题的回复（也是一个字符串）。

其余实现的方法纯粹是出于心理原因，让人类产生与某人交流而不是某物的错觉。

`Name`方法是一个 getter 方法，返回聊天机器人的名称。

`Title`方法是一个 getter 方法，返回聊天机器人的标题。

`ThumbnailPath`方法是一个 getter 方法，返回聊天机器人的头像图像的路径。

每个 getter 方法都有一个对应的 setter 方法：`SetName`、`SetTitle`和`SetThumbnailPath`。

通过定义`Bot`接口，我们清楚地说明了聊天机器人的期望。这使我们能够在将来使聊天机器人解决方案具有可扩展性。例如，`Case`展示的智能可能过于基础和限制。在不久的将来，我们可能希望实现一个名为 Molly 的机器人，其智能可能使用更强大的算法实现。只要 Molly 聊天机器人实现了`Bot`接口，新的聊天机器人就可以轻松地插入到我们的 Web 应用程序中。

实际上，从服务器端 Web 应用程序的角度来看，这只是一行代码的更改。我们将实例化一个`AgentMolly`实例，而不是实例化一个`AgentCase`实例。除了智能上的差异，新的聊天机器人 Molly 将具有自己的名称、标题和头像图像，因此人类可以将其与`Case`区分开来。

以下是`AgentCase`结构：

```go
type AgentCase struct {
 Bot
 name string
 title string
 thumbnailPath string
 knowledgeBase map[string]string
 knowledgeCorpus []string
 sampleQuestions []string
}
```

我们已经将`Bot`接口嵌入到`struct`定义中，表明`AgentCase`类型将实现`Bot`接口。`name`字段是代理的名称。`title`字段是代理的标题。`thumbnailPath`字段用于指定聊天机器人头像图像的路径。

`knowledgeBase`字段是`map`类型的`map[string]string`。这本质上是代理的大脑。`map`中的键是特定问题中发现的常见术语。`map`中的值是问题的答案。

`knowledgeCorpus`字段是一个字符串`byte`切片，是机器人可能被问到的问题中存在的术语的知识语料库。我们使用`knowledgeBase`映射的键来构建`knowledgeCorpus`。语料库是用于进行语言分析的文本集合。在我们的情况下，我们将根据人类用户提供给机器人的问题（查询）进行语言分析。

`sampleQuestions`字段是一个字符串`byte`切片，其中包含用户可能向聊天机器人提出的示例问题列表。聊天机器人在问候用户时将向用户提供一个示例问题，以诱使人类用户进行对话。人类用户可以根据自己的喜好自由地改写示例问题或提出完全不同的问题。

`initializeIntelligence`方法用于初始化 Case 的大脑：

```go
func (a *AgentCase) initializeIntelligence() {

  a.knowledgeBase = map[string]string{
    "isomorphic go isomorphic go web applications": "Isomorphic Go is the methodology to create isomorphic web applications using the Go (Golang) programming language. An isomorphic web application, is a web application, that contains code which can run, on both the web client and the web server.",
    "kick recompile code restart web server instance instant kickstart lightweight mechanism": "Kick is a lightweight mechanism to provide an instant kickstart to a Go web server instance, upon the modification of a Go source file within a particular project directory (including any subdirectories). An instant kickstart consists of a recompilation of the Go code and a restart of the web server instance. Kick comes with the ability to take both the go and gopherjs commands into consideration when performing the instant kickstart. This makes it a really handy tool for isomorphic golang projects.",
    "starter code starter kit": "The isogoapp, is a basic, barebones web app, intended to be used as a starting point for developing an Isomorphic Go application. Here's the link to the github page: https://github.com/isomorphicgo/isogoapp",
    "lack intelligence idiot stupid dumb dummy don't know anything": "Please don't question my intelligence, it's artificial after all!",
    "find talk topic presentation lecture subject": "Watch the Isomorphic Go talk by Kamesh Balasubramanian at GopherCon India: https://youtu.be/zrsuxZEoTcs",
    "benefits of the technology significance of the technology importance of the technology": "Here are some benefits of Isomorphic Go: Unlike JavaScript, Go provides type safety, allowing us to find and eliminate many bugs at compile time itself. Eliminates mental context-shifts between back-end and front-end coding. Page loading prompts are not necessary.",
    "perform routing web app register routes define routes": "You can implement client-side routing in your web application using the isokit Router preventing the dreaded full page reload.",
    "render templates perform template rendering": "Use template sets, a set of project templates that are persisted in memory and are available on both the server-side and the client-side",
    "cogs reusable components react-like react": "Cogs are reuseable components in an Isomorphic Go web application.",
  }

  a.knowledgeCorpus = make([]string, 1)
  for k, _ := range a.knowledgeBase {
    a.knowledgeCorpus = append(a.knowledgeCorpus, k)
  }

  a.sampleQuestions = []string{"What is isomorphic go?", "What are the benefits of this technology?", "Does isomorphic go offer anything react-like?", "How can I recompile code instantly?", "How can I perform routing in my web app?", "Where can I get starter code?", "Where can I find a talk on this topic?"}

}
```

在这个方法中有三个重要的任务：

+   首先，我们设置 Case 的知识库。

+   其次，我们设置 Case 的知识语料库。

+   第三，我们设置 Case 将在问候人类用户时使用的示例问题。

我们必须处理的第一个任务是设置 Case 的知识库。这包括设置`AgentCase`实例的`knowledgeBase`属性。如前所述，`map`中的键指的是问题中的术语，`map`中的值是问题的答案。例如，`"同构 go 同构 go web 应用程序"`键可以处理以下问题：

+   什么是同构 Go？

+   你能告诉我关于同构 Go 的情况吗？

它还可以处理不是问题的陈述：

+   介绍一下同构 Go

+   给我一个关于同构 Go 的概述

由于`knowledgeBase`映射的地图文字声明中包含大量文本，我建议您在计算机上查看源文件`agentcase.go`。

我们必须处理的第二个任务是设置 Case 的语料库，这是用于针对用户问题进行语言分析的文本集合。语料库是从`knowledgeBase`映射的键构造的。我们将`AgentCase`实例的`knowledgeCorpus`字段属性设置为使用内置的`make`函数创建的新的字符串`byte`切片。使用`for`循环，我们遍历`knowledgeBase map`中的所有条目，并将每个键附加到`knowledgeCorpus`字段切片中。

我们必须处理的第三个也是最后一个任务是设置`Case`将呈现给人类用户的示例问题。我们简单地填充`AgentCase`实例的`sampleQuestions`属性。我们使用字符串文字声明来填充包含在字符串`byte`切片中的所有示例问题。

这是`AgentCase`类型的 getter 和 setter 方法：

```go
func (a *AgentCase) Name() string {
  return a.name
}

func (a *AgentCase) Title() string {
  return a.title
}

func (a *AgentCase) ThumbnailPath() string {
  return a.thumbnailPath
}

func (a *AgentCase) SetName(name string) {
  a.name = name
}

func (a *AgentCase) SetTitle(title string) {
  a.title = title
}

func (a *AgentCase) SetThumbnailPath(thumbnailPath string) {
  a.thumbnailPath = thumbnailPath
}
```

这些方法用于获取和设置`AgentCase`对象的`name`，`title`和`thumbnailPath`字段。

这是用于创建新的`AgentCase`实例的构造函数：

```go
func NewAgentCase() *AgentCase {
  agentCase := &AgentCase{name: "Case", title: "Resident Isomorphic Gopher Agent", thumbnailPath: "/static/images/chat/Case.png"}
  agentCase.initializeIntelligence()
  return agentCase
}
```

我们声明并初始化`agentCase`变量为一个新的`AgentCase`实例，设置`name`，`title`和`thumbnailPath`字段。然后我们调用`initializeIntelligence`方法来初始化 Case 的大脑。最后，我们返回新创建和初始化的`AgentCase`实例。

# 问候人类

`Greeting`方法用于在激活实时聊天功能时向用户提供首次问候：

```go
func (a *AgentCase) Greeting() string {

  sampleQuestionIndex := randomNumber(0, len(a.sampleQuestions))
  greeting := "Hi there! I'm Case. You can ask me a question on Isomorphic Go. Such as...\"" + a.sampleQuestions[sampleQuestionIndex] + "\""
  return greeting

}
```

由于问候将包括一个可以问 Case 的随机选择的示例问题，因此调用`randomNumber`函数来获取示例问题的索引号。我们将最小值和最大值传递给`randomNumber`函数，以指定生成的随机数应该在的范围内。

这是`randomNumber`函数用于生成给定范围内的随机数：

```go
func randomNumber(min, max int) int {
  rand.Seed(time.Now().UTC().UnixNano())
  return min + rand.Intn(max-min)
}
```

回到`Greeting`方法，我们使用随机索引从`sampleQuestions`字符串切片中检索示例问题。然后我们将示例问题分配给`greeting`变量并返回`greeting`。

# 回答人类的问题

现在我们已经初始化了聊天机器人的智能，并准备好迎接人类用户，是时候指导聊天机器人如何思考用户的问题，以便聊天机器人可以提供明智的回答了。

聊天机器人将发送给人类用户的回复仅限于`AgentCase`结构的`knowledgeBase`映射中的值。如果人类用户问的问题超出了聊天机器人所知道的范围（知识语料库），它将简单地回复消息“我不知道答案。”

为了分析用户的问题并为其提供最佳回复，我们将使用`nlp`包，其中包含一系列可用于基本自然语言处理的机器学习算法。

您可以通过发出以下`go get`命令来安装`nlp`包：

```go
$ go get github.com/james-bowman/nlp
```

让我们逐步了解`Reply`方法，从方法声明开始：

```go
func (a *AgentCase) Reply(query string) string {
```

该函数接收一个问题字符串，并返回给定问题的答案字符串。

我们声明`result`变量，表示用户问题的答案：

```go
  var result string
```

`result`变量将由`Reply`方法返回。

使用`nlp`包，我们创建一个新的`vectoriser`和一个新的`transformer`：

```go
  vectoriser := nlp.NewCountVectoriser(true)
  transformer := nlp.NewTfidfTransformer()
```

**`vectoriser`**将用于将知识语料库中的查询术语编码为术语文档矩阵，其中每列代表语料库中的一个文档，每行代表一个术语。它用于跟踪在特定文档中找到的术语的频率。对于我们的使用场景，您可以将文档视为在`knowledgeCorpus`字符串切片中找到的唯一条目。

`transformer`将用于消除`knowledgeCorpus`中频繁出现术语的偏差。例如，`knowledgeCorpus`中重复出现的单词，如*the*、*and*和*web*，将具有较小的权重。转换器是**TFIDF（词频逆文档频率）**转换器。

然后我们继续创建`reducer`，这是一个新的`TruncatedSVD`实例：

```go
  reducer := nlp.NewTruncatedSVD(4)
```

我们刚刚声明的`reducer`很重要，因为我们将执行**潜在语义分析**（**LSA**），也称为**潜在语义索引**（**LSI**），以搜索和检索与用户查询术语相匹配的正确文档。LSA 帮助我们根据术语的共现来找到语料库中存在的语义属性。它假设频繁一起出现的单词必须具有一定的语义关系。

`reducer`用于查找可能隐藏在文档特征向量中的术语频率下的语义含义。

以下代码是一个将语料库转换为潜在语义索引的管道，该索引适合于文档的模型：

```go
  matrix, _ := vectoriser.FitTransform(a.knowledgeCorpus...)
  matrix, _ = transformer.FitTransform(matrix)
  lsi, _ := reducer.FitTransform(matrix)
```

我们必须通过相同的管道运行用户的查询，以便它在相同的维度空间中被投影：

```go
  matrix, _ = vectoriser.Transform(query)
  matrix, _ = transformer.Transform(matrix)
  queryVector, _ := reducer.Transform(matrix)
```

现在我们已经准备好了`lsi`和`queryVector`，是时候找到最匹配查询术语的文档了。我们通过计算我们语料库中每个文档与查询的余弦相似度来实现这一点：

```go
  highestSimilarity := -1.0
  var matched int
  _, docs := lsi.Dims()
  for i := 0; i < docs; i++ {
    similarity := nlp.CosineSimilarity(queryVector.(mat.ColViewer).ColView(0), lsi.(mat.ColViewer).ColView(i))
    if similarity > highestSimilarity {
      matched = i
      highestSimilarity = similarity
    }
  }
```

**余弦相似度**计算两个数值向量之间的角度差异。

与用户查询具有最高相似度的语料库中的文档将被匹配为最能反映用户问题的最佳文档。余弦相似度的可能值可以在 0 到 1 的范围内。0 值表示完全正交，1 值表示完全匹配。余弦相似度值也可以是**NaN（不是数字）**值。NaN 值表明根本没有匹配。

如果没有找到匹配，`highestSimilarity`值将为`-1`；否则，它将是 0 到 1 之间的值：

```go
  if highestSimilarity == -1 {
    result = "I don't know the answer to that one."
  } else {
    result = a.knowledgeBase[a.knowledgeCorpus[matched]]
  }

  return result
```

在`if`条件块中，我们检查`highestSimilarity`值是否为`-1`；如果是，用户的答案将是`"I don't know the answer to that one."`。

如果我们到达`else`块，表示`highestSimilarity`是 0 到 1 之间的值，表示找到了匹配。回想一下，我们`knowledgeCorpus`中的文档在`knowledgeBase` `map`中有对应的键。用户问题的答案是`knowledgeBase` `map`中提供的键的值，我们将`result`字符串设置为这个值。在方法的最后一行代码中，我们返回`result`变量。

实现聊天机器人智能的逻辑是受到 James Bowman 的文章《在 Go 中使用机器学习进行网页的语义分析》的启发（[`www.jamesbowman.me/post/semantic-analysis-of-webpages-with-machine-learning-in-go/`](http://www.jamesbowman.me/post/semantic-analysis-of-webpages-with-machine-learning-in-go/)）。

# 向客户端公开代理的信息

现在我们已经实现了聊天代理`AgentCase`，我们需要一种方法将 Case 的信息暴露给客户端，特别是其名称、标题和头像图像的路径。

我们创建一个新的 Rest API 端点`GetAgentInfoEndpoint`，以向客户端 Web 应用程序公开聊天代理的信息：

```go
func GetAgentInfoEndpoint(env *common.Env, chatbot bot.Bot) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

    m := make(map[string]string)
    m["AgentName"] = chatbot.Name()
    m["AgentTitle"] = chatbot.Title()
    m["AgentThumbImagePath"] = chatbot.ThumbnailPath()
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(m)
  })
```

请注意，在`GetAgentInfoEndpoint`函数的签名中，我们接受`env`对象和`chatbot`对象。请注意，`chatbot`是`bot.Bot`类型的接口类型，而不是`AgentCase`类型。这使我们能够轻松地在将来将另一个机器人（例如`AgentMolly`）替换为`AgentCase`。

我们简单地创建一个`map[string]string`类型的映射`m`，其中包含机器人的姓名、职称和头像路径。我们设置一个标头以指示服务器响应将以 JSON 格式返回。最后，我们使用`http.ResponseWriter` `w`编写 JSON 编码的`map`。

# 实现实时聊天的客户端功能

现在我们已经介绍了实现聊天机器人所需的服务器端功能，是时候从客户端 Web 应用程序的角度关注实时聊天功能了。

在`InitialPageLayoutControls`函数内，我们在顶部栏中的实时聊天图标上添加了一个`click`事件的`event`监听器：

```go
  liveChatIcon := env.Document.GetElementByID("liveChatIcon").(*dom.HTMLImageElement)
  liveChatIcon.AddEventListener("click", false, func(event dom.Event) {

    chatbox := env.Document.GetElementByID("chatbox")
    if chatbox != nil {
      return
    }
    go chat.StartLiveChat(env)
  })
```

如果实时聊天功能已经激活，则`chatbox` div 元素将已经存在，即它将是一个非 nil 值。在这种情况下，我们从函数中返回。

然而，在实时聊天功能尚未激活的情况下，我们将调用位于`chat`包中的`StartLiveChat`函数作为 goroutine，传入`env`对象。调用此函数将激活实时聊天功能。

# 创建实时聊天客户端

我们将使用`gopherjs/websocket/websocketjs`包来创建一个 WebSocket 连接，该连接将用于连接到 Web 服务器实例。

您可以使用以下`go get`命令安装此包：

```go
$ go get -u github.com/gopherjs/websocket
```

实时聊天功能的客户端实现可以在`client/chat/chat.go`源文件中找到。我们定义了类型为`websocketjs.WebSocket`的`ws`变量和类型为`map[string]string`的`agentInfo`变量：

```go
var ws *websocketjs.WebSocket
var agentInfo map[string]string
```

我们还声明了一个代表 Enter 键的键码的常量：

```go
const ENTERKEY int = 13
```

`GetAgentInfoRequest`函数用于从`/restapi/get-agent-info`端点获取代理信息：

```go
func GetAgentInfoRequest(agentInfoChannel chan map[string]string) {
  data, err := xhr.Send("GET", "/restapi/get-agent-info", nil)
  if err != nil {
    println("Encountered error: ", err)
  }
  var agentInfo map[string]string
  json.NewDecoder(strings.NewReader(string(data))).Decode(&agentInfo)
  agentInfoChannel <- agentInfo
}
```

一旦我们从服务器检索到 JSON 编码的数据，我们将其解码为`map[string]string`类型的`map`。然后我们通过通道`agentInfoChannel`发送`agentInfo map`。

`getServerPort`函数是一个辅助函数，用于获取服务器运行的端口：

```go
func getServerPort(env *common.Env) string {

  if env.Location.Port != "" {
    return env.Location.Port
  }

  if env.Location.Protocol == "https" {
    return "443"
  } else {
    return "80"
  }

}
```

此函数用于在`StartLiveChat`函数内构造`serverEndpoint`字符串变量，该变量表示我们将要建立 WebSocket 连接的服务器端点。

当用户点击顶部栏中的实时聊天图标时，`StartLiveChat`函数将作为 goroutine 被调用：

```go
func StartLiveChat(env *common.Env) {

  agentInfoChannel := make(chan map[string]string)
  go GetAgentInfoRequest(agentInfoChannel)
  agentInfo = <-agentInfoChannel
```

首先，我们通过调用`GetAgentInfoRequest`函数作为一个 goroutine 来获取代理的信息。代理的信息将作为`map[string]string`类型的映射通过`agentInfoChannel`通道发送。`agentInfo` `map`将被用作传递给`partials/chatbox_partial`模板以显示代理的详细信息（姓名、职称和头像）的数据对象。

然后，我们继续创建一个新的 WebSocket 连接并连接到服务器端点：

```go
  var err error
  serverEndpoint := "ws://" + env.Location.Hostname + ":" + getServerPort(env) + "/ws"
  ws, err = websocketjs.New(serverEndpoint)
  if err != nil {
    println("Encountered error when attempting to connect to the websocket: ", err)
  }
```

我们使用辅助函数`getServerPort`来获取服务器运行的端口。服务器端口值用于构造`serverEndpoint`字符串变量，该变量表示我们将连接到的服务器端点的 WebSocket 地址。

我们使用`env.Document`对象的`GetElementByID`方法来获取聊天容器`div`元素，通过提供 ID 为`"chatboxContainer"`。我们还添加了 CSS 动画样式，使聊天框容器在聊天机器人可以回答问题时产生戏剧性的脉动效果：

```go
  chatContainer := env.Document.GetElementByID("chatboxContainer").(*dom.HTMLDivElement)
  chatContainer.SetClass("containerPulse")

  env.TemplateSet.Render("partials/chatbox_partial", &isokit.RenderParams{Data: agentInfo, Disposition: isokit.PlacementReplaceInnerContents, Element: chatContainer})
```

我们调用模板集对象的`Render`方法，渲染`"partials/chatbox_partial"`模板并提供模板渲染参数。我们指定要提供给模板的数据对象将是`agentInfo`映射。我们指定渲染的方式应该是用渲染模板输出替换相关元素的内部 HTML 内容。最后，我们指定要渲染到的相关元素是`chatContainer`元素。

当实时聊天功能可用且与服务器的 WebSocket 连接已连接时，聊天框标题栏，包含聊天框标题的条纹，`chatboxHeaderBar`，将被着绿色。如果 WebSocket 连接已断开或出现错误，则条纹将被着红色。默认情况下，当我们将`chatboxHeaderBar`的默认 CSS 类设置为`"chatboxHeader"`时，条纹将被着绿色：

```go
  chatboxHeaderBar := env.Document.GetElementByID("chatboxHeaderBar").(*dom.HTMLDivElement)
  chatboxHeaderBar.SetClass("chatboxHeader")
```

# 初始化事件监听器

最后，我们调用`InitializeChatEventHandlers`函数，传入`env`对象，初始化实时聊天功能的事件处理程序：

```go
  InitializeChatEventHandlers(env)
```

`InitializeChatEventHandlers`函数负责设置实时聊天功能所需的所有事件监听器。有两个需要用户交互的控件。第一个是消息`input`字段，用户通过按下 Enter 键输入并发送问题。第二个是关闭按钮，即 X，位于聊天框右上角，用于关闭实时聊天功能。

为了处理用户与消息`input`字段的交互，我们设置了`keypress`事件监听器，它将检测消息`input`文本字段内的`keypress`事件：

```go
func InitializeChatEventHandlers(env *common.Env) {

  msgInput := env.Document.GetElementByID("chatboxInputField").(*dom.HTMLInputElement)
  msgInput.AddEventListener("keypress", false, func(event dom.Event) {
    if event.Underlying().Get("keyCode").Int() == ENTERKEY {
      event.PreventDefault()
      go ChatSendMessage(env, msgInput.Value)
      msgInput.Value = ""
    }

  })
```

我们通过在`env.Document`对象上调用`GetElementByID`方法获取`input`消息文本字段元素。然后我们为该元素附加了一个`keypress`事件监听器函数。如果用户按下的键是 Enter 键，我们将阻止`keypress`事件的默认行为，并调用`ChatSendMessage`函数，作为一个 goroutine，传入`env`对象和`msgInput`元素的`Value`属性。最后，我们通过将消息输入字段的`Value`属性设置为空字符串值来清除文本。

# 关闭聊天控件

为了处理用户点击 X 控件关闭实时聊天功能时的交互，我们设置了一个事件监听器来处理关闭控件的点击事件：

```go
  closeControl := env.Document.GetElementByID("chatboxCloseControl").(*dom.HTMLDivElement)
  closeControl.AddEventListener("click", false, func(event dom.Event) {
    CloseChat(env)
  })
```

我们通过在`env.Document`对象上调用`GetElementByID`方法，指定 ID 为`"chatboxCloseControl"`，获取代表关闭控件的`div`元素。我们在`click`事件上为关闭控件附加一个事件监听器，该事件监听器将调用`CloseChat`函数。

# 为 WebSocket 对象设置事件监听器

现在我们已经为用户交互设置了事件监听器，我们必须在 WebSocket 对象`ws`上设置事件监听器。我们首先在`message`事件上添加一个事件监听器：

```go
  ws.AddEventListener("message", false, func(ev *js.Object) {
    go HandleOnMessage(env, ev)
  })
```

当 WebSocket 连接上有新消息时，将触发`message`事件监听器。这表明代理向用户发送消息。在这种情况下，我们调用`HandleOnMessage`函数，将`env`对象和事件对象`ev`传递给函数。

WebSocket 对象中我们需要监听的另一个事件是`close`事件。这个事件可能会在正常操作场景下触发，比如用户使用关闭控件关闭实时聊天功能。这个事件也可能在异常操作场景下触发，比如 Web 服务器实例突然宕机，中断 WebSocket 连接。我们的代码必须足够智能，只在异常连接关闭的情况下触发：

```go
  ws.AddEventListener("close", false, func(ev *js.Object) {6

    chatboxContainer := env.Document.GetElementByID("chatboxContainer").(*dom.HTMLDivElement)
    if len(chatboxContainer.ChildNodes()) > 0 {
      go HandleDisconnection(env)
    }
  })
```

我们首先获取聊天框容器`div`元素。如果聊天框容器中的子节点数量大于零，则意味着在用户使用实时聊天功能时连接异常关闭，我们必须调用`HandleDisconnection`函数，作为一个 goroutine，将`env`对象传递给该函数。

可能会有一些情况，关闭事件不会触发，比如当我们失去互联网连接时。WebSocket 连接正在通信的 TCP 连接可能仍然被视为活动的，即使互联网连接已经断开。为了使我们的实时聊天功能能够处理这种情况，我们需要监听`env.Window`对象的`offline`事件，当网络连接丢失时会触发该事件：

```go
  env.Window.AddEventListener("offline", false, func(event dom.Event) {
    go HandleDisconnection(env)
  })

}
```

我们执行与之前处理此事件相同的操作。我们调用`HandleDisconnection`函数，作为一个 goroutine，将`env`对象传递给该函数。请注意，最后的闭括号`}`表示`InitializeChatEventHandlers`函数的结束。

现在我们已经为实时聊天功能设置了所有必要的事件监听器，是时候检查刚刚设置的事件监听器调用的每个函数了。

在用户在消息`input`文本字段中按下 Enter 键后，将调用`ChatSendMessage`函数：

```go
func ChatSendMessage(env *common.Env, message string) {
  ws.Send([]byte(message))
  UpdateChatBox(env, message, "Me")
}
```

我们调用 WebSocket 对象`ws`的`Send`方法，将用户的问题发送到 Web 服务器。然后调用`UpdateChatBox`函数将用户的消息呈现到聊天框的对话容器中。我们将`env`对象、用户编写的`message`和`sender`字符串作为输入值传递给`UpdateChatBox`函数。`sender`字符串是发送消息的人；在这种情况下，由于用户发送了消息，`sender`字符串将是`"Me"`。`sender`字符串帮助用户区分用户发送的消息和聊天机器人回复的消息。

`UpdateChatBox`函数用于更新聊天框对话容器区域：

```go
func UpdateChatBox(env *common.Env, message string, sender string) {

  m := make(map[string]string)
  m["Name"] = sender
  m["Message"] = message
  conversationContainer := env.Document.GetElementByID("chatboxConversationContainer").(*dom.HTMLDivElement)
  env.TemplateSet.Render("partials/livechatmsg_partial", &isokit.RenderParams{Data: m, Disposition: isokit.PlacementAppendTo, Element: conversationContainer})
  scrollHeight := conversationContainer.Underlying().Get("scrollHeight")
  conversationContainer.Underlying().Set("scrollTop", scrollHeight)
}
```

我们创建一个新的`map[string]string`类型的映射，它将被用作传递给`partials/livechatmsg_partial`模板的数据对象。该映射包括一个带有键`"Name"`的条目，表示`sender`，以及一个带有键`"Message"`的条目，表示`message`。`"Name"`和`"Message"`的值都将显示在聊天框的对话容器区域中。

我们通过调用`env.Document`对象的`GetElementByID`方法并指定`id`值为`"chatboxConversationContainer"`来获取`conversationContainer`元素。

我们调用`env.TemplateSet`对象的`Render`方法，并指定要渲染`partials/livechatmsg_partial`模板。在渲染参数（`RenderParams`）对象中，我们将`Data`字段设置为`map` `m`。我们将`Disposition`字段设置为`isokit.PlacementAppendTo`，以指定该操作将是一个*append to*操作，相对于关联元素。我们将`Element`字段设置为`conversationContainer`，因为这是将聊天消息追加到的元素。

函数中的最后两行将在渲染新消息时自动将`conversationContainer`滚动到底部，以便始终显示最近的消息给用户。

除了`ChatSendMessage`函数之外，`UpdateChatBox`函数的另一个使用者是`HandleOnMessage`函数：

```go
func HandleOnMessage(env *common.Env, ev *js.Object) {

  response := ev.Get("data").String()
  UpdateChatBox(env, response, agentInfo["AgentName"])
}
```

请记住，此功能将在从 WebSocket 连接触发`"message"`事件时调用。我们通过获取`event`对象的`data`属性的字符串值，从通过 WebSocket 连接传递的聊天机器人获取响应。然后我们调用`UpdateChatBox`函数，传入`env`对象、`response`字符串和`sender`字符串`agentInfo["AgentName"]`。请注意，我们已经传递了代理的名称，即使用`"AgentName"`键获取的`agentInfo` `map`中的值，作为`sender`字符串。

`CloseChat`函数用于关闭网络套接字连接并从用户界面中解除聊天框：

```go
func CloseChat(env *common.Env) {
  ws.Close()
  chatboxContainer := env.Document.GetElementByID("chatboxContainer").(*dom.HTMLDivElement)
  chatboxContainer.RemoveChild(chatboxContainer.ChildNodes()[0])

}
```

我们首先在 WebSocket 对象上调用`Close`方法。我们获取`chatboxContainer`元素并移除其第一个子节点，这将随后移除第一个子节点的所有子节点。

请记住，此功能将在用户点击聊天框中的 X 控件时调用，或者在打开实时聊天功能时遇到异常的 WebSocket 连接终止的情况下调用。

# 处理断开连接事件

这将引导我们到最后一个函数`HandleDisconnection`，它在异常的 WebSocket 连接关闭事件或互联网连接断开时被调用，即当`wenv.Window`对象触发`offline`事件时：

```go
func HandleDisconnection(env *common.Env) {

  chatContainer := env.Document.GetElementByID("chatboxContainer").(*dom.HTMLDivElement)
  chatContainer.SetClass("")

  chatboxHeaderBar := env.Document.GetElementByID("chatboxHeaderBar").(*dom.HTMLDivElement)
  chatboxHeaderBar.SetClass("chatboxHeader disconnected")

  chatboxTitleDiv := env.Document.GetElementByID("chatboxTitle").(*dom.HTMLDivElement)
  if chatboxTitleDiv != nil {
    titleSpan := chatboxTitleDiv.ChildNodes()[0].(*dom.HTMLSpanElement)
    if titleSpan != nil {
      var countdown uint64 = 6
      tickerForCountdown := time.NewTicker(1 * time.Second)
      timerToCloseChat := time.NewTimer(6 * time.Second)
      go func() {
        for _ = range tickerForCountdown.C {
          atomic.AddUint64(&countdown, ^uint64(0))
          safeCountdownValue := atomic.LoadUint64(&countdown)
          titleSpan.SetInnerHTML("Disconnected! - Closing LiveChat in " + strconv.FormatUint(safeCountdownValue, 10) + " seconds.")
        }
      }()
      go func() {
        <-timerToCloseChat.C
        tickerForCountdown.Stop()
        CloseChat(env)
      }()
    }
  }
}
```

我们首先使用`SetClass`方法将`chatContainer`的 CSS`classname`值设置为空字符串，以禁用`chatContainer`元素的脉动效果，以指示连接已中断。

然后，我们通过使用`SetClass`方法将`chatboxHeaderBar`元素的 CSS`classname`值设置为`"chatboxHeader disconnected"`，将`chatboxHeaderBar`的背景颜色更改为红色。

剩下的代码将向用户显示一条消息，指示连接已断开，并且实时聊天功能将自动启动倒计时。`chatboxHeaderBar`将按秒显示倒计时 5-4-3-2-1，当实时聊天功能关闭时。我们使用两个 goroutine，一个用于倒计时计时器，另一个用于倒计时计时器。当倒计时计时器到期时，表示倒计时结束，我们调用`CloseChat`函数，传入`env`对象来关闭实时聊天功能。

# 与代理人交谈

此时，我们已经实现了服务器端和客户端功能，实现了实时聊天功能，展示了实时 Web 应用程序功能。现在是时候开始与聊天代理进行对话（问题和答案会话）了。

在网站顶部栏找到实时聊天图标后，我们会在网页的右下角看到聊天框。以下截图显示了带有聊天代理问候语的聊天框：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/156fc180-8401-4377-a6a2-e2e39b2bf9fe.png)

图 8.3：聊天框打开并显示聊天代理的问候

我们可以使用聊天框右上角的 X 控件关闭实时聊天框。我们可以通过再次点击顶部栏中的实时聊天图标来重新激活实时聊天功能。我们可以提供一个陈述，例如告诉我更多关于同构 Go，而不是向聊天代理提问，就像我们在以下截图中所示的那样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/c3eafb6a-f985-4e2e-8f24-58389c7c9db6.png)

图 8.4：即使不是问题，聊天代理也能理解信息请求

人类用户和聊天代理之间的问答会话可以持续多长时间，如下一张截图所示。这也许是聊天代理的最大优势——在与人类打交道时具有无限的耐心。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/bd3b7d18-d40e-4fb8-990c-53fe05c5a7dc.png)

图 8.5：问题和答案会话可以持续多长时间取决于人类的意愿。

我们实现的聊天代理具有极其狭窄和有限的智能范围。当人类用户提出超出其智能范围的问题时，聊天代理将承认自己不知道答案，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/0ca621a3-a61d-4ba4-8d13-14f02f9e92f4.png)

图 8.6：聊天代理对超出其智能范围的问题没有答案

一些人类用户可能对聊天代理粗鲁。这是聊天代理所服务的公共角色所带来的。如果我们调整语料库得当，我们的聊天代理可以展示一个风趣的回复。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/daf82631-447d-4a5b-acc9-8dbc20cb0fe1.png)

图 8.7：聊天代理展示一个风趣的回复

正如前面所述，我们已经有策略地将聊天框容器放在网页布局的主要内容区域之外。这样做后，聊天框和与聊天代理的对话可以在我们自由导航 IGWEB 的链接时继续，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/08c6306f-7edc-45b9-8f53-b000a8cb82d0.png)

图 8.8：用户在 IGWEB 中导航时，聊天对话将被保留

例如，如下所示，即使在单击咖啡杯产品图像以进入产品详细页面后，聊天对话仍在继续：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f18de492-5396-4668-855d-b0735549ab42.png)

图 8.9：用户访问咖啡杯产品详细页面时，聊天对话已保留

实时网络应用取决于对互联网的持续连接。让我们看看实时聊天功能如何优雅地处理断开互联网连接的情况，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/073b2350-2bbb-4a2e-a245-c88950a9018a.png)

图 8.10：关闭互联网连接

一旦网络连接被关闭，我们立即在聊天框的标题栏中得到断开连接的通知，如*图 8.11*所示。聊天框标题栏的背景颜色变为红色，并启动关闭实时聊天功能的倒计时。倒计时完成后，实时聊天功能将自动关闭：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/5caf4ba7-a60e-44bb-9380-3e142e10bc86.png)

图 8.11：关闭实时聊天功能的倒计时出现在聊天框的标题栏中

在实现实时网络应用功能时，始终重要考虑持久 WebSocket 连接中断的情况。当 Web 客户端和 Web 服务器之间的持久连接中断时，通过优雅地关闭实时聊天，我们有一种方式向用户提供*提示*，让用户与聊天代理解除联系。

# 总结

在本章中，我们以 IGWEB 的实时网络应用功能的形式实现了实时聊天功能。您学会了如何使用 WebSocket 在 Web 服务器和 Web 客户端之间建立持久连接。在服务器端，我们向您介绍了 Gorilla 工具包项目中的`websocket`包。在客户端，我们向您介绍了 GopherJS 项目中的`gopherjs/websocket/websocketjs`包。

我们创建了一个简单的初级聊天机器人，实时回答用户提出的问题，人类和机器人之间的对话通过建立的 WebSocket 连接进行中继。由于实时网络应用功能取决于持续连接，我们还添加了代码，以便在互联网连接中断的情况下自动关闭实时聊天功能。

我们使用`nlp`包来实现初级聊天代理的大脑，以便它可以回答一些与同构 Go 相关的问题。我们使我们的聊天代理解决方案可扩展，未来可以通过定义`Bot`接口来添加具有不同智能的新机器人。

在第九章中，*Cogs– 可重复使用的组件*，我们将探讨如何在整个 IGWEB 中实现可重复使用的接口小部件。可重复使用的组件提供了促进更大重用性的手段，它们可以以即插即用的方式使用。正如您将了解的那样，齿轮也是高效的，利用虚拟 DOM 根据需要重新渲染其内容。


# 第九章：Cogs - 可重用组件

在本书的前五章中，我们专注于为 IGWEB 上的特定网页或特定功能开发功能，例如我们在上一章中实现的实时聊天功能。到目前为止，我们所做的解决方案都为特定的个人目的服务。并没有考虑为特定的用户界面功能促进代码重用，因为我们没有需要创建多个实例。

可重用组件是用户界面小部件，提供了促进更大重用性的手段。它们可以以即插即用的方式使用，因为每个组件都是一个独立的用户界面小部件，包含自己的一组 Go 源文件和静态资产，例如 Go 模板文件，以及 CSS 和 JavaScript 源文件。

在本章中，我们将专注于创建可在同构 Go web 应用程序中使用的**cogs**——可重用组件。术语`cog`代表**Go 中的组件对象**。Cogs 是可重用的用户界面小部件，可以纯粹由 Go 实现（**纯齿轮**），也可以使用 Go 和 JavaScript 实现（**混合齿轮**）。

我们可以创建多个`cog`的实例，并通过提供输入参数（以键值对的形式）给`cog`，即**props**，来控制 cog 的行为。当对 props 进行后续更改时，`cog`是**响应式**的，这意味着它可以自动重新渲染自己。因此，cogs 具有根据其 props 的更改而改变外观的能力。

也许，cogs 最吸引人的特点是它们是可以立即重用的。Cogs 被实现为独立的 Go 包，包含一个或多个 Go 源文件以及 cog 实现所需的任何静态资产。

在本章中，我们将涵盖以下主题：

+   基本的`cog`概念

+   实现纯齿轮

+   实现混合齿轮

# 基本 cog 概念

**Cogs**（Go 中的组件对象）是在 Go 中实现的可重用组件。cogs 背后的指导理念是允许开发人员以成熟的方式在前端创建可重用组件。Cogs 是自包含的，定义为自己的 Go 包，这使得重用和维护它们变得容易。由于它们的自包含性质，cogs 可以用于创建可组合的用户界面。

Cogs 遵循关注点的清晰分离，其中`cog`的表示层使用一个或多个 Go 模板实现，`cog`的控制器逻辑在一个或多个 Go 源文件中实现，这些文件包含在一个 Go 包中。这些 Go 源文件可能导入标准库或第三方库的 Go 包。当我们在本章的*实现纯齿轮*部分实现时间之前的齿轮时，我们将看到一个例子。

Cogs 也可能有与之相关的 CSS 样式表和 JavaScript 代码，允许`cog`开发者/维护者根据需要利用预构建的 JavaScript 解决方案，而不是直接将 JavaScript 小部件移植到 Go。这使得 cogs 与现有的 JavaScript 解决方案具有互操作性，并防止开发人员重复发明轮子，从而节省宝贵的时间。例如，Pikaday（[`github.com/dbushell/Pikaday`](https://github.com/dbushell/Pikaday)）是一个成熟的日历日期选择器 JavaScript 小部件。在本章的*实现混合齿轮*部分，我们将学习如何实现一个使用 Pikaday JavaScript 小部件提供的功能的日期选择器`cog`。使用日期选择器`cog`的 Go 开发人员不需要了解 JavaScript，并且可以仅使用他们对 Go 的知识来使用它。

每个`cog`都带有一个**虚拟 DOM 树**，这是其实际 DOM 树的内存表示。操作`cog`的内存虚拟 DOM 树要比操作实际 DOM 树本身更有效率。*图 9.1*是一个 Venn 图，描述了`cog`的虚拟 DOM 树、两个树之间的差异以及实际 DOM 树：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/53478aff-9055-402c-8a14-4400ab176f58.png)

图 9.1：显示虚拟 DOM、差异和实际 DOM 的 Venn 图

当对`cog`的属性（*props*）进行更改时，`cog`的渲染引擎将利用其虚拟 DOM 树来确定更改，然后将更改与实际 DOM 树进行协调。这允许`cog`是*reactive*，意味着`cog`可以在其 props 更新时自动重新渲染自身。通过这种方式，cogs 减少了更新用户界面时涉及的复杂性。

# UX 工具包

UX 工具包提供了在`cog`包中实现 cogs 的功能，可以使用以下`go get`命令进行安装：

```go
$ go get -u github.com/uxtoolkit/cog
```

所有 cogs 必须实现`Cog`接口：

```go
type Cog interface {
  Render() error
  Start() error
}
```

`Render`方法负责在网页上渲染`cog`。如果在渲染过程中出现任何错误，该方法将返回一个`error`对象。

`Start`方法负责激活`cog`。如果`cog`无法启动，该方法将返回一个`error`对象。

`cog`包含两个重要的导出变量，`ReactivityEnabled`和`VDOMEnabled`。这两个导出变量都是`bool`类型，默认情况下都设置为`true`。

当变量`ReactivityEnabled`设置为`true`时，cogs 将在其 props 更改时重新渲染。如果`ReactivityEnabled`设置为`false`，则必须显式调用`cog`的`Render`方法来重新渲染`cog`。

当变量`VDOMEnabled`设置为`true`时，cogs 将利用`cog`的虚拟 DOM 树进行渲染。如果`VDOMEnabled`设置为`false`，则将通过替换内部 HTML 操作使用实际 DOM 树来渲染`cog`。这可能是一个昂贵的操作，可以通过利用`cog`的虚拟 DOM 树来避免。

`UXCog`类型实现了`Cog`接口的`Render`方法。以下是`UXCog struct`的样子：

```go
type UXCog struct {
  Cog
  cogType reflect.Type
  cogPrefixName string
  cogPackagePath string
  cogTemplatePath string
  templateSet *isokit.TemplateSet
  Props map[string]interface{}
  element *dom.Element
  id string
  hasBeenRendered bool
  parseTree *reconcile.ParseTree
  cleanupFunc func()
}
```

`UXCog`类型提供了使 cogs 工作的基本功能。这意味着为了实现我们自己的 cogs，我们必须在我们创建的所有 cogs 的类型定义中嵌入`UXCog`。`UXCog`类型的以下方法（为简洁起见，仅呈现方法签名）对我们来说特别重要：

```go
func (u *UXCog) ID() string

func (u *UXCog) SetID(id string) 

func (u *UXCog) CogInit(ts *isokit.TemplateSet)

func (u *UXCog) SetCogType(cogType reflect.Type)

func (u *UXCog) SetProp(key string, value interface{})

func (u *UXCog) Render() error
```

`ID`方法是一个 getter 方法，返回`cog`在 DOM 中的`div`容器的 ID。`cog`的`div`容器被称为其**挂载点**。

`SetID`方法是一个 setter 方法，用于设置 DOM 中`cog`的`div`容器的 ID。

`CogInit`方法用于将`cog`与应用程序的`TemplateSet`对象关联起来。该方法有两个重要目的。首先，该方法用于在服务器端注册`cog`，以便所有给定`cog`的模板都包含在由`isokit`内置的静态资产捆绑系统生成的模板包中。其次，在客户端调用`cog`的`CogInit`方法允许`cog`访问客户端应用程序的`TemplateSet`对象，从而允许`cog`在网页上进行渲染。

`SetCogType`方法允许我们通过对新实例化的`cog`执行运行时反射来动态设置`cog`的类型。这为 isokit 的静态资产捆绑系统提供了所需的钩子，以捆绑与给定`cog`相关的模板文件、CSS 源文件和 JavaScript 源文件。

`SetProp` 方法用于在 cog 的 `Props` 映射中设置键值对，该映射的类型为 `map[string]interface{}`。映射的 `key` 表示 prop 的名称，值表示 prop 的值。

`Render` 方法负责将 `cog` 渲染到 DOM。如果在渲染后对 `cog` 进行更改（其 prop 值已更新），则将重新渲染 `cog`。

您可以访问 UX 工具包网站，了解有关 cogs 的更多信息：[`uxtoolkit.io`](http://uxtoolkit.io)。

现在我们已经了解了 `UXCog` 类型，是时候来检查 `cog` 的解剖学了。

# cog 的解剖学

对于 IGWEB 项目，我们将在 `$IGWEB_APP_ROOT/shared/cogs` 文件夹中创建 cogs。当您阅读本节时，您可以查看 `$IGWEB_APP_ROOT/shared/cogs/timeago` 文件夹中找到的 time ago `cog` 的实现，以查看所述概念的具体实现。

仅用于说明的目的，我们将带您了解创建一个名为 `widget` 的简单 `cog` 的过程。

`widget` 文件夹中包含的小部件 `cog` 的项目结构以以下方式组织：

```go
  ⁃ widget
    ⁃ widget.go
    ⁃ templates
    ⁃ widget.tmpl
```

`widget.go` 源文件将包含小部件 `cog` 的实现。

`templates` 文件夹包含用于实现 `cog` 的模板源文件。如果要在网页上呈现 `cog`，至少必须存在一个模板源文件。模板源文件的名称必须与 `cog` 的包名称匹配。例如，对于 `cog` 包 `widget`，模板源文件的名称必须是 `widget.tmpl`。

在命名包名称和源文件时，cogs 遵循 *约定优于配置* 策略。由于我们选择了名称 `widget`，因此我们必须在 `widget.go` 源文件中也声明一个名为 `widget` 的 Go 包：

```go
package widget
```

所有 cogs 都需要在其导入分组中包含 `errors` 包、`reflect` 包和 `cog` 包：

```go
import (
  "errors"
  "reflect"
  "github.com/uxtoolkit/cog"
)
```

我们必须声明一个未导出的、包范围的变量，名为 `cogType`：

```go
var cogType reflect.Type
```

此变量表示 `cog` 的类型。我们在 `cog` 包的 `init` 函数中调用 `reflect` 包中的 `TypeOf` 函数，传入一个新创建的 `cog` 实例，以动态设置 `cog` 的类型：

```go
func init() {
  cogType = reflect.TypeOf(Widget{})
}
```

这为 isokit 的静态捆绑系统提供了一个钩子，以了解在哪里获取所需的静态资源来使 `cog` 函数正常运行。

`cog` 实现了特定类型。对于小部件，我们实现了 `Widget` 类型。这是 `Widget struct`：

```go
type Widget struct {
  cog.UXCog
}
```

我们必须将 `cog.UXCog` 类型嵌入到 `cog` 中，以从 `cog.UxCog` 类型中获取所需的所有功能，以实现 `cog`。

`struct` 可能包含其他字段定义，这些字段定义是实现 `cog` 所需的，具体取决于 `cog` 的用途。

每个 `cog` 实现都应包含一个构造函数：

```go
func NewWidget() *Widget {
  w := &Widget{}
  w.SetCogType(cogType)
  return f
}
```

与任何典型的构造函数一样，目的是创建 `Widget` 的新实例。

cog 的构造函数必须包含调用 `SetCogType` 方法的行（以粗体显示）。这是 isokit 的自动静态资源捆绑系统用作钩子，以捆绑 `cog` 所需的静态资源。

可以设置 `Widget` 类型的其他字段以初始化 `cog`，这取决于 `cog` 的实现。

为了实现 `Cog` 接口的实现，所有 cogs 必须实现一个 `Start` 方法：

```go
func (w *Widget) Start() error {

  var allRequiredConditionsHaveBeenMet bool = true
```

`Start` 方法负责激活 `cog`，包括将 `cog` 初始渲染到网页上。如果 `cog` 启动失败，`Start` 方法将返回一个 `error` 对象，否则将返回一个 `nil` 值。

仅用于说明，我们定义了一个包含名为 `allRequiredConditionsHaveBeenMet` 的布尔变量的 `if` 条件块：

```go
  if allRequiredConditionsHaveBeenMet == false {
    return errors.New("Failed to meet all requirements, cog failed to start!")
  }
```

如果满足了启动`cog`的所有条件，这个变量将等于`true`。否则，它将等于`false`。如果它是`false`，那么我们将返回一个新的`error`对象，表示`cog`由于未满足所有要求而无法启动。

我们可以通过调用`SetProp`方法在 cog 的`Props`映射中设置键值对：

```go
  w.SetProp("foo", "bar")
```

在这种情况下，我们已将名为`foo`的 prop 设置为值`bar`。`Props`映射将自动用作传入 cog 模板的数据对象。这意味着`Props`映射中定义的所有 prop 都可以被 cog 的模板访问。

按照惯例，cog 的模板源文件名称必须命名为`widget.tmpl`，以匹配 cog 的包名称`widget`，并且模板文件应该位于 cog 的文件夹`widget`中的`templates`文件夹中。

让我们快速看一下`widget.tmpl`源文件可能是什么样子：

```go
<p>Value of Foo is: {{.foo}}</p>
```

请注意，我们能够打印出模板中具有键`foo`的 prop 的值。

让我们回到 widget cog 的`Start`方法。我们调用 cog 的`Render`方法来在 web 浏览器中渲染`cog`：

```go
  err := w.Render()
  if err != nil {
    return err
  }
```

如果在渲染`cog`时遇到错误，`Render`方法将返回一个`error`对象，否则将返回一个值为`nil`，表示`cog`已成功渲染。

如果`cog`成功渲染，cog 的`Start`方法会返回一个值为`nil`，表示`cog`已成功启动：

```go
return nil
```

为了将我们的`cog`渲染到真实的 DOM 中，我们需要一个地方来渲染`cog`。包含`cog`渲染内容的`div`容器被称为其**挂载点**。挂载点是`cog`在 DOM 中渲染的位置。要在主页上渲染 widget `cog`，我们需要将以下标记添加到主页的内容模板中：

```go
<div data-component="cog" id="widgetContainer"></div>
```

通过将`data-component`属性设置为`"cog"`，我们表明`div`元素将用作 cog 的挂载点，并且 cog 的渲染内容将包含在此元素内。

在客户端应用程序中，widget `cog`可以这样实例化：

```go
w := widget.NewWidget()
w.CogInit(env.TemplateSet)
w.SetID("widgetContainer")
w.Start()
w.SetProp("foo", "bar2")
```

我们创建一个新的`Widget`实例，并将其分配给变量`w`。我们必须调用`cog`的`CogInit`方法，将应用程序的`TemplateSet`对象与`cog`关联起来。`cog`利用`TemplateSet`来获取其关联的模板，这些模板是渲染`cog`所需的。我们调用 cog 的`SetID`方法，将`id`传递给充当 cog 挂载点的`div`元素。我们调用 cog 的`Start`方法来激活`cog`。由于`Start`方法调用了 cog 的`Render`方法，因此 cog 将在指定的挂载点`div`元素中渲染，即`"widgetContainer"`的 id。最后，当我们调用`SetProp`方法并将`"foo"` prop 的值更改为`"bar2"`时，`cog`将自动重新渲染。

现在我们已经检查了`cog`的基本结构，让我们考虑如何使用虚拟 DOM 来渲染 cog。

# 虚拟 DOM 树

每个`cog`实例都有一个与之关联的虚拟 DOM 树。这个虚拟 DOM 树是由 cog 的`div`容器的所有子元素组成的解析树。

*图 9.2*是一个流程图，描述了将`cog`渲染和重新渲染（通过协调应用）到 DOM 的过程：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/d0aea435-af93-438d-9ce3-b88c23d6edd5.png)

图 9.2：描述了渲染和重新渲染 cog 的流程图

当`cog`首次在 DOM 中渲染时，会执行替换内部 HTML 操作。在 DOM 中替换元素的内部 HTML 内容是一个昂贵的操作。因此，在`cog`的后续渲染中不会执行此操作。

齿轮的`Render`方法的所有后续调用将利用齿轮的虚拟 DOM 树。齿轮的虚拟 DOM 树用于跟踪齿轮当前虚拟 DOM 树与齿轮新虚拟 DOM 树之间的变化。当齿轮的 prop 值已更新时，`cog`将有一个新的虚拟 DOM 树与其当前虚拟 DOM 树进行比较。

让我们考虑一个小部件齿轮的示例场景。调用小部件齿轮的`Start`方法将执行`cog`的初始渲染（因为`Start`方法内部调用了`Render`方法）。`cog`将具有一个虚拟 DOM 树，该树将是包含`cog`渲染内容的`div`容器的解析树。如果我们通过调用`cog`的`SetProp`方法更新了`"foo"`prop（该 prop 在`cog`的模板中呈现），那么将自动调用`Render`方法，因为`cog`是响应式的。在对`cog`执行后续渲染操作时，齿轮的当前虚拟 DOM 树将与齿轮的新虚拟 DOM 树（更新齿轮 prop 后创建的虚拟 DOM 树）进行差异比较。

如果当前虚拟 DOM 树和新虚拟 DOM 树之间没有变化，则无需执行任何操作。但是，如果当前虚拟 DOM 树和新虚拟 DOM 树之间存在差异，则必须将构成差异的更改应用于实际的 DOM。应用这些更改的过程称为**协调**。执行协调允许我们避免执行昂贵的替换内部 HTML 操作。成功应用协调后，齿轮的新虚拟 DOM 树将被视为齿轮的当前虚拟 DOM 树，以准备`cog`进行下一个渲染周期：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/f1b661e1-dbf9-40f0-a649-2349e36cf1c2.png)

图 9.3：齿轮的现有虚拟 DOM 树（左）和齿轮的新虚拟 DOM 树（右）

*图 9.3*在左侧描述了齿轮的现有虚拟 DOM 树，右侧描述了齿轮的新虚拟 DOM 树。在对两个虚拟 DOM 树（新的和现有的）进行`diff`操作后，确定右侧的`div`元素（包含`ul`元素）及其子元素已更改，并且协调操作将仅更新实际 DOM 中的`div`元素及其子元素。

# 齿轮的生命周期

*图 9.4*描述了`cog`的生命周期，该生命周期始于服务器端，在那里我们首先注册`cog`。必须在服务器端注册`cog`的类型，以便`cog`的关联模板以及其他静态资产可以自动捆绑并提供给客户端应用程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/39a0e440-a9ed-406b-a79c-9aa495618c26.png)

图 9.4：齿轮的生命周期

`cog`生命周期中的后续步骤发生在客户端。我们通过引入一个`div`元素，其 data-component 属性等于`"cog"`，来声明`cog`的挂载点，以指示该`div`元素是`cog`的挂载点。

下一步是通过调用其构造函数创建`cog`的新实例。我们通过调用其`CogInit`方法并传递客户端应用程序的`TemplateSet`对象来初始化`cog`。初始化`cog`还包括通过调用其`SetID`方法将挂载点与`cog`关联起来（以便`cog`知道在哪里进行渲染）。`Cog`初始化还包括在调用`Start`方法之前通过调用其`SetProp`方法在`cog`的`Props map`中设置 prop。

请注意，在调用齿轮的`Start`方法之前调用齿轮的`SetProp`方法将不会渲染`cog`。只有在通过调用其`Start`方法将`cog`呈现到挂载点后，才会在调用其`SetProp`方法后重新呈现`cog`。

调用`Cog`的`Start`方法将激活`cog`并将`cog`的内容呈现到指定的挂载点。

任何后续对齿轮的`SetProp`方法的调用都将导致齿轮的重新渲染。

当用户在网站上导航到不同的页面时，包含`cog`的容器将被移除，从而有效地销毁`cog`。用户可以指定一个清理函数，在销毁`cog`之前应该调用该函数。这可以帮助在`cog`被销毁之前以负责任的方式释放资源。我们将在本章后面看到实现清理函数的示例。

# 实现纯 cogs

现在我们对 cogs 有了基本的了解，是时候在实践中实现一些 cogs 了。尽管 cogs 在客户端操作，但重要的是要注意，服务器端应用程序需要通过注册来承认它们的存在。出于这个原因，cogs 的代码被策略性地放置在`shared/cogs`文件夹中。

纯 cogs 是专门用 Go 实现的。正如你将看到的，我们可以利用现有的 Go 包的功能来实现 cogs。

在`igweb.go`源文件的主函数中，我们调用`initailizeCogs`函数，传入应用程序的模板集：

```go
initializeCogs(env.TemplateSet)
```

`initializeCogs`函数负责初始化 Isomorphic Go web 应用程序中要使用的所有 cogs：

```go
func initializeCogs(ts *isokit.TemplateSet) {
  timeago.NewTimeAgo().CogInit(ts)
  liveclock.NewLiveClock().CogInit(ts)
  datepicker.NewDatePicker().CogInit(ts)
  carousel.NewCarousel().CogInit(ts)
  notify.NewNotify().CogInit(ts)
  isokit.BundleStaticAssets()
}
```

请注意，`initializeCogs`函数接受一个唯一的输入参数`ts`，即`TemplateSet`对象。我们调用齿轮的构造函数来创建一个新的`cog`实例，并立即调用`cog`的`CogInit`方法，将`TemplateSet`对象`ts`作为输入参数传递给该方法。这允许`cog`将其模板包含到应用程序的模板集中，以便随后要生成的模板包将包括与`cog`相关的模板。

我们调用`BundleStaticAssets`方法来生成每个`cog`所需的静态资源（CSS 和 JavaScript 源文件）。将生成两个文件。第一个文件是`cogimports.css`，其中包含所有 cogs 所需的 CSS 源代码，第二个文件是`cogimports.js`，其中包含所有 cogs 所需的 JavaScript 源代码。

# 时间差 cog

现在我们已经看到了如何在服务器端初始化 cogs，是时候来看看制作`cog`需要做些什么了。我们将从制作一个非常简单的`cog`开始，即时间差`cog`，它以人类可理解的格式显示时间。

是时候重新查看关于页面上的 Gopher 简介了。在第三章中的*自定义模板函数*部分，*Go on the Front-End with GopherJS*，我们学习了如何使用自定义模板函数以 Ruby 格式显示 Gopher 的开始日期时间。

我们将进一步展示开始日期时间的人类可理解格式，通过实现一个时间差`cog`。*图 9.5*是一个示例，显示了 Molly 在默认 Go 格式、Ruby 格式和人类可理解格式的开始日期：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/2f766aa0-f732-486e-bb0f-b66f8b102f43.png)

图 9.5：描绘时间差 cog 的插图，最后一行显示了人类可读格式的时间

Molly 于 2017 年 5 月 24 日加入了 IGWEB 团队，以人类可读的格式，即 6 个月前（在撰写时的当前时间）。

在`about_content.tmpl`模板源文件中，我们为时间差`cog`引入了一个`div`容器：

```go
<h1>About</h1>

<div id="gopherTeamContainer">
  {{range .Gophers}}

    <div class="gopherContainer">

      <div class="gopherImageContainer">
        <img height="270" src="img/{{.ImageURI}}">
      </div>

      <div class="gopherDetailsContainer">
          <div class="gopherName"><h3><b>{{.Name}}</b></h3></div>
          <div class="gopherTitle"><span>{{.Title}}</span></div> 
          <div class="gopherBiodata"><p>{{.Biodata}}</p></div>
          <div class="gopherStartTime">
            <p class="standardStartTime">{{.Name}} joined the IGWEB team on <span class="starttime">{{.StartTime}}.</p>
            <p class="rubyStartTime">That's <span class="starttime">{{.StartTime | rubyformat}}</span> in Ruby date format.</p>
            <div class="humanReadableGopherTime">That's
 <div id="Gopher-{{.Name}}" data-starttimeunix="{{.StartTime | unixformat}}" data-component="cog" class="humanReadableDate starttime"></div>
 in Human readable format.
 </div>
          </div>
      </div>
    </div>

  {{end}}
</div>
```

请注意，我们已经分配了名为`data-component`的属性，其值为`cog`。这是为了表明这个`div`容器将作为一个装载点，容纳`cog`的渲染内容。我们将容器的`id`属性设置为带有前缀`"Gopher-"`的 Gopher 的名字。

稍后您将看到，当我们实例化一个`cog`时，我们必须为`cog`的`div`容器提供一个 ID，以便`cog`实例知道它的挂载点是`cog`应该将其输出呈现到的位置。我们定义了另一个自定义数据属性`starttimeunix`，并将其设置为 Gopher 开始为 IGWEB 工作时的 Unix 时间戳值。

请记住，该值是通过调用模板操作获得的，该操作将`StartTime`属性通过管道传输到自定义模板函数`unixformat`中获得的值。

`unixformat`自定义模板函数是`shared/templatefuncs/funcs.go`源文件中定义的`UnixTime`函数的别名：

```go
func UnixTime(t time.Time) string {
  return strconv.FormatInt(t.Unix(), 10)
}
```

此函数将返回给定`Time`实例的 Unix 格式的时间作为`string`值。

回到`about_content.tmpl`源文件，注意提供给`div`容器的`humanReadableDate` CSS `className`。我们稍后将使用这个 CSS `className`来获取关于页面上所有`timeago` `cog`的`div`容器。

现在我们已经看到了如何在关于页面上声明`cog`的`div`容器，让我们来看看如何实现时间过去的`cog`。

时间过去的`cog`是一个纯 Go `cog`。这意味着它仅使用 Go 实现。Go 包`go-humanize`为我们提供了显示时间的功能。我们将利用这个包来实现时间过去的`cog`。这是`go-humanize`包的 GitHub 页面的 URL：[`github.com/dustin/go-humanize`](https://github.com/dustin/go-humanize)。

让我们检查`shared/cogs/timeago/timeago.go`源文件。我们首先声明包名为`timeago`：

```go
package timeago
```

在我们的导入分组中，我们包括`github.com/uxtoolkit/cog`，这个包为我们提供了实现`cog`的功能（以粗体显示）。我们在导入分组中包括`go-humanize`分组，并用名称`"humanize"`进行别名（以粗体显示）：

```go
import (
  "errors"
  "reflect"
  "time"

 humanize "github.com/dustin/go-humanize"
  "github.com/uxtoolkit/cog"
)
```

所有的齿轮都必须声明一个名为`cogType`的未导出变量，其类型为`reflect.Type`：

```go
var cogType reflect.Type
```

在`init`函数内，我们使用`reflect.TypeOf`函数对新创建的`TimeAgo`实例调用，将返回的值赋给`cogType`变量：

```go
func init() {
  cogType = reflect.TypeOf(TimeAgo{})
}
```

对于我们实现的每个`cog`，也需要初始化`cogType`变量。正确设置`cogType`允许静态资产捆绑系统考虑到齿轮在 Web 应用程序中的静态资产依赖关系。`cogType`将被用于收集所有模板和静态资产，这些资产是使`cog`函数正常运行所需的。

这是我们用来定义`TimeAgo cog`的`struct`：

```go
type TimeAgo struct {
  cog.UXCog
  timeInstance time.Time
}
```

请注意，我们在`struct`定义中嵌入了`ux.UXCog`。正如前面所述，`cog.UXCog`类型将为我们提供必要的功能，以允许我们呈现`cog`。除了嵌入`ux.UXCog`，我们还声明了一个未导出字段，名为`timeInstance`，类型为`time.Time`。这将包含我们将转换为人类可读格式的`time.Time`实例。

我们创建一个名为`NewTimeAgo`的构造函数，它返回一个新的`TimeAgo cog`实例：

```go
func NewTimeAgo() *TimeAgo {
  t := &TimeAgo{}
  t.SetCogType(cogType)
  return t
}
```

我们在这里拥有的构造函数遵循 Go 中实现的任何其他构造函数的相同模式。请注意，我们将`cogType`传递给新创建的`TimeAgo`实例的`SetCogType`方法。这是必需的，以便`cog`的静态资产包含在 isokit 的静态资产捆绑系统生成的静态资产捆绑中。

我们为`TimeAgo`结构的`timeInstance`字段创建了一个 setter 方法，名为`SetTime`：

```go
func (t *TimeAgo) SetTime(timeInstance time.Time) {
  t.timeInstance = timeInstance
}
```

客户端应用程序将使用此 setter 方法为`TimeAgo` `cog`设置时间。我们将使用`SetTime`方法来设置 Gopher 加入 IGWEB 团队的开始日期。

为了实现`Cog`接口，`cog`必须定义一个`Start`方法。`Start`方法是`cog`中操作发生的地方。通过阅读其`Start`方法，您应该能够对`cog`的功能有一个大致的了解。以下是`TimeAgo` cog 的`Start`方法：

```go
func (t *TimeAgo) Start() error {

  if t.timeInstance.IsZero() == true {
    return errors.New("The time instance value has not been set!")
  }

  t.SetProp("timeAgoValue", humanize.Time(t.timeInstance))

  err := t.Render()
  if err != nil {
    return err
  }

  return nil
}
```

`Start`方法返回一个错误对象，通知调用者`cog`是否正确启动。在执行任何活动之前，会检查`timeInstance`值是否已设置。我们使用`if`条件语句来检查`timeInstance`值是否为其零值，表示它尚未设置。如果发生这种情况，该方法将返回一个新创建的`error`对象，指示时间值尚未设置。如果`timeInstance`值已设置，我们将继续向前。

我们调用 cog 的`SetProp`方法，使用人类可理解的时间值设置`timeAgoValue`属性。我们通过调用`go-humanize`包（别名为`humanize`）中的`Time`函数，并传递 cog 的`timeInstance`值来获取人类可理解的时间值。

我们调用 cog 的`Render`方法来渲染`cog`。如果在尝试渲染`cog`时发生错误，则`Start`方法将返回`error`对象。否则，将返回`nil`值，表示启动`cog`时没有错误。

此时，我们已经实现了`timeago` cog 的 Go 部分。为了使人类可读的时间出现在网页上，我们必须实现 cog 的模板。

`timeago.tmpl`文件（位于`shared/cogs/timeago/templates`目录中）是一个简单的单行模板。我们声明以下`span`元素，并且有一个模板动作来渲染`timeAgoValue`属性：

```go
<span class="timeagoSpan">{{.timeAgoValue}}</span>
```

按照惯例，`cog`包中的主要模板的名称必须与`cog`包的相同。例如，对于`timeago`包，`cog`的主要模板将是`timeago.tmpl`。您可以自由定义和使用已在应用程序模板集中注册的任何自定义模板函数，以及`cog`模板。您还可以创建任意数量的子模板，这些子模板将由`cog`的主要模板调用。

现在我们已经准备好在关于页面上实例化`cog`的模板。

让我们来看看`client/handlers/about.go`源文件中的`InitializeAboutPage`函数：

```go
func InitializeAboutPage(env *common.Env) {
  humanReadableDivs := env.Document.GetElementsByClassName("humanReadableDate")
  for _, div := range humanReadableDivs {
    unixTimestamp, err := strconv.ParseInt(div.GetAttribute("data-starttimeunix"), 10, 64)
    if err != nil {
      log.Println("Encountered error when attempting to parse int64 from string:", err)
    }
    t := time.Unix(unixTimestamp, 0)
 humanTime := timeago.NewTimeAgo()
 humanTime.CogInit(env.TemplateSet)
 humanTime.SetID(div.ID())
 humanTime.SetTime(t)
 err = humanTime.Start()
    if err != nil {
      println("Encountered the following error when attempting to start the timeago cog: ", err)
    }
  }
}
```

由于关于页面上列出了三个地鼠，页面上将运行总共三个`TimeAgo` cog 实例。我们使用`env.Document`对象上的`GetElementByClassName`方法，提供`humanReadableDate`类名，来收集 cog 的`div`容器。然后我们循环遍历每个`div`元素，这就是实例化`cog`的所有操作发生的地方。

首先，我们从`div`容器中包含的自定义数据属性中提取 Unix 时间戳值。回想一下，我们使用自定义模板函数`unixformat`将`starttimeunix`自定义数据属性填充为地鼠的开始时间的 Unix 时间戳。

然后我们使用`time`包中可用的`Unix`函数创建一个新的`time.Time`对象，并提供我们从`div`容器的自定义数据属性中提取的`unixTimestamp`。用粗体显示了实例化和设置`TimeAgo` cog 的代码。我们首先通过调用构造函数`NewTimeAgo`来实例化一个新的`TimeAgo` cog，并将其分配给`humanTime`变量。

然后我们在`humanTime`对象上调用`CogInit`方法，并提供`env.TemplateSet`对象。我们调用`SetID`方法来注册`div`容器的`id`属性，以将其与`cog`实例关联起来。然后我们在`TimeAgo` cog 上调用`SetTime`方法，传入我们从`div`容器中提取的`unixTimestamp`创建的`time.Time`对象`t`。

现在我们已经准备好通过调用其`Start`方法启动`cog`。我们将`Start`方法返回的`error`对象分配给`err`。如果`err`不等于`nil`，则表示在启动`cog`时发生了错误，在这种情况下，我们将在网页控制台中打印出有意义的消息。如果没有错误，`cog`将呈现在网页上。*图 9.6*显示了 Molly 的启动时间的屏幕截图。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/15fecc9b-375a-4b05-89b6-9892c784b211.png)

图 9.6：时间前`cog`的操作

# 实时时钟`cog`

当我们在时间前调用`Start`方法时，时间将使用虚拟 DOM 呈现在网页上，而不是进行替换内部 HTML 操作。由于时间前`cog`只更新一次时间，即在调用`cog`的`Start`方法时，很难欣赏到`cog`的虚拟 DOM 的作用。

在这个例子中，我们将构建一个实时时钟`Cog`，它具有显示世界上任何地方的当前时间的能力。由于我们将显示到秒的时间，我们将每秒执行一次`SetProp`操作以重新呈现实时时钟`Cog`。

*图 9.7*是实时时钟的插图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/aa3d10d9-cfda-475d-952d-b54caf49810b.png)

图 9.7：描绘实时时钟`cog`的插图

我们将为四个地方渲染当前时间：您目前所在的地方、金奈、新加坡和夏威夷。在`shared/templates/index_content.tmpl`模板源文件中，我们声明了四个`div`容器，它们作为我们将实例化的四个实时时钟`cog`的安装点。

```go
 <div data-component="cog" id="myLiveClock" class="liveclockTime"></div>
 <div data-component="cog" id="chennaiLiveClock" class="liveclockTime"></div>
 <div data-component="cog" id="singaporeLiveClock" class="liveclockTime"></div>
 <div data-component="cog" id="hawaiiLiveClock" class="liveclockTime"></div>
```

再次注意，我们通过声明包含属性`"data-component"`的`div`容器来定义实时时钟的安装点，并将其值设置为`"cog"`。我们为所有四个`cog`容器分配了唯一的 ID。我们在`div`容器中声明的类名`liveclockTime`是用于样式目的。

现在我们已经为四个实时时钟`cog`设置了安装点，让我们来看看如何实现实时时钟`cog`。

实时时钟`Cog`的实现可以在`shared/cogs/liveclock`文件夹中的`liveclock.go`源文件中找到。

我们为`cog`的包名称声明了名称`liveclock`：

```go
package liveclock
```

请注意，在我们的导入分组中，我们包含了`github.com/uxtoolkit/cog`包：

```go
import (
  "errors"
  "reflect"
  "time"
 "github.com/uxtoolkit/cog"
)
```

我们定义了未导出的包变量`cogType`：

```go
var cogType reflect.Type
```

在`init`函数内，我们将`cogType`变量赋值为调用`reflect.TypeOf`函数在新创建的`LiveClock`实例上返回的值：

```go
func init() {
  cogType = reflect.TypeOf(LiveClock{})
}
```

这是实现`cog`的必要步骤。

到目前为止，我们已经确定了声明和初始化`cogType`是实现`cog`的基本要求的一部分。

以下是`LiveClock` cog 的结构：

```go
type LiveClock struct {
  cog.UXCog
  ticker *time.Ticker
}
```

我们在`cog`的结构定义中嵌入了`cog.UXCog`类型。我们引入了一个`ticker`字段，它是指向`time.Ticker`的指针。我们将使用这个`ticker`每秒进行一次实时时钟的滴答。

以下是`LiveClock` cog 的构造函数：

```go
func NewLiveClock() *LiveClock {
  liveClock := &LiveClock{}
 liveClock.SetCogType(cogType)
  liveClock.SetCleanupFunc(liveClock.Cleanup)
  return liveClock
}
```

`NewLiveClock`函数充当实时时钟`cog`的构造函数。我们声明并初始化`liveClock`变量为一个新的`LiveClock`实例。我们调用`liveClock`对象的`SetCogType`方法并传递`cogType`。请记住，这是构造函数中必须存在的步骤（以粗体显示）。

然后我们调用`liveClock`对象的`SetCleanupFunc`方法，并提供一个清理函数`liveClock.Cleanup`。`SetCleanUp`方法包含在`cog.UXCog`类型中。它允许我们指定一个在`cog`从 DOM 中移除之前应该调用的清理函数。最后，我们返回`LiveClock cog`的新实例。

让我们来看一下`Cleanup`函数：

```go
func (lc *LiveClock) Cleanup() {
  lc.ticker.Stop()
}
```

这个函数非常简单。我们只需在 cog 的`ticker`对象上调用`Stop`方法来停止`ticker`。

这是 cog 的`Start`方法，其中`ticker`将被启动：

```go
func (lc *LiveClock) Start() error {
```

我们首先声明时间布局常量`layout`，并将其设置为`RFC1123Z`时间格式。我们声明一个`location`变量，指向`time.Location`类型：

```go
  const layout = time.RFC1123
  var location *time.Location
```

在启动`LiveClock` cog 之前，`cog`的用户必须设置两个重要的属性，即`"timezoneName"`和`"timezoneOffset"`：

```go
  if lc.Props["timezoneName"] != nil && lc.Props["timezoneOffset"] != nil {
    location = time.FixedZone(lc.Props["timezoneName"].(string), lc.Props["timezoneOffset"].(int))
  } else {
    return errors.New("The timezoneName and timezoneOffset props need to be set!")
  }
```

这些值用于初始化位置变量。如果这些属性中的任何一个未提供，将返回一个错误。

如果这两个属性都存在，我们继续将实时时钟`cog`的`ticker`属性分配给一个新创建的`time.Ticker`实例，它将每秒进行滴答：

```go
lc.ticker = time.NewTicker(time.Millisecond * 1000)
```

我们在 ticker 的通道上使用`range`来迭代每一秒，当值到达时，我们设置`currentTime`属性，为其提供格式化的时间值（以粗体显示）：

```go
  go func() {
    for t := range lc.ticker.C {
 lc.SetProp("currentTime", t.In(location).Format(layout))
    }
  }()
```

请注意，我们同时使用了位置和时间布局来格式化时间。一旦 cog 被渲染，每秒将自动调用`SetProp`来调用`Render`方法重新渲染 cog。

我们调用 cog 的`Render`方法来将 cog 渲染到网页上：

```go
  err := lc.Render()
  if err != nil {
    return err
  }
```

在方法的最后一行，我们返回一个`nil`值，表示没有发生错误：

```go
 return nil
```

我们已经在`liveclock.tmpl`源文件中定义了`cog`的模板：

```go
<p>{{.timeLabel}}: {{.currentTime}}</p>
```

我们打印出时间标签，以及当前时间。`timeLabel`属性用于向`cog`提供时间标签，并且将是我们想要知道当前时间的地方的名称。

现在我们已经看到了制作实时时钟`cog`所需的内容，以及它如何显示时间，让我们继续在主页上添加一些实时时钟 cogs。

这是`index.go`源文件中`InitializeIndexPage`函数内部的代码部分，我们在其中为本地时区实例化实时时钟 cog：

```go
  // Localtime Live Clock Cog
  localZonename, localOffset := time.Now().In(time.Local).Zone()
  lc := liveclock.NewLiveClock()
  lc.CogInit(env.TemplateSet)
  lc.SetID("myLiveClock")
  lc.SetProp("timeLabel", "Local Time")
  lc.SetProp("timezoneName", localZonename)
  lc.SetProp("timezoneOffset", localOffset)
  err = lc.Start()
  if err != nil {
    println("Encountered the following error when attempting to start the local liveclock cog: ", err)
  }
```

为了实例化本地时间的 cog，我们首先获取本地区域名称和本地时区偏移量。然后我们创建一个名为`lc`的`LiveClock cog`的新实例。我们调用`CogInit`方法来初始化 cog。我们调用`SetID`方法来注册 cog 的挂载点的`id`，即`div`容器，`cog`将把其输出渲染到其中。我们调用`SetProp`方法来设置`"timeLabel"`、`"timezoneName"`和`"timezoneOffset"`属性。最后，我们调用`Start`方法来启动`LiveClock` cog。和往常一样，我们检查`cog`是否正常启动，如果没有，我们在 web 控制台中打印出`error`对象。

类似地，我们以与本地时间相同的方式实例化了 Chennai、新加坡和夏威夷的`LiveClock` cogs，除了一件事。对于其他地方，我们明确提供了每个地方的时区名称和 GMT 时区偏移量：

```go
  // Chennai Live Clock Cog
  chennai := liveclock.NewLiveClock()
  chennai.CogInit(env.TemplateSet)
  chennai.SetID("chennaiLiveClock")
  chennai.SetProp("timeLabel", "Chennai")
  chennai.SetProp("timezoneName", "IST")
  chennai.SetProp("timezoneOffset", int(+5.5*3600))
  err = chennai.Start()
  if err != nil {
    println("Encountered the following error when attempting to start the chennai liveclock cog: ", err)
  }

  // Singapore Live Clock Cog
  singapore := liveclock.NewLiveClock()
  singapore.CogInit(env.TemplateSet)
  singapore.SetID("singaporeLiveClock")
  singapore.SetProp("timeLabel", "Singapore")
  singapore.SetProp("timezoneName", "SST")
  singapore.SetProp("timezoneOffset", int(+8.0*3600))
  err = singapore.Start()
  if err != nil {
    println("Encountered the following error when attempting to start the singapore liveclock cog: ", err)
  }

  // Hawaii Live Clock Cog
  hawaii := liveclock.NewLiveClock()
  hawaii.CogInit(env.TemplateSet)
  hawaii.SetID("hawaiiLiveClock")
  hawaii.SetProp("timeLabel", "Hawaii")
  hawaii.SetProp("timezoneName", "HDT")
  hawaii.SetProp("timezoneOffset", int(-10.0*3600))
  err = hawaii.Start()
  if err != nil {
    println("Encountered the following error when attempting to start the hawaii liveclock cog: ", err)
  }
```

现在，我们将能够看到实时时钟 cogs 的运行情况。*图 9.8*是主页上显示的实时时钟的屏幕截图。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/7e166fd4-a7db-4b49-8d19-07f012ac9d5c.png)

图 9.8：实时时钟 cog 的运行情况

随着每一秒的流逝，每个实时时钟都会更新新的时间值。虚拟 DOM 会渲染出变化的部分，有效地在每秒重新渲染实时时钟。

到目前为止，我们实现的前两个 cogs 都是完全由 Go 实现的纯 cogs。如果我们想利用现有的 JavaScript 解决方案来提供特定功能，该怎么办？这将是需要实现混合 cog 的情况，一个由 Go 和 JavaScript 实现的`cog`。

# 实现混合 cogs

JavaScript 已经存在了二十多年。在这段时间内，使用这种语言创建了许多强大的、可用于生产的解决方案。同构 Go 不能独立存在，我们必须承认 JavaScript 生态系统中有许多有用的现成解决方案。在许多情况下，我们可以通过利用现有的 JavaScript 解决方案来节省大量时间和精力，而不是以纯 Go 的方式重新实现整个解决方案。

混合 cogs 是使用 Go 和 JavaScript 实现的。混合 cogs 的主要目的是利用现有的 JavaScript 解决方案的功能，并将该功能公开为`cog`。这意味着`cog`实现者需要了解 Go 和 JavaScript 来实现混合 cogs。请记住，混合 cogs 的用户只需要了解 Go，因为 JavaScript 的使用是`cog`的内部实现细节。这使得那些可能不熟悉 JavaScript 的 Go 开发人员可以方便地使用 cogs。

# 日期选择器 cog

让我们考虑一种需要实现混合`cog`的情况。Molly，IGWEB 的事实产品经理，提出了一个提供更好客户支持的绝佳主意。她向技术团队提出的功能请求是允许网站用户在联系表单上提供一个可选的优先日期，通过这个日期，用户应该在 IGWEB 团队的 gopher 回复。

Molly 找到了一个独立的日期选择器小部件，使用纯 JavaScript 实现（没有框架/库依赖），名为 Pikaday：[`github.com/dbushell/Pikaday`](https://github.com/dbushell/Pikaday)。

Pikaday，JavaScript 日期选择器小部件，突出了本节开头提到的事实。JavaScript 不会消失，已经有许多有用的解决方案是用它创建的。这意味着，我们必须有能力在有意义的时候利用现有的 JavaScript 解决方案。Pikaday 日期选择器是一个特定的用例，更有利于利用现有的 JavaScript 日期选择器小部件，而不是将其作为纯`cog`实现。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/72dbbc90-5aa2-4242-a10a-c8bb83c6cfb7.png)

图 9.9：描述时间敏感日期输入字段和日历日期选择器小部件的线框设计

*图 9.9*是一个线框设计，描述了带有时间敏感输入字段的联系表单，当点击时，将显示一个日历日期选择器。让我们看看通过使用 Go 和 JavaScript 实现的日期选择器 cog 来满足 Molly 的请求需要做些什么。

我们首先将 Pikaday 日期选择器所需的 JavaScript 和 CSS 源文件放在`cog`的`static`文件夹中的`js`和`css`文件夹中（分别）。

在`shared/templates/partials/contactform_partial.tmpl`源文件中，我们声明了日期选择器 cog 的挂载点（以粗体显示）：

```go
    <fieldset class="pure-control-group">
      <div data-component="cog" id="sensitivityDate"></div>
    </fieldset>
```

`div`容器满足所有`cog`挂载点的两个基本要求：我们已经设置了属性`"data-component"`，值为`"cog"`，并为`cog`容器指定了一个`id`为`"sensitivityDate"`。

让我们逐节检查日期选择器 cog 的实现，定义在`shared/cogs/datepicker/datepicker.go`源文件中。首先，我们从声明包名开始：

```go
package datepicker
```

这是 cog 的导入分组：

```go
import (
  "errors"
  "reflect"
  "time"

  "github.com/gopherjs/gopherjs/js"
  "github.com/uxtoolkit/cog"
)
```

注意我们在导入分组中包含了`gopherjs`包（以粗体显示）。我们将需要`gopherjs`的功能来查询 DOM。

在我们声明`cogType`之后，我们将`JS`变量初始化为`js.Global`：

```go
var cogType reflect.Type
var JS = js.Global
```

正如您可能还记得的那样，这为我们节省了一点输入。我们可以直接将`js.Global`称为`JS`。

从 Pikaday 项目网页[`github.com/dbushell/Pikaday`](https://github.com/dbushell/Pikaday)，我们可以了解日期选择器小部件接受的所有输入参数。输入参数作为单个 JavaScript 对象提供。日期选择器`cog`将公开这些输入参数的子集，足以满足 Molly 的功能请求。我们创建了一个名为`DatePickerParams`的`struct`，它作为日期选择器小部件的输入参数：

```go
type DatePickerParams struct {
  *js.Object
  Field *js.Object `js:"field"`
  FirstDay int `js:"firstDay"`
  MinDate *js.Object `js:"minDate"`
  MaxDate *js.Object `js:"maxDate"`
  YearRange []int `js:"yearRange"`
}
```

我们嵌入`*js.Object`以指示这是一个 JavaScript 对象。然后我们为 JavaScript 输入对象的相应属性的`struct`声明相应的 Go 字段。例如，名为`Field`的字段是为`field`属性而声明的。我们为每个字段提供的`"js"` `struct`标签允许 GopherJS 将`struct`及其字段从其指定的 Go 名称转换为其等效的 JavaScript 名称。正如我们声明了名为 Field 的字段一样，我们还为`FirstDay`（`firstDay`）、`MinDate`（`minDate`）、`MaxDate`（`maxDate`）和`YearRange`（`yearRange`）声明了字段。

阅读 Pikaday 文档，[`github.com/dbushell/Pikaday`](https://github.com/dbushell/Pikaday)，我们可以了解每个输入参数的作用：

+   `Field` - 用于将日期选择器绑定到表单字段。

+   `FirstDay` - 用于指定一周的第一天。（0 代表星期日，1 代表星期一，依此类推）。

+   `MinDate` - 可以在日期选择器小部件中选择的最早日期。

+   `MaxDate` - 可以在日期选择器小部件中选择的最晚日期。

+   `YearRange` - 要显示的年份范围。

现在我们已经定义了日期选择器的输入参数结构`DatePickerParams`，是时候实现日期选择器`cog`了。我们首先声明`DatePicker`结构：

```go
type DatePicker struct {
  cog.UXCog
  picker *js.Object
}
```

像往常一样，我们嵌入`cog.UXCog`来带来我们需要的所有 UXCog 功能。我们还声明了一个字段`picker`，它是指向`js.Object`的指针。`picker`属性将用于引用 Pikaday 日期选择器 JavaScript 对象。

然后我们为日期选择器`cog`实现了一个名为`NewDatePicker`的构造函数：

```go
func NewDatePicker() *DatePicker {
  d := &DatePicker{}
  d.SetCogType(cogType)
  return d
}
```

到目前为止，cog 构造函数对您来说应该很熟悉。它的职责是返回`DatePicker`的新实例，并设置 cog 的`cogType`。

现在我们的构造函数已经就位，是时候来检查日期选择器 cog 的`Start`方法了：

```go
func (d *DatePicker) Start() error {

  if d.Props["datepickerInputID"] == nil {
    return errors.New("Warning: The datePickerInputID prop need to be set!")
  }

  err := d.Render()
  if err != nil {
    return err
  }
```

我们首先检查是否已设置`"datepickerInputID"`属性。这是输入字段元素的`id`，将用作`DatePickerParams` `struct`中的`Field`值。在开始`cog`之前，调用者必须设置此属性，这是一个硬性要求。未设置此属性将导致错误。

如果已设置`"datepickerInputID"`属性，我们调用 cog 的`Render`方法来渲染 cog。这将为日期选择器 JavaScript 小部件依赖的输入字段渲染 HTML 标记。

然后我们声明并实例化`params`，这是一个 JavaScript 对象，将被传递给日期选择器 JavaScript 小部件：

```go
params := &DatePickerParams{Object: js.Global.Get("Object").New()}
```

日期选择器输入参数对象`params`是一个 JavaScript 对象。Pikaday JavaScript 对象将使用`params`对象进行初始配置。

我们使用 cog 的`Props`属性来遍历 cog 的属性。对于每次迭代，我们获取属性的名称（`propName`）和属性的值（`propValue`）：

```go
 for propName, propValue := range d.Props {
```

我们声明的`switch`块对于可读性很重要：

```go
 switch propName {

    case "datepickerInputID":
      inputFieldID := propValue.(string)
      dateInputField := JS.Get("document").Call("getElementById", inputFieldID)
      params.Field = dateInputField

    case "datepickerLabel":
      // Do nothing

    case "datepickerMinDate":
      datepickerMinDate := propValue.(time.Time)
      minDateUnix := datepickerMinDate.Unix()
      params.MinDate = JS.Get("Date").New(minDateUnix * 1000)

    case "datepickerMaxDate":
      datepickerMaxDate := propValue.(time.Time)
      maxDateUnix := datepickerMaxDate.Unix()
      params.MaxDate = JS.Get("Date").New(maxDateUnix * 1000)

    case "datepickerYearRange":
      yearRange := propValue.([]int)
      params.YearRange = yearRange

    default:
      println("Warning: Unknown prop name provided: ", propName)
    }
  }
```

`switch`块内的每个`case`语句告诉我们日期选择器`cog`接受的所有属性作为输入参数，这些参数将被传递到 Pikaday JavaScript 小部件。如果未识别属性名称，则在 Web 控制台中打印警告，说明该属性未知。

第一种情况处理了`"datepickerInputID"`属性。它将用于指定激活 Pikaday 小部件的输入元素的`id`。在这种情况下，我们通过在`document`对象上调用`getElementById`方法并将`inputFieldID`传递给该方法来获取输入元素字段。我们将输入`params`属性`Field`设置为从`getElementById`方法调用中获取的输入字段元素。

第二种情况处理了`"datepickerLabel"`属性。`"datepickerLabel"`属性的值将在 cog 的模板源文件中使用。因此，不需要处理这种特殊情况。

第三种情况处理了`"datepickerMinDate"`属性。它将用于获取 Pikaday 小部件应显示的最小日期。我们将调用者提供的`type time.Time`的`"datepickerMinDate"`值转换为其 Unix 时间戳表示。然后，我们使用 Unix 时间戳创建一个新的 JavaScript `date`对象，适用于`minDate`输入参数。

第四种情况处理了`"datepickerMaxDate"`属性。它将用于获取日期选择器小部件应显示的最大日期。我们在这里采用了与`minDate`参数相同的策略。

第五种情况处理了`"datepickerYearRange"`属性。它将用于指定显示的日历将覆盖的年份范围。年份范围是一个切片，我们使用属性的值填充输入参数对象的`YearRange`属性。

如前所述，`default` `case`处理了调用者提供未知属性名称的情况。如果我们到达`default` `case`，我们将在 Web 控制台中打印警告消息。

现在我们可以实例化 Pikaday 小部件，并将输入参数对象`params`提供给它：

```go
d.picker = JS.Get("Pikaday").New(params)
```

最后，我们通过返回`nil`值表示启动`cog`时没有错误：

```go
return nil
```

现在我们已经实现了日期选择器 cog，让我们来看看 cog 的主要模板，定义在`shared/cogs/datepicker/templates/datepicker.tmpl`源文件中，是什么样子：

```go
 <label class="datepickerLabel" for="datepicker">{{.datepickerLabel}}</label>
 <input class="datepickerInput" type="text" id="{{.datepickerInputID}}" name="{{.datepickerInputID}}">
```

我们声明一个`label`元素，使用属性`"datepickerLabel"`显示日期选择器 cog 的标签。我们声明一个`input`元素，它将作为与 Pikaday 小部件一起使用的输入元素字段。我们使用`"datepickerInputID"`属性指定输入元素字段的`id`属性。

现在我们已经实现了日期选择器 cog，是时候开始使用它了。我们在`client/handlers/contact.go`源文件中的`InitializeContactPage`函数中实例化`cog`：

```go
  byDate := datepicker.NewDatePicker()
  byDate.CogInit(env.TemplateSet)
  byDate.SetID("sensitivityDate")
  byDate.SetProp("datepickerLabel", "Time Sensitivity Date:")
  byDate.SetProp("datepickerInputID", "byDateInput")
  byDate.SetProp("datepickerMinDate", time.Now())
  byDate.SetProp("datepickerMaxDate", time.Date(2027, 12, 31, 23, 59, 0, 0, time.UTC))
  err := byDate.Start()
  if err != nil {
    println("Encountered the following error when attempting to start the datepicker cog: ", err)
  }
```

首先，我们创建一个`DatePicker cog`的新实例。然后，我们调用 cog 的`CogInit`方法，注册应用程序的模板集。我们调用`SetID`方法设置 cog 的挂载点。我们调用 cog 的`SetProp`方法设置`datePickerLabel`、`datepickerInputID`、`datepickerMinDate`和`datepickerMaxDate`属性。我们调用 cog 的`Start`方法来激活它。如果启动`cog`时出现任何错误，我们将错误消息打印到 Web 控制台。

这就是全部内容了！我们可以利用日期选择器混合`cog`从 Pikaday 小部件中获取所需的功能。这种方法的优势在于，使用日期选择器`cog`的 Go 开发人员不需要了解 Pikaday 小部件的内部工作（JavaScript），就可以使用它。相反，他们可以在 Go 的范围内使用日期选择器`cog`向他们公开的功能。

*图 9.10*显示了日期选择器`cog`的操作截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/8e47b957-a807-4bb5-8ccf-4950f4ddd950.png)

图 9.10：日历日期选择器小部件的操作

即使齿轮用户除了必需的`datepickerInputID`之外没有提供任何自定义配置日期选择器`cog`的 props，Pikaday 小部件也可以正常启动。但是，如果我们需要为`cog`提供一组默认参数怎么办？在下一个示例中，我们将构建另一个混合`cog`，一个轮播图（图像滑块）`cog`，在其中我们将定义默认参数。

# 轮播图齿轮

在本示例中，我们将创建一个图像轮播图齿轮，如*图 9.11*中的线框设计所示。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/bc822f06-91d8-4abd-ad46-dee1c7ecf5f3.png)

图 9.11：描述轮播图齿轮的线框设计

轮播图齿轮将由 vanilla JavaScript 中实现的 tiny-slider 小部件提供动力。以下是 tiny-slider 项目的 URL：[`github.com/ganlanyuan/tiny-slider`](https://github.com/ganlanyuan/tiny-slider)。

我们将 tiny-slider 小部件的 JavaScript 源文件`tiny-slider.min.js`放在齿轮的`static/js`文件夹中。我们将与 tiny-slider 小部件相关的 CSS 文件`tiny-slider.css`和`styles.css`放在`static/css`文件夹中。

我们将构建的轮播图齿轮将公开由 tiny-slider 小部件提供的以下输入参数：

```go
container Node | String Default: document.querySelector('.slider').
```

`container`参数表示滑块容器元素或选择器：

```go
items Integer Default: 1.
```

`items`参数表示正在显示的幻灯片数量：

```go
slideBy Integer | 'page' Default: 1.
```

`slideBy`参数表示一次“点击”要进行的幻灯片数量：

```go
autoplay Boolean Default: false.
```

`autoplay`参数用于切换幻灯片的自动更改：

```go
autoplayText Array (Text | Markup) Default: ['start', 'stop'].
```

`autoplayText`参数控制自动播放开始/停止按钮中显示的文本或标记。

```go
controls Boolean Default: true.
```

`controls`参数用于切换控件（上一个/下一个按钮）的显示和功能。

图像轮播图将显示 IGWEB 上可用的一组特色产品。我们在`shared/templates/index_content.tmpl`源文件中声明了齿轮的挂载点：

```go
<div data-component="cog" id="carousel"></div>
```

我们声明了作为轮播图齿轮挂载点的`div`容器。我们声明了属性`"data-component"`，并将其赋值为`"cog"`。我们还声明了一个`id`属性为`"carousel"`。

轮播图齿轮实现在`shared/cogs/carousel`文件夹中的`carousel.go`源文件中。以下是包声明和导入分组：

```go
package carousel

import (
  "errors"
  "reflect"

  "github.com/gopherjs/gopherjs/js"
  "github.com/uxtoolkit/cog"
)
```

tiny-slider 小部件使用输入参数 JavaScript 对象进行实例化。我们将使用`CarouselParams struct`来建模输入参数对象：

```go
type CarouselParams struct {
  *js.Object
  Container string `js:"container"`
  Items int `js:"items"`
  SlideBy string `js:"slideBy"`
  Autoplay bool `js:"autoplay"`
  AutoplayText []string `js:"autoplayText"`
  Controls bool `js:"controls"`
}
```

在嵌入指向`js.Object`的指针之后，我们在`struct`中定义的每个字段都对应于其等效的 JavaScript 参数对象属性。例如，`Container`字段映射到输入参数对象的`container`属性。

以下是定义`carousel`齿轮的`struct`：

```go
type Carousel struct {
  cog.UXCog
  carousel *js.Object
}
```

像往常一样，我们嵌入了`cog.UXCog`类型，以借用`UXCog`的功能。`carousel`字段将用于引用 JavaScript 对象的 tiny-slider 小部件。

到目前为止，您应该能够猜到轮播图齿轮的构造函数是什么样子的：

```go
func NewCarousel() *Carousel {
  c := &Carousel{}
  c.SetCogType(cogType)
  return c
}
```

除了创建对`Carousel`实例的新引用之外，构造函数还设置了齿轮的`cogType`。

现在是时候检查轮播图齿轮实现的大部分内容了，这些内容可以在齿轮的`Start`方法中找到：

```go
func (c *Carousel) Start() error {
```

我们首先检查`cog`的用户是否设置了`contentItems`和`carouselContentID`props。`contentItems`prop 是应该出现在轮播图中的图像的服务器相对路径的字符串切片。`carouselContentID`prop 是包含轮播图内容的`div`容器的`id`属性的值。

如果这些 props 中的任何一个都没有设置，我们将返回一个指示这两个 props 都必须设置的`error`。如果这两个 props 已经设置，我们将继续渲染齿轮：

```go
  if c.Props["contentItems"] == nil || c.Props["carouselContentID"] == nil {
    return errors.New("The contentItems and carouselContentID props need to be set!")
  }

  err := c.Render()
  if err != nil {
    return err
  }
```

在这一时刻我们渲染`cog`，因为网页上需要存在 HTML 标记才能使`cog`正常工作。值得注意的是，包含轮播内容的`div`容器，我们使用必需的`carouselContentID`属性提供其`id`。如果渲染`cog`时出现错误，我们返回错误以表示无法启动`cog`。如果在渲染`cog`时没有遇到错误，我们继续实例化输入参数对象：

```go
 params := &CarouselParams{Object: js.Global.Get("Object").New()}
```

这个`struct`代表了我们将在实例化时提供给 tiny-slider 对象的输入参数。

接下来的代码部分很重要，因为这是我们定义默认参数的地方：

```go
  // Set the default parameter values
  params.Items = 1
  params.SlideBy = "page"
  params.Autoplay = true
  params.AutoplayText = []string{PLAYTEXT, STOPTEXT}
  params.Controls = false
```

当齿轮维护者查看这一段代码时，他们可以很容易地确定齿轮的默认行为。通过查看默认参数，可以知道滑块一次只会显示一个项目。滑块设置为按页模式滑动，并且滑块将自动开始幻灯片放映。我们为`AutoplayText`属性提供了一个字符串切片，使用`PLAYTEXT`和`STOPTEXT`常量分别表示播放和停止按钮的文本符号。我们将`Controls`属性设置为`false`，这样默认情况下图像轮播中将不会出现上一个和下一个按钮。

我们继续迭代`cog`的用户提供的所有属性，访问每个属性，包括`propName`（`string`）和`propValue`（`interface{}`）：

```go
 for propName, propValue := range c.Props {
```

我们在`propName`上声明了一个`switch`块：

```go
 switch propName {

    case "carouselContentID":
      if propValue != nil {
        params.Container = "#" + c.Props["carouselContentID"].(string)
      }

    case "contentItems":
      // Do nothing

    case "items":
      if propValue != nil {
        params.Items = propValue.(int)
      }

    case "slideBy":
      if propValue != nil {
        params.SlideBy = c.Props["slideBy"].(string)
      }

    case "autoplay":
      if propValue != nil {
        params.Autoplay = c.Props["autoplay"].(bool)
      }

    case "autoplayText":
      if propValue != nil {
        params.AutoplayText = c.Props["autoplayText"].([]string)
      }

    case "controls":
      if propValue != nil {
        params.Controls = c.Props["controls"].(bool)
      }

    default:
      println("Warning: Unknown prop name provided: ", propName)
    }
  }
```

使用`switch`块可以轻松看到每个`case`语句中所有有效属性的名称。如果属性名称未知，则会进入`default`情况，在那里我们会在 Web 控制台中打印警告消息。

第一个`case`处理了必需的`"carouselContentID"`属性。它用于指定将包含轮播内容项目的`div`容器。

第二个`case`处理了必需的`"contentItems"`属性。这个属性是一个`string`切片，用于在 cog 的模板中使用，因此我们不需要执行任何操作。

第三个`case`处理了`"items"`属性。这是处理 tns-slider 对象的`items`参数的属性，它显示在同一时间显示的幻灯片数量。如果属性值不是`nil`，我们将属性值的`int`值分配给`params.Items`属性。

第四个`case`处理了`slideBy`属性。如果属性值不是`nil`，我们将属性值（断言为`string`类型）分配给`params`对象的`SlideBy`属性。

第五个`case`处理了`"autoplay"`属性。如果属性值不是`nil`，我们将属性值（断言为`bool`类型）分配给`params`对象的`Autoplay`属性。

第六个`case`处理了`"autoplayText"`属性。如果属性值不是`nil`，我们将属性值（断言为`[]string`类型）分配给`params`对象的`AutoplayText`属性。

第七个`case`处理了`"controls"`属性。如果属性值不是`nil`，我们将属性值（断言为`bool`类型）分配给`params`对象的`Controls`属性。

如果属性名称不属于前面七个情况之一，它将由`default case`处理。请记住，如果我们到达这个`case`，这表示`cog`的用户提供了一个未知的属性名称。

现在我们可以实例化 tiny-slider 小部件并将其分配给齿轮的`carousel`属性：

```go
c.carousel = JS.Get("tns").New(params)
```

`Start`方法返回`nil`值，表示启动`cog`时没有遇到错误：

```go
return nil
```

`shared/cogs/carousel/templates/carousel.tmpl`源文件定义了 carousel `cog`的模板：

```go
<div id="{{.carouselContentID}}" class="carousel">
{{range .contentItems}}
  <div><img src="img/strong>"></div>
{{end}}
</div>
```

我们声明一个`div`容器来存放轮播图像。`contentItems`中的每个项目都是到图像的服务器相对路径。我们使用`range`模板操作来迭代`contentItems`属性（一个`string`切片），以打印出每个图像的地址，这些地址位于自己的`div`容器内。请注意，我们将点（`.`）模板操作作为`img`元素的`src`属性的值。点模板操作表示在迭代`contentItems`切片时的当前值。

现在我们已经实现了轮播`cog`并创建了其模板，是时候在主页上实例化和启动`cog`了。我们将添加轮播`cog`的代码到`client/handlers/index.go`源文件的`InitializeIndexPage`函数的开头。

```go
  c := carousel.NewCarousel()
  c.CogInit(env.TemplateSet)
  c.SetID("carousel")
  contentItems := []string{"/static/images/products/watch.jpg", "/static/images/products/shirt.jpg", "/static/images/products/coffeemug.jpg"}
  c.SetProp("contentItems", contentItems)
  c.SetProp("carouselContentID", "gophersContent")
  err := c.Start()
  if err != nil {
    println("Encountered the following error when attempting to start the carousel cog: ", err)
  }
```

我们首先通过调用构造函数`NewCarousel`创建一个新的轮播`cog`，`c`。我们调用`CogInit`方法将应用程序的模板集与`cog`关联起来。我们调用`SetID`方法将`cog`与其挂载点关联起来，即`div`容器，`cog`将在其中呈现其输出。我们使用`string`切片文字将路径设置为图像文件的路径。我们调用`SetProp`方法设置所需的`contentItems`和所需的`carouselContent`属性。我们不设置任何其他属性，因为我们对轮播`cog`的默认行为感到满意。我们启动`cog`并检查是否在此过程中遇到任何错误。如果遇到任何错误，我们将在 Web 控制台中打印错误消息。

*图 9.12*是渲染的轮播`cog`的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/4be2b386-51b2-4bd6-899d-d06b545241a2.png)

图 9.12：轮播`cog`的运行情况

现在我们已经完成了轮播`cog`，接下来我们将在下一节中创建一个通知`cog`，用于在网页上显示动画通知消息。

# 通知`cog`

到目前为止，我们考虑的所有`cog`实现都已将输出呈现到网页上。让我们考虑实现一个不将任何输出呈现到网页上的`cog`。我们将要实现的通知`cog`将利用 Alertify JavaScript 库在网页上显示动画通知消息。

*图 9.13*是一个插图，描述了当用户将商品添加到购物车时，出现在网页右下角的通知消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/132cedbc-64e4-4837-8316-8be30cb47e23.png)

图 9.13：插图描述了一个通知

由于`cog`将完全依赖 JavaScript 库进行渲染，因此我们不必为`cog`实现模板，也不必为`cog`声明挂载点。

我们将利用 Alertify JavaScript 库的功能来显示通知。以下是 Alertify 项目的 URL：[`github.com/MohammadYounes/AlertifyJS`](https://github.com/MohammadYounes/AlertifyJS)。

查看`shared/cogs/notify`文件夹，注意没有模板文件夹存在。我们已将 Alertify 的 CSS 和 JavaScript 源文件的静态资产放在`shared/cogs/notify/static/css`和`shared/cogs/notify/static/js`文件夹中。

通知`cog`实现在`shared/cogs/notify`文件夹中的`notify.go`源文件中。由于对于客户端 Web 应用程序来说只有一个通知系统是有意义的，即由通知`cog`提供的通知系统，因此只能启动一个`cog`实例。为了跟踪并确保只能启动一个通知`cog`实例，我们将声明`alreadyStarted`布尔变量：

```go
var alreadyStarted bool
```

`Notify`结构定义了通知`cog`的字段：

```go
type Notify struct {
  cog.UXCog
  alertify *js.Object
  successNotificationEventListener func(*js.Object)
  errorNotificationEventListener func(*js.Object)
}
```

我们在这里输入`cog.UXCog`以便带入实现`Cog`接口所需的功能。`alertify`字段用于引用`alertify` JavaScript 对象。

我们正在构建的通知`cog`是事件驱动的。例如，当从客户端应用程序的任何页面触发自定义成功通知事件时，将显示成功通知。我们定义了两个字段，`successNotificationEventListener`和`errorNotificationEventListener`，它们都是函数，以 JavaScript 对象指针作为输入变量。我们定义了这些字段，以便我们可以跟踪设置用于监听成功和错误通知的自定义事件监听器函数。当需要移除事件监听器时，因为它们是通知`cog`实例的属性，所以很容易访问它们。

`NewNotify`函数充当构造函数：

```go
func NewNotify() *Notify {
  n := &Notify{}
  n.SetCogType(cogType)
  n.SetCleanupFunc(n.Cleanup)
  return n
}
```

请注意，我们已注册了一个清理函数（以粗体显示），该函数将在销毁`cog`之前调用。

让我们来看一下`Start`方法：

```go
func (n *Notify) Start() error {
  if alreadyStarted == true {
    return errors.New("The notification cog can be instantiated only once.")
  }
```

我们首先检查`alreadyStarted`布尔变量的值，以查看是否已经启动了通知`cog`实例。如果`alreadyStarted`的值为`true`，则表示先前已经启动了通知`cog`实例，因此我们返回一个指示无法启动通知`cog`的`error`。

如果`cog`尚未启动，我们继续实例化 Alertify JavaScript 对象：

```go
 n.alertify = js.Global.Get("alertify")
```

我们调用`StartListening`方法来设置监听自定义成功和错误通知消息事件的事件监听器：

```go
  n.StartListening()
  return nil
```

这是`StartListening`方法：

```go
func (n *Notify) StartListening() {

  alreadyStarted = true
  D := dom.GetWindow()
  n.successNotificationEventListener = D.AddEventListener("displaySuccessNotification", false, func(event dom.Event) {
    message := event.Underlying().Get("detail").String()
    n.notifySuccess(message)
  })

  n.errorNotificationEventListener = D.AddEventListener("displayErrorNotification", false, func(event dom.Event) {
    message := event.Underlying().Get("detail").String()
    n.notifyError(message)
  })
}
```

如果我们已经到达这个方法，这表明`cog`已经成功启动，所以我们将`alreadyStarted`布尔变量设置为`true`。我们设置一个事件监听器，用于监听`displaySuccessNotification`自定义事件。我们通过将其赋值给`cog`实例的`successNotificationEventListener`属性来跟踪我们正在创建的事件监听器函数。我们声明并实例化`message`变量，并将其设置为`event`对象的`detail`属性，该属性将包含应在网页上显示给用户的`string` `message`。然后我们调用`cog`的`notifySuccess`方法来在网页上显示成功通知消息。

我们遵循类似的程序来设置`displayErrorNotification`的事件监听器。我们将事件监听器函数分配给`cog`的`errorNotificationEventListener`属性。我们从`event`对象中提取`detail`属性，并将其分配给`message`变量。我们调用`cog`的`notifyError`方法来在网页上显示错误通知消息。

`notifySuccess`方法负责在网页上显示成功通知消息：

```go
func (n *Notify) notifySuccess(message string) {
  n.alertify.Call("success", message)
}
```

我们调用 alertify 对象的`success`方法来显示成功通知消息。

`notifyError`方法负责在网页上显示错误通知消息：

```go
func (n *Notify) notifyError(message string) {
  n.alertify.Call("error", message)
}
```

我们调用 alertify 对象的`error`方法来显示错误通知消息。

`CleanUp`方法只是调用`StopListening`方法：

```go
func (n *Notify) Cleanup() {
  n.StopListening()
}
```

`StopListening`方法用于在销毁`cog`之前移除事件监听器：

```go
func (n *Notify) StopListening() {
  D := dom.GetWindow()
  if n.successNotificationEventListener != nil {
    D.RemoveEventListener("displaySuccessNotification", false, n.successNotificationEventListener)
  }

  if n.errorNotificationEventListener != nil {
    D.RemoveEventListener("displayErrorNotification", false, n.errorNotificationEventListener)
  }

}
```

我们调用 DOM 对象的`RemoveEventListener`方法来移除处理`displaySuccessNotification`和`displayErrorNotification`自定义事件的事件监听函数。

`notify`包的导出`Success`函数用于广播自定义成功事件通知消息：

```go
func Success(message string) {
  var eventDetail = js.Global.Get("Object").New()
  eventDetail.Set("detail", message)
  customEvent := js.Global.Get("window").Get("CustomEvent").New("displaySuccessNotification", eventDetail)
  js.Global.Get("window").Call("dispatchEvent", customEvent)
}
```

在函数内部，我们创建了一个名为`eventDetail`的新 JavaScript 对象。我们将应该在网页上显示的`string` `message`分配给`eventDetail`对象的`detail`属性。然后，我们创建了一个名为`customEvent`的新自定义`event`对象。我们将自定义事件的名称`displaySuccessNotification`以及`eventDetail`对象作为输入参数传递给`CustomEvent`类型的构造函数。最后，为了分发事件，我们在`window`对象上调用`dispatchEvent`方法，并提供`customEvent`。

notify 包的导出`Error`函数用于广播自定义错误事件通知消息：

```go
func Error(message string) {
  var eventDetail = js.Global.Get("Object").New()
  eventDetail.Set("detail", message)
  customEvent := js.Global.Get("window").Get("CustomEvent").New("displayErrorNotification", eventDetail)
  js.Global.Get("window").Call("dispatchEvent", customEvent)
}
```

这个函数的实现几乎与`Success`函数完全相同。唯一的区别是我们分发了一个`displayErrorNotification`自定义事件。

我们在`client/handlers/initpagelayoutcontrols.go`源文件中的`InitializePageLayoutControls`函数中实例化和启动通知`cog`（以粗体显示）：

```go
func InitializePageLayoutControls(env *common.Env) {

 n := notify.NewNotify()
 err := n.Start()
 if err != nil {
 println("Error encountered when attempting to start the notify cog: ", err)
 }

  liveChatIcon := env.Document.GetElementByID("liveChatIcon").(*dom.HTMLImageElement)
  liveChatIcon.AddEventListener("click", false, func(event dom.Event) {

    chatbox := env.Document.GetElementByID("chatbox")
    if chatbox != nil {
      return
    }
    go chat.StartLiveChat(env)
  })

}
```

将添加商品到购物车的通知消息（成功或错误）放在`client/handlers/shoppingcart.go`源文件中的`addToCart`函数中：

```go
func addToCart(productSKU string) {

  m := make(map[string]string)
  m["productSKU"] = productSKU
  jsonData, _ := json.Marshal(m)

  data, err := xhr.Send("PUT", "/restapi/add-item-to-cart", jsonData)
  if err != nil {
    println("Encountered error: ", err)
    notify.Error("Failed to add item to cart!")
    return
  }
  var products []*models.Product
  json.NewDecoder(strings.NewReader(string(data))).Decode(&products)
  notify.Success("Item added to cart")
}
```

如果商品无法添加到购物车，则调用`notify.Error`函数（以粗体显示）。如果商品成功添加到购物车，则调用`notify.Success`函数（以粗体显示）。

从`client/handlers/shoppingcart.go`源文件中的`removeFromCart`函数中找到从购物车中移除商品的通知消息：

```go
func removeFromCart(env *common.Env, productSKU string) {

  m := make(map[string]string)
  m["productSKU"] = productSKU
  jsonData, _ := json.Marshal(m)

  data, err := xhr.Send("DELETE", "/restapi/remove-item-from-cart", jsonData)
  if err != nil {
    println("Encountered error: ", err)
    notify.Error("Failed to remove item from cart!")
    return
  }
  var products []*models.Product
  json.NewDecoder(strings.NewReader(string(data))).Decode(&products)
  renderShoppingCartItems(env)
  notify.Success("Item removed from cart")
}
```

如果商品无法从购物车中移除，则调用`notify.Error`函数（以粗体显示）。如果商品成功从购物车中移除，则调用`notify.Success`函数（以粗体显示）。

*图 9.14*是通知 cog 在操作时的裁剪截图，当我们向购物车中添加产品时：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/iso-go/img/6776f61a-1404-4129-8eb4-8815fef218c1.png)

图 9.14：通知 cog 在操作中

# 摘要

在本章中，我们介绍了 cogs——可重复使用的组件，可以纯粹使用 Go（纯 cogs）实现，也可以使用 Go 和 JavaScript（混合 cogs）实现。Cogs 带来了许多好处。我们可以以即插即用的方式使用它们，创建它们的多个实例，由于它们的自包含性质，可以轻松地维护它们，并且可以轻松地重用它们，因为它们可以作为自己的 Go 包以及它们所需的静态资产（模板文件、CSS 和 JavaScript 源文件）存在。

我们向您介绍了 UX 工具包，它为我们提供了实现 cogs 的技术。我们研究了 cog 的解剖结构，并探讨了关于 Go、CSS、JavaScript 和模板文件放置的 cog 文件结构可能是什么样子。我们考虑了 cogs 如何利用虚拟 DOM 来呈现其内容，而不是执行昂贵的替换内部 HTML 操作。我们介绍了 cog 生命周期的各个阶段。我们向您展示了如何在 IGWEB 中实现各种 cogs，其中包括纯 cogs 和混合 cogs。

在第十章中，*测试同构 Go Web 应用程序*，我们将学习如何对 IGWEB 进行自动化的端到端测试。这将包括实现测试来在服务器端和客户端上执行功能。
