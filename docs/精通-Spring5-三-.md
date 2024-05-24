# 精通 Spring5（三）

> 原文：[`zh.annas-archive.org/md5/73290E1F786F5BAA832E07A902070E3F`](https://zh.annas-archive.org/md5/73290E1F786F5BAA832E07A902070E3F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：扩展微服务

在第五章《使用 Spring Boot 构建微服务》中，我们构建了一个基本组件，提供了一些服务。在本章中，我们将重点放在添加更多功能，使我们的微服务能够投入生产。

我们将讨论如何将这些功能添加到我们的微服务中：

+   异常处理

+   HATEOAS

+   缓存

+   国际化

我们还将讨论如何使用 Swagger 文档化我们的微服务。我们将了解使用 Spring Security 保护微服务的基础知识。

# 异常处理

异常处理是开发 Web 服务的重要部分之一。当出现问题时，我们希望向服务使用者返回有关出现问题的良好描述。您不希望服务在不返回任何有用信息给服务使用者的情况下崩溃。

Spring Boot 提供了良好的默认异常处理。我们将从查看 Spring Boot 提供的默认异常处理功能开始，然后再进行自定义。

# Spring Boot 默认异常处理

为了了解 Spring Boot 提供的默认异常处理，让我们从向不存在的 URL 发送请求开始。

# 不存在的资源

让我们使用一个头部（Content-Type:application/json）向`http://localhost:8080/non-existing-resource`发送一个`GET`请求。

当我们执行请求时，下面的截图显示了响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/51cba3ab-d570-4eb9-a226-3c27456647af.png)

响应如下代码片段所示：

```java
    {
      "timestamp": 1484027734491,
      "status": 404,
      "error": "Not Found",
      "message": "No message available",
      "path": "/non-existing-resource"
    }
```

一些重要的事情需要注意：

+   响应头具有 HTTP 状态码`404 - 资源未找到`

+   Spring Boot 返回一个有效的 JSON；响应，其中说明资源未找到

# 资源抛出异常

让我们创建一个抛出异常的资源，并向其发送一个`GET`请求，以了解应用程序对运行时异常的反应。

让我们创建一个抛出异常的虚拟服务。下面的代码片段显示了一个简单的服务：

```java
    @GetMapping(path = "/users/dummy-service")
    public Todo errorService() {
      throw new RuntimeException("Some Exception Occured");
    }
```

一些重要的事情需要注意：

+   我们正在创建一个带有 URI `/users/dummy-service`的`GET`服务。

+   该服务抛出`RuntimeException`。我们选择了`RuntimeException`以便能够轻松创建异常。如果需要，我们可以轻松替换为自定义异常。

让我们使用 Postman 向前述服务发送一个`GET`请求，网址为`http://localhost:8080/users/dummy-service`。响应如下所示的代码：

```java
    {
      "timestamp": 1484028119553,
      "status": 500,
      "error": "Internal Server Error",
      "exception": "java.lang.RuntimeException",
      "message": "Some Exception Occured",
      "path": "/users/dummy-service"
   }
```

一些重要的事情需要注意：

+   响应头具有 HTTP 状态码`500`；`内部服务器错误`

+   Spring Boot 还返回抛出异常的消息

正如我们在前面的两个例子中所看到的，Spring Boot 提供了良好的默认异常处理。在下一节中，我们将重点关注应用程序对自定义异常的反应。

# 抛出自定义异常

让我们创建一个自定义异常，并从服务中抛出它。看一下下面的代码：

```java
    public class TodoNotFoundException extends RuntimeException {
      public TodoNotFoundException(String msg) {
        super(msg);
      }
    }
```

这是一个非常简单的代码片段，定义了`TodoNotFoundException`。

现在让我们增强我们的`TodoController`类，当找不到具有给定 ID 的`todo`时抛出`TodoNotFoundException`：

```java
    @GetMapping(path = "/users/{name}/todos/{id}")
    public Todo retrieveTodo(@PathVariable String name, 
    @PathVariable int id) {
      Todo todo = todoService.retrieveTodo(id);
      if (todo == null) {
        throw new TodoNotFoundException("Todo Not Found");
       }

     return todo;
    }
```

如果`todoService`返回一个空的`todo`，我们抛出`TodoNotFoundException`。

当我们向一个不存在的`todo`（`http://localhost:8080/users/Jack/todos/222`）发送一个`GET`请求时，我们得到了下面代码片段中显示的响应：

```java
    {
      "timestamp": 1484029048788,
      "status": 500,
      "error": "Internal Server Error",
      "exception":    
      "com.mastering.spring.springboot.bean.TodoNotFoundException",
      "message": "Todo Not Found",
      "path": "/users/Jack/todos/222"
    }
```

正如我们所看到的，清晰的异常响应被发送回服务使用者。然而，还有一件事情可以进一步改进——响应状态。当找不到资源时，建议返回`404 - 资源未找到`状态。我们将在下一个示例中看看如何自定义响应状态。

# 自定义异常消息

让我们看看如何自定义前面的异常并返回带有自定义消息的适当响应状态。

让我们创建一个 bean 来定义我们自定义异常消息的结构：

```java
    public class ExceptionResponse {
      private Date timestamp = new Date();
      private String message;
      private String details;

      public ExceptionResponse(String message, String details) {
        super();
        this.message = message;
        this.details = details;
       }

      public Date getTimestamp() {
        return timestamp;
      }

      public String getMessage() {
        return message;
      }

      public String getDetails() {
        return details;
      }
     }
```

我们已经创建了一个简单的异常响应 bean，其中包含自动填充的时间戳和一些额外属性，即消息和详细信息。

当抛出`TodoNotFoundException`时，我们希望使用`ExceptionResponse` bean 返回响应。以下代码显示了如何为`TodoNotFoundException.class`创建全局异常处理：

```java
    @ControllerAdvice
    @RestController
    public class RestResponseEntityExceptionHandler 
      extends  ResponseEntityExceptionHandler 
      {
        @ExceptionHandler(TodoNotFoundException.class)
        public final ResponseEntity<ExceptionResponse> 
        todoNotFound(TodoNotFoundException ex) {
           ExceptionResponse exceptionResponse = 
           new ExceptionResponse(  ex.getMessage(), 
           "Any details you would want to add");
           return new ResponseEntity<ExceptionResponse>
           (exceptionResponse, new HttpHeaders(), 
           HttpStatus.NOT_FOUND);
         }
     }
```

需要注意的一些重要事项如下：

+   `RestResponseEntityExceptionHandler 扩展 ResponseEntityExceptionHandler`：我们正在扩展`ResponseEntityExceptionHandler`，这是 Spring MVC 为中心化异常处理`ControllerAdvice`类提供的基类。

+   `@ExceptionHandler(TodoNotFoundException.class)`: 这定义了接下来要处理特定异常`TodoNotFoundException.class`的方法。任何其他未定义自定义异常处理的异常将遵循 Spring Boot 提供的默认异常处理。

+   `ExceptionResponse exceptionResponse = new ExceptionResponse(ex.getMessage(), "您想要添加的任何细节")`：这创建了一个自定义异常响应。

+   `new ResponseEntity<ExceptionResponse>(exceptionResponse,new HttpHeaders(), HttpStatus.NOT_FOUND)`: 这是返回`404 资源未找到`响应的定义，其中包括先前定义的自定义异常。

当我们使用`GET`请求执行服务到一个不存在的`todo`（`http://localhost:8080/users/Jack/todos/222`）时，我们会得到以下响应：

```java
    {
      "timestamp": 1484030343311,
      "message": "Todo Not Found",
      "details": "Any details you would want to add"
    }
```

如果要为所有异常创建通用异常消息，我们可以向`RestResponseEntityExceptionHandler`添加一个带有`@ExceptionHandler(Exception.class)`注解的方法。

以下代码片段显示了我们如何做到这一点：

```java
    @ExceptionHandler(Exception.class)
    public final ResponseEntity<ExceptionResponse> todoNotFound(
    Exception ex) {
       //Customize and return the response
    }
```

任何未定义自定义异常处理程序的异常将由前面的方法处理。

# 响应状态

在 REST 服务中要关注的重要事情之一是错误响应的响应状态。以下表格显示了要使用的场景和错误响应状态：

| **情况** | **响应状态** |
| --- | --- |
| 请求体不符合 API 规范。它没有足够的细节或包含验证错误。 | ;400 错误请求 |
| 认证或授权失败。 | 401 未经授权 |
| 用户由于各种因素无法执行操作，例如超出限制。 | 403 禁止 |
| 资源不存在。 | 404 未找到 |
| 不支持的操作，例如，在只允许`GET`的资源上尝试 POST。; | 405 方法不允许 |
| 服务器上的错误。理想情况下，这不应该发生。消费者将无法修复这个问题。; | 500 内部服务器错误 |

在这一部分，我们看了 Spring Boot 提供的默认异常处理以及我们如何进一步定制以满足我们的需求。

# HATEOAS

**HATEOAS**（**超媒体作为应用状态的引擎**）是 REST 应用程序架构的约束之一。

让我们考虑一种情况，即服务消费者从服务提供者那里消费大量服务。开发这种类型的系统的最简单方法是让服务消费者存储他们从服务提供者那里需要的每个资源的资源 URI。然而，这将在服务提供者和服务消费者之间创建紧密耦合。每当服务提供者上的任何资源 URI 发生变化时，服务消费者都需要进行更新。

考虑一个典型的 Web 应用程序。假设我导航到我的银行账户详情页面。几乎所有银行网站都会在屏幕上显示我在银行账户上可以进行的所有交易的链接，以便我可以通过链接轻松导航。

如果我们可以将类似的概念引入 RESTful 服务，使得服务不仅返回有关请求资源的数据，还提供其他相关资源的详细信息，会怎么样？

HATEOAS 将这个概念引入了 RESTful 服务中，即为给定的资源显示相关链接。当我们返回特定资源的详细信息时，我们还返回可以对该资源执行的操作的链接，以及相关资源的链接。如果服务消费者可以使用响应中的链接执行事务，那么它就不需要硬编码所有链接。

Roy Fielding（[`roy.gbiv.com/untangled/2008/rest-apis-must-be-hypertext-driven`](http://roy.gbiv.com/untangled/2008/rest-apis-must-be-hypertext-driven)）提出的与 HATEOAS 相关的约束摘录如下：

<q>REST API 不得定义固定的资源名称或层次结构（客户端和服务器的明显耦合）。服务器必须有自由控制自己的命名空间。相反，允许服务器指示客户端如何构造适当的 URI，例如在 HTML 表单和 URI 模板中所做的那样，通过在媒体类型和链接关系中定义这些指令。</q> REST API 应该在没有先前知识的情况下进入（书签）和一组适用于预期受众的标准化媒体类型（即，预计任何可能使用 API 的客户端都能理解）。从那时起，所有应用程序状态转换必须由客户端选择接收到的表示中存在的服务器提供的选择来驱动，或者由用户对这些表示的操作所暗示。转换可以由客户端对媒体类型和资源通信机制的知识确定（或受限于），这两者都可以即时改进（例如，按需代码）。

这里显示了一个带有 HATEOAS 链接的示例响应。这是对`/todos`请求的响应，以便检索所有 todos：

```java
    {
      "_embedded" : {
        "todos" : [ {
          "user" : "Jill",
          "desc" : "Learn Hibernate",
          "done" : false,
         "_links" : {
          "self" : {
                 "href" : "http://localhost:8080/todos/1"
                 },
          "todo" : {
                 "href" : "http://localhost:8080/todos/1"
                  }
            }
     } ]
    },
     "_links" : {
     "self" : {
              "href" : "http://localhost:8080/todos"
              },
     "profile" : {
              "href" : "http://localhost:8080/profile/todos"
              },
     "search" : {
              "href" : "http://localhost:8080/todos/search"
              }
       },
     }
```

上述响应包括以下链接：

+   特定的`todos`(`http://localhost:8080/todos/1`)

+   搜索资源(`http://localhost:8080/todos/search`)

如果服务消费者想要进行搜索，它可以选择从响应中获取搜索 URL 并将搜索请求发送到该 URL。这将减少服务提供者和服务消费者之间的耦合。

# 在响应中发送 HATEOAS 链接

现在我们了解了 HATEOAS 是什么，让我们看看如何在响应中发送与资源相关的链接。

# Spring Boot starter HATEOAS

Spring Boot 有一个专门的 HATEOAS 启动器，称为`spring-boot-starter-hateoas`。我们需要将其添加到`pom.xml`文件中。

以下代码片段显示了依赖块：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-hateoas</artifactId>
    </dependency>
```

`spring-boot-starter-hateoas`的一个重要依赖是`spring-hateoas`，它提供了 HATEOAS 功能：

```java
    <dependency>
      <groupId>org.springframework.hateoas</groupId>
      <artifactId>spring-hateoas</artifactId>
    </dependency>
```

让我们增强`retrieveTodo`资源(`/users/{name}/todos/{id}`)以在响应中返回检索所有`todos`(`/users/{name}/todos`)的链接：

```java
    @GetMapping(path = "/users/{name}/todos/{id}")
    public Resource<Todo> retrieveTodo(
    @PathVariable String name, @PathVariable int id) {
    Todo todo = todoService.retrieveTodo(id);
      if (todo == null) {
           throw new TodoNotFoundException("Todo Not Found");
        }

     Resource<Todo> todoResource = new Resource<Todo>(todo);
     ControllerLinkBuilder linkTo = 
     linkTo(methodOn(this.getClass()).retrieveTodos(name));
     todoResource.add(linkTo.withRel("parent"));

     return todoResource;
    }
```

需要注意的一些重要点如下：

+   `ControllerLinkBuilder linkTo = linkTo(methodOn(this.getClass()).retrieveTodos(name))`：我们想要获取当前类中`retrieveTodos`方法的链接

+   `linkTo.withRel("parent")`：当前资源的关系是 parent

以下片段显示了向`http://localhost:8080/users/Jack/todos/1`发送`GET`请求时的响应：

```java
   {
     "id": 1,
     "user": "Jack",
     "desc": "Learn Spring MVC",
     "targetDate": 1484038262110,
     "done": false,
     "_links": {
               "parent": {
               "href": "http://localhost:8080/users/Jack/todos"
               }
        }
   }
```

`_links`部分将包含所有链接。目前，我们有一个带有关系 parent 和`href`为`http://localhost:8080/users/Jack/todos`的链接。

如果您在执行上述请求时遇到问题，请尝试使用 Accept 标头--`application/json`。

HATEOAS 并不是今天大多数资源中常用的东西。然而，它有潜力在服务提供者和消费者之间减少耦合。

# 验证

一个好的服务在处理数据之前总是验证数据。在本节中，我们将研究 Bean Validation API，并使用其参考实现来在我们的服务中实现验证。

Bean Validation API 提供了许多注释，可用于验证 bean。*JSR 349*规范定义了 Bean Validation API 1.1。Hibernate-validator 是参考实现。两者已经在`spring-boot-web-starter`项目中定义为依赖项：

+   `hibernate-validator-5.2.4.Final.jar`

+   `validation-api-1.1.0.Final.jar`

我们将为 createTodo 服务方法创建一个简单的验证。

创建验证包括两个步骤：

1.  在控制器方法上启用验证。

1.  在 bean 上添加验证。

# 在控制器方法上启用验证

在控制器方法上启用验证非常简单。以下代码片段显示了一个示例：

```java
    @RequestMapping(method = RequestMethod.POST, 
    path = "/users/{name}/todos")
    ResponseEntity<?> add(@PathVariable String name
    @Valid @RequestBody Todo todo) {
```

`@Valid（包 javax.validation）`注释用于标记要验证的参数。在执行`add`方法之前，将执行`Todo` bean 中定义的任何验证。

# 在 bean 上定义验证

让我们在`Todo` bean 上定义一些验证：

```java
   public class Todo {
     private int id; 

     @NotNull
     private String user;

     @Size(min = 9, message = "Enter atleast 10 Characters.")
     private String desc;
```

需要注意的一些重要点如下：

+   `@NotNull`：验证用户字段不为空

+   `@Size(min = 9, message = "Enter atleast 10 Characters.")`：检查`desc`字段是否至少有九个字符。

还有许多其他注释可用于验证 bean。以下是一些 Bean Validation 注释：

+   `@AssertFalse`，`@AssertTrue`：对于布尔元素。检查被注释的元素。

+   `@AssertFalse`：检查是否为 false。`@Assert`检查是否为 true。

+   `@Future`：被注释的元素必须是将来的日期。

+   `@Past`：被注释的元素必须是过去的日期。

+   `@Max`：被注释的元素必须是一个数字，其值必须小于或等于指定的最大值。

+   `@Min`：被注释的元素必须是一个数字，其值必须大于或等于指定的最小值。

+   `@NotNull`：被注释的元素不能为空。

+   `@Pattern`：被注释的`{@code CharSequence}`元素必须与指定的正则表达式匹配。正则表达式遵循 Java 正则表达式约定。

+   `@Size`：被注释的元素大小必须在指定的边界内。

# 单元测试验证

以下示例显示了如何对我们添加的验证进行单元测试：

```java
     @Test
     public void createTodo_withValidationError() throws Exception {
       Todo mockTodo = new Todo(CREATED_TODO_ID, "Jack", 
       "Learn Spring MVC", new Date(), false);

       String todo = "{"user":"Jack","desc":"Learn","done":false}";

       when( service.addTodo(
         anyString(), anyString(), isNull(), anyBoolean()))
        .thenReturn(mockTodo);

         MvcResult result = mvc.perform(
         MockMvcRequestBuilders.post("/users/Jack/todos")
        .content(todo)
        .contentType(MediaType.APPLICATION_JSON))
        .andExpect(
           status().is4xxClientError()).andReturn();
     }
```

需要注意的一些重要点如下：

+   `"desc":"Learn"`：我们使用长度为`5`的 desc 值。这将导致`@Size(min = 9, message = "Enter atleast 10 Characters.")`检查失败。

+   `.andExpect(status().is4xxClientError())`：检查验证错误状态。

# REST 服务文档

在服务提供者可以使用服务之前，他们需要一个服务合同。服务合同定义了有关服务的所有细节：

+   我如何调用服务？服务的 URI 是什么？

+   请求格式应该是什么？

+   我应该期望什么样的响应？

有多种选项可用于为 RESTful 服务定义服务合同。在过去几年中最受欢迎的是**Swagger**。Swagger 在过去几年中得到了很多支持，得到了主要供应商的支持。在本节中，我们将为我们的服务生成 Swagger 文档。

来自 Swagger 网站（[`swagger.io`](http://swagger.io)）的以下引用定义了 Swagger 规范的目的：

Swagger 规范为您的 API 创建 RESTful 合同，详细说明了所有资源和操作，以人类和机器可读的格式进行易于开发、发现和集成。

# 生成 Swagger 规范

RESTful 服务开发在过去几年中的一个有趣发展是工具的演变，可以从代码生成服务文档（规范）。这确保了代码和文档始终保持同步。

**Springfox Swagger**可以用来从 RESTful 服务代码生成 Swagger 文档。此外，还有一个名为**Swagger UI**的精彩工具，当集成到应用程序中时，提供人类可读的文档。

以下代码片段显示了如何将这两个工具添加到`pom.xml`文件中：

```java
    <dependency>
     <groupId>io.springfox</groupId>
     <artifactId>springfox-swagger2</artifactId>
     <version>2.4.0</version>
    </dependency>

    <dependency>
     <groupId>io.springfox</groupId>
     <artifactId>springfox-swagger-ui</artifactId>
     <version>2.4.0</version>
    </dependency>
```

下一步是添加配置类以启用和生成 Swagger 文档。以下代码片段显示了如何做到这一点：

```java
    @Configuration
    @EnableSwagger2
    public class SwaggerConfig {
      @Bean
      public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
        .select()
        .apis(RequestHandlerSelectors.any())
        .paths(PathSelectors.any()).build();
      }
    }
```

需要注意的一些重要点如下：

+   `@Configuration`：定义一个 Spring 配置文件

+   `@EnableSwagger2`：启用 Swagger 支持的注解

+   `Docket`：一个简单的构建器类，用于使用 Swagger Spring MVC 框架配置 Swagger 文档的生成

+   `new Docket(DocumentationType.SWAGGER_2)`：配置 Swagger 2 作为要使用的 Swagger 版本

+   `.apis(RequestHandlerSelectors.any()).paths(PathSelectors.any())`：包括文档中的所有 API 和路径

当我们启动服务器时，我们可以启动 API 文档 URL（`http://localhost:8080/v2/api-docs`）。以下截图显示了一些生成的文档：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/dfce5d48-ef55-4393-9a25-e6c695125f13.png)

让我们来看一些生成的文档。这里列出了检索`todos`服务的文档：

```java
    "/users/{name}/todos": {
      "get": {
      "tags": [
             "todo-controller"
             ],
      "summary": "retrieveTodos",
      "operationId": "retrieveTodosUsingGET",
      "consumes": [
               "application/json"
               ],
      "produces": [
               "*/*"
               ],
      "parameters": [
              {
                "name": "name",
                "in": "path",
                "description": "name",
                "required": true,
                "type": "string"
              }
             ],
       "responses": {
       "200": {
              "description": "OK",
              "schema": {
                      "type": "array",
                      items": {
                          "$ref": "#/definitions/Todo"
                        }
                       }
               },
       "401": {
                "description": "Unauthorized"
               },
       "403": {
                "description": "Forbidden"
              },
       "404": {
                "description": "Not Found"
              } 
        }
     }
```

服务定义清楚地定义了服务的请求和响应。还定义了服务在不同情况下可以返回的不同响应状态。

以下代码片段显示了`Todo` bean 的定义：

```java
    "Resource«Todo»": {
      "type": "object",
      "properties": {
      "desc": {
               "type": "string"
             },
     "done": {
               "type": "boolean"
             },
     "id": {
              "type": "integer",
              "format": "int32"
           },
     "links": {
              "type": "array",
              "items": {
                         "$ref": "#/definitions/Link"
                       }
              },
     "targetDate": {
                    "type": "string",
                    "format": "date-time"
                },
     "user": {
              "type": "string"
            }
        }
      }
```

它定义了`Todo` bean 中的所有元素，以及它们的格式。

# Swagger UI

Swagger UI（`http://localhost:8080/swagger-ui.html`）也可以用来查看文档。Swagger UI 是通过在上一步中添加到我们的`pom.xml`中的依赖项（`io.springfox:springfox-swagger-ui`）启用的。

Swagger UI（[`petstore.swagger.io`](http://petstore.swagger.io)）也可以在线使用。我们可以使用 Swagger UI 可视化任何 Swagger 文档（swagger JSON）。

以下截图显示了公开控制器服务的列表。当我们点击任何控制器时，它会展开显示每个控制器支持的请求方法和 URI 列表：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/3c9a0fb3-d07a-4b93-8a02-50c3d01812f7.png)

以下截图显示了在 Swagger UI 中为创建用户的`todo`服务的 POST 服务的详细信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/c29b7ef2-eb45-4e26-9310-cfb09e9f0950.png)

需要注意的一些重要事项如下：

+   参数显示了所有重要的参数，包括请求体

+   参数类型 body（对于`todo`参数）显示了请求体的预期结构

+   响应消息部分显示了服务返回的不同 HTTP 状态代码

Swagger UI 提供了一种出色的方式来在不需要太多额外工作的情况下公开 API 的服务定义。

# 使用注解自定义 Swagger 文档

Swagger UI 还提供了注解来进一步自定义您的文档。

这里列出了检索`todos`服务的一些文档：

```java
    "/users/{name}/todos": {
      "get": {
      "tags": [
             "todo-controller"
             ],
      "summary": "retrieveTodos",
      "operationId": "retrieveTodosUsingGET",
      "consumes": [
               "application/json"
               ],
      "produces": [
                "*/*"
               ],
```

如您所见，生成的文档非常原始。我们可以在文档中改进许多内容，以更好地描述服务。以下是一些示例：

+   提供更好的摘要

+   添加 application/JSON 到 produces

Swagger 提供了我们可以添加到我们的 RESTful 服务中的注解，以自定义文档。让我们在控制器中添加一些注解以改进文档：

```java
    @ApiOperation(
      value = "Retrieve all todos for a user by passing in his name", 
      notes = "A list of matching todos is returned. Current pagination   
      is not supported.",
      response = Todo.class, 
      responseContainer = "List", 
      produces = "application/json")
      @GetMapping("/users/{name}/todos")
      public List<Todo> retrieveTodos(@PathVariable String name) {
        return todoService.retrieveTodos(name);
     }
```

需要注意的几个重要点如下：

+   `@ApiOperation(value = "Retrieve all todos for a user by passing in his name")`：在文档中作为服务摘要生成

+   `notes = "A list of matching todos is returned. Current pagination is not supported."`：在文档中生成作为服务描述的说明

+   `produces = "application/json”`：自定义服务文档的`produces`部分

以下是更新后的文档摘录：

```java
    get": {
         "tags": [
                   "todo-controller"
                 ],
         "summary": "Retrieve all todos for a user by passing in his 
          name",
         "description": "A list of matching todos is returned. Current 
          pagination is not supported.",
         "operationId": "retrieveTodosUsingGET",
         "consumes": [
                     "application/json"
                   ],
         "produces": [
                     "application/json",
                     "*/*"
                   ],
```

Swagger 提供了许多其他注解来自定义文档。以下列出了一些重要的注解：

+   `@Api`：将类标记为 Swagger 资源

+   `@ApiModel`：提供有关 Swagger 模型的附加信息

+   `@ApiModelProperty`：添加和操作模型属性的数据

+   `@ApiOperation`：描述针对特定路径的操作或 HTTP 方法

+   `@ApiParam`：为操作参数添加附加元数据

+   `@ApiResponse`：描述操作的示例响应

+   `@ApiResponses`：允许多个`ApiResponse`对象的列表包装器。

+   `@Authorization`：声明要在资源或操作上使用的授权方案

+   `@AuthorizationScope`：描述 OAuth 2 授权范围

+   `@ResponseHeader`：表示可以作为响应的一部分提供的标头

Swagger 提供了一些 Swagger 定义注解，可以用来自定义有关一组服务的高级信息--联系人、许可和其他一般信息。以下是一些重要的注解：

+   `@SwaggerDefinition`：要添加到生成的 Swagger 定义的定义级属性

+   `@Info`：Swagger 定义的一般元数据

+   `@Contact`：用于描述 Swagger 定义的联系人的属性

+   `@License`：用于描述 Swagger 定义的许可证的属性

# 使用 Spring Security 保护 REST 服务

到目前为止，我们创建的所有服务都是不安全的。消费者不需要提供任何凭据即可访问这些服务。然而，在现实世界中，所有服务通常都是受保护的。

在本节中，我们将讨论验证 REST 服务的两种方式：

+   基本身份验证

+   OAuth 2.0 身份验证

我们将使用 Spring Security 实现这两种类型的身份验证。

Spring Boot 提供了一个用于 Spring Security 的启动器；`spring-boot-starter-security`。我们将从向我们的`pom.xml`文件中添加 Spring Security 启动器开始。

# 添加 Spring Security 启动器

将以下依赖项添加到您的文件`pom.xml`中：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
```

`Spring-boot-starter-security`依赖项；引入了三个重要的 Spring Security 依赖项：

+   `spring-security-config`

+   `spring-security-core`

+   `spring-security-web`

# 基本身份验证

`Spring-boot-starter-security`依赖项；还默认为所有服务自动配置基本身份验证。

如果我们现在尝试访问任何服务，我们将收到`"拒绝访问"`的消息。

当我们发送请求到`http://localhost:8080/users/Jack/todos`时的响应如下代码片段中所示：

```java
    {
      "timestamp": 1484120815039,
      "status": 401,
      "error": "Unauthorized",
      "message": "Full authentication is required to access this 
       resource",
       "path": "/users/Jack/todos"
    }
```

响应状态为`401 - 未经授权`。

当资源受基本身份验证保护时，我们需要发送用户 ID 和密码来验证我们的请求。由于我们没有配置用户 ID 和密码，Spring Boot 会自动配置默认的用户 ID 和密码。默认用户 ID 是`user`。默认密码通常会打印在日志中。

以下代码片段中显示了一个示例：

```java
2017-01-11 13:11:58.696 INFO 3888 --- [ restartedMain] b.a.s.AuthenticationManagerConfiguration :

Using default security password: 3fb5564a-ce53-4138-9911-8ade17b2f478

2017-01-11 13:11:58.771 INFO 3888 --- [ restartedMain] o.s.s.web.DefaultSecurityFilterChain : Creating filter chain: Ant [pattern='/css/**'], []
```

在上述代码片段中划线的是日志中打印的默认安全密码。

我们可以使用 Postman 发送带有基本身份验证的请求。以下截图显示了如何在请求中发送基本身份验证详细信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/579ca5d7-bcc6-4814-8079-65b2b715a312.png)

正如你所看到的，身份验证成功，我们得到了一个适当的响应。

我们可以在`application.properties`中配置我们选择的用户 ID 和密码，如下所示：

```java
   security.user.name=user-name
   security.user.password=user-password
```

Spring Security 还提供了使用 LDAP 或 JDBC 或任何其他数据源进行用户凭据身份验证的选项。

# 集成测试

我们之前为服务编写的集成测试将因为无效的凭据而开始失败。我们现在将更新集成测试以提供基本身份验证凭据：

```java
    private TestRestTemplate template = new TestRestTemplate();
    HttpHeaders headers = createHeaders("user-name", "user-password");

    HttpHeaders createHeaders(String username, String password) {
      return new HttpHeaders() {
       {
         String auth = username + ":" + password;
         byte[] encodedAuth = Base64.getEncoder().encode
         (auth.getBytes(Charset.forName("US-ASCII")));
         String authHeader = "Basic " + new String(encodedAuth);
         set("Authorization", authHeader);
        }
      };
     }

    @Test
    public void retrieveTodos() throws Exception {
      String expected = "["
      + "{id:1,user:Jack,desc:\"Learn Spring MVC\",done:false}" + ","
      + "{id:2,user:Jack,desc:\"Learn Struts\",done:false}" + "]";
      ResponseEntity<String> response = template.exchange(
      createUrl("/users/Jack/todos"), HttpMethod.GET,
      new HttpEntity<String>(null, headers),
      String.class);
      JSONAssert.assertEquals(expected, response.getBody(), false);
    }
```

需要注意的一些重要事项如下：

+   `createHeaders("user-name", "user-password")`：此方法创建`Base64\. getEncoder().encode`基本身份验证标头

+   `ResponseEntity<String> response = template.exchange(createUrl("/users/Jack/todos"), ;HttpMethod.GET,new HttpEntity<String>(null, headers), String.class)`: 关键变化是使用`HttpEntity`来提供我们之前创建的标头给 REST 模板

# 单元测试

我们不希望在单元测试中使用安全性。以下代码片段显示了如何在单元测试中禁用安全性：

```java
   @RunWith(SpringRunner.class)
   @WebMvcTest(value = TodoController.class, secure = false)
   public class TodoControllerTest {
```

关键部分是`WebMvcTest`注解上的`secure = false`参数。这将禁用单元测试的 Spring Security。

# OAuth 2 认证

OAuth 是一种协议，提供了一系列流程，用于在各种网络应用程序和服务之间交换授权和认证信息。它使第三方应用程序能够从服务中获取对用户信息的受限访问权限，例如 Facebook、Twitter 或 GitHub。

在深入细节之前，回顾一下通常与 OAuth 2 认证相关的术语将会很有用。

让我们考虑一个例子。假设我们想要将 Todo API 暴露给互联网上的第三方应用程序。

以下是典型 OAuth 2 交换中的重要参与者：

+   **资源所有者**：这是第三方应用程序的用户，希望使用我们的 Todo API。它决定我们的 API 中的信息可以向第三方应用程序提供多少。

+   **资源服务器**：托管 Todo API，我们想要保护的资源。

+   **客户端**：这是希望使用我们的 API 的第三方应用程序。

+   **授权服务器**：提供 OAuth 服务的服务器。

# 高级流程

以下步骤展示了典型 OAuth 认证的高级流程：

1.  应用程序请求用户授权访问 API 资源。

1.  当用户提供访问权限时，应用程序会收到授权授予。

1.  应用程序提供用户授权授予和自己的客户端凭据给授权服务器。

1.  如果认证成功，授权服务器将以访问令牌回复。

1.  应用程序调用提供认证访问令牌的 API（资源服务器）。

1.  如果访问令牌有效，资源服务器返回资源的详细信息。

# 为我们的服务实现 OAuth 2 认证

Spring Security 的 OAuth 2（`spring-security-oauth2`）是为 Spring Security 提供 OAuth 2 支持的模块。我们将在`pom.xml`文件中将其添加为依赖项：

```java
    <dependency>
      <groupId>org.springframework.security.oauth</groupId>
      <artifactId>spring-security-oauth2</artifactId>
    </dependency>
```

# 设置授权和资源服务器

spring-security-oauth2 截至 2017 年 6 月尚未更新以适应 Spring Framework 5.x 和 Spring Boot 2.x 的变化。我们将使用 Spring Boot 1.5.x 来举例说明 OAuth 2 认证。代码示例在 GitHub 存储库中；[`github.com/PacktPublishing/Mastering-Spring-5.0`](https://github.com/PacktPublishing/Mastering-Spring-5.0)。

通常，授权服务器会是一个不同的服务器，而不是 API 暴露的应用程序。为了简化，我们将使当前的 API 服务器同时充当资源服务器和授权服务器。

以下代码片段显示了如何使我们的应用程序充当资源和授权服务器：

```java
   @EnableResourceServer
   @EnableAuthorizationServer
   @SpringBootApplication
   public class Application {
```

以下是一些重要的事项：

+   `@EnableResourceServer`：OAuth 2 资源服务器的便利注解，启用 Spring Security 过滤器，通过传入的 OAuth 2 令牌对请求进行身份验证

+   `@EnableAuthorizationServer`：一个便利注解，用于在当前应用程序上下文中启用授权服务器，必须是`DispatcherServlet`上下文，包括`AuthorizationEndpoint`和`TokenEndpoint`

现在我们可以在`application.properties`中配置访问详情，如下所示：

```java
    security.user.name=user-name
    security.user.password=user-password
    security.oauth2.client.clientId: clientId
    security.oauth2.client.clientSecret: clientSecret
    security.oauth2.client.authorized-grant-types:     
    authorization_code,refresh_token,password
    security.oauth2.client.scope: openid
```

一些重要的细节如下：

+   `security.user.name`和`security.user.password`是资源所有者的身份验证详细信息，是第三方应用程序的最终用户

+   `security.oauth2.client.clientId`和`security.oauth2.client.clientSecret`是客户端的身份验证详细信息，是第三方应用程序（服务消费者）

# 执行 OAuth 请求

我们需要一个两步骤的过程来访问 API：

1.  获取访问令牌。

1.  使用访问令牌执行请求。

# 获取访问令牌

要获取访问令牌，我们调用授权服务器（`http://localhost:8080/oauth/token`），在基本身份验证模式下提供客户端身份验证详细信息和用户凭据作为表单数据的一部分。以下截图显示了我们如何在基本身份验证中配置客户端身份验证详细信息：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/d5c2d818-4bee-47bc-a05f-73b94568d12d.png)

以下截图显示了如何将用户身份验证详细信息配置为 POST 参数的一部分：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/7bf1640a-be2f-4728-993b-9869b1f095bc.png)

我们使用`grant_type`作为密码，表示我们正在发送用户身份验证详细信息以获取访问令牌。当我们执行请求时，我们会得到类似以下代码片段所示的响应：

```java
    {
      "access_token": "a633dd55-102f-4f53-bcbd-a857df54b821",
      "token_type": "bearer",
      "refresh_token": "d68d89ec-0a13-4224-a29b-e9056768c7f0",
      "expires_in": 43199,
      "scope": "openid"
    }
```

以下是一些重要细节：

+   `access_token`: 客户端应用程序可以使用访问令牌来进行进一步的 API 调用身份验证。然而，访问令牌将在通常非常短的时间内过期。

+   `refresh_token`: 客户端应用程序可以使用`refresh_token`向认证服务器提交新请求，以获取新的`access_token`。

# 使用访问令牌执行请求

一旦我们有了`access_token`，我们可以使用`access_token`执行请求，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/c549b7c3-2c0e-41ec-bf28-57580a2d3173.png)

正如您在前面的截图中所看到的，我们在请求标头中提供了访问令牌，称为 Authorization。我们使用格式的值`"Bearer {access_token}"`。身份验证成功，我们得到了预期的资源详细信息。

# 集成测试

现在我们将更新我们的集成测试以提供 OAuth 2 凭据。以下测试突出了重要细节：

```java
    @Test
    public void retrieveTodos() throws Exception {
      String expected = "["
      + "{id:1,user:Jack,desc:\"Learn Spring MVC\",done:false}" + ","
      +"{id:2,user:Jack,desc:\"Learn Struts\",done:false}" + "]";
      String uri = "/users/Jack/todos";
      ResourceOwnerPasswordResourceDetails resource = 
      new ResourceOwnerPasswordResourceDetails();
      resource.setUsername("user-name");
      resource.setPassword("user-password");
      resource.setAccessTokenUri(createUrl("/oauth/token"));
      resource.setClientId("clientId");
      resource.setClientSecret("clientSecret");
      resource.setGrantType("password");
      OAuth2RestTemplate oauthTemplate = new 
      OAuth2RestTemplate(resource,new 
      DefaultOAuth2ClientContext());
      ResponseEntity<String> response = 
      oauthTemplate.getForEntity(createUrl(uri), String.class);
     JSONAssert.assertEquals(expected, response.getBody(), false);
    }
```

一些重要的事项如下：

+   `ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails()`: 我们使用用户凭据和客户端凭据设置了`ResourceOwnerPasswordResourceDetails`

+   `resource.setAccessTokenUri(createUrl("/oauth/token"))`: 配置认证服务器的 URL

+   `OAuth2RestTemplate oauthTemplate = new OAuth2RestTemplate(resource,new DefaultOAuth2ClientContext())`: `OAuth2RestTemplate`是`RestTemplate`的扩展，支持 OAuth 2 协议

在本节中，我们看了如何在资源中启用 OAuth 2 身份验证。

# 国际化

**国际化**（**i18n**）是开发应用程序和服务的过程，使它们可以为世界各地的不同语言和文化进行定制。它也被称为**本地化**。国际化或本地化的目标是构建可以以多种语言和格式提供内容的应用程序。

Spring Boot 内置支持国际化。

让我们构建一个简单的服务，以了解如何在我们的 API 中构建国际化。

我们需要向我们的 Spring Boot 应用程序添加`LocaleResolver`和消息源。以下代码片段应包含在`Application.java`中：

```java
    @Bean
    public LocaleResolver localeResolver() {
      SessionLocaleResolver sessionLocaleResolver = 
      new SessionLocaleResolver();
      sessionLocaleResolver.setDefaultLocale(Locale.US);
      return sessionLocaleResolver;
    }

   @Bean
   public ResourceBundleMessageSource messageSource() {
     ResourceBundleMessageSource messageSource = 
     new ResourceBundleMessageSource();
     messageSource.setBasenames("messages");
     messageSource.setUseCodeAsDefaultMessage(true);
    return messageSource;
   }
```

一些重要的事项如下：

+   `sessionLocaleResolver.setDefaultLocale(Locale.US)`: 我们设置了`Locale.US`的默认区域设置。

+   `messageSource.setBasenames("messages")`: 我们将消息源的基本名称设置为`messages`。如果我们处于 fr 区域设置（法国），我们将使用`message_fr.properties`中的消息。如果在`message_fr.properties`中找不到消息，则将在默认的`message.properties`中搜索。

+   `messageSource.setUseCodeAsDefaultMessage(true)`: 如果未找到消息，则将代码作为默认消息返回。

让我们配置各自文件中的消息。让我们从`messages`属性开始。该文件中的消息将作为默认消息：

```java
    welcome.message=Welcome in English
```

让我们也配置`messages_fr.properties`。该文件中的消息将用于区域设置。如果此处不存在消息，则将使用`messages.properties`中的默认消息：

```java
   welcome.message=Welcome in French
```

让我们创建一个服务，根据`"Accept-Language"`头中指定的区域设置返回特定消息：

```java
    @GetMapping("/welcome-internationalized")
    public String msg(@RequestHeader(value = "Accept-Language", 
    required = false) Locale locale) {
      return messageSource.getMessage("welcome.message", null, 
      locale);
    }
```

以下是需要注意的几点：

+   `@RequestHeader(value = "Accept-Language", required = false) Locale locale`：区域设置从请求头`Accept-Language`中获取。不是必需的。如果未指定区域设置，则使用默认区域设置。

+   `messageSource.getMessage("welcome.message", null, locale)`: `messageSource`被自动装配到控制器中。我们根据给定的区域设置获取欢迎消息。

以下屏幕截图显示了在不指定默认`Accept-Language`时调用前面的服务时的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/c66a5e37-0172-4460-a7d3-c17a862ae5ea.png)

从`messages.properties`返回默认消息。

以下屏幕截图显示了在使用`Accept-Language fr`调用前面的服务时的响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/6da4bb0b-3be3-4efd-bd29-0f7aee72b0a5.png)

从`messages_fr.properties`返回本地化消息。

在前面的示例中，我们定制了服务，根据请求中的区域设置返回本地化消息。类似的方法可以用于国际化组件中的所有服务。

# 缓存

从服务中缓存数据在提高应用程序性能和可扩展性方面起着至关重要的作用。在本节中，我们将看一下 Spring Boot 提供的实现选项。

Spring 提供了基于注解的缓存抽象。我们将首先使用 Spring 缓存注解。稍后，我们将介绍*JSR-107*缓存注解，并将它们与 Spring 抽象进行比较。

# Spring-boot-starter-cache

Spring Boot 为缓存提供了一个启动器项目`spring-boot-starter-cache`。将其添加到应用程序中会引入所有依赖项，以启用*JSR-107*和 Spring 缓存注解。以下代码片段显示了`spring-boot-starter-cache`的依赖项详细信息。让我们将其添加到我们的文件`pom.xml`中：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-cache</artifactId>
    </dependency>
```

# 启用缓存

在我们开始使用缓存之前，我们需要在应用程序上启用缓存。以下代码片段显示了如何启用缓存：

```java
    @EnableCaching
    @SpringBootApplication
    public class Application {
```

`@EnableCaching`将在 Spring Boot 应用程序中启用缓存。

Spring Boot 会自动配置适当的 CacheManager 框架，作为相关缓存的提供者。稍后我们将详细了解 Spring Boot 如何决定 CacheManager。

# 缓存数据

现在我们已经启用了缓存，我们可以在希望缓存数据的方法上添加`@Cacheable`注解。以下代码片段显示了如何在`retrieveTodos`上启用缓存：

```java
    @Cacheable("todos")
    public List<Todo> retrieveTodos(String user) {
```

在前面的示例中，特定用户的`todos`被缓存。对于特定用户的方法的第一次调用，`todos`将从服务中检索。对于相同用户的后续调用，数据将从缓存中返回。

Spring 还提供了有条件的缓存。在以下代码片段中，仅当满足指定条件时才启用缓存：

```java
    @Cacheable(cacheNames="todos", condition="#user.length < 10”)
    public List<Todo> retrieveTodos(String user) {
```

Spring 还提供了额外的注解来从缓存中清除数据并向缓存中添加一些自定义数据。一些重要的注解如下所示：

+   `@CachePut`：用于显式向缓存中添加数据

+   `@CacheEvict`：用于从缓存中删除过期数据

+   `@Caching`：允许在同一个方法上使用多个嵌套的`@Cacheable`、`@CachePut`和`@CacheEvict`注解

# JSR-107 缓存注解

*JSR-107*旨在标准化缓存注解。以下是一些重要的*JSR-107*注解：

+   `@CacheResult`：类似于`@Cacheable`

+   `@CacheRemove`：类似于`@CacheEvict`；如果发生异常，`@CacheRemove`支持有条件的驱逐

+   `@CacheRemoveAll`：类似于`@CacheEvict(allEntries=true)`；用于从缓存中移除所有条目

*JSR-107*和 Spring 的缓存注解在提供的功能方面非常相似。它们中的任何一个都是一个不错的选择。我们稍微倾向于*JSR-107*，因为它是一个标准。但是，请确保在同一个项目中不要同时使用两者。

# 自动检测顺序

启用缓存时，Spring Boot 自动配置开始寻找缓存提供程序。以下列表显示了 Spring Boot 搜索缓存提供程序的顺序。列表按优先级递减的顺序排列：

+   JCache（*JSR-107*）（EhCache 3、Hazelcast、Infinispan 等）

+   EhCache 2.x

+   Hazelcast

+   Infinispan

+   Couchbase

+   Redis

+   Caffeine

+   Guava

+   Simple

# 摘要

Spring Boot 使得开发基于 Spring 的应用变得简单。它使我们能够非常快速地创建生产就绪的应用程序。

在本章中，我们介绍了如何向我们的应用程序添加异常处理、缓存和国际化等功能。我们讨论了使用 Swagger 记录 REST 服务的最佳实践。我们了解了如何使用 Spring Security 保护我们的微服务的基础知识。

在下一章中，我们将把注意力转向 Spring Boot 中的高级功能。我们将学习如何在我们的 REST 服务之上提供监控，学习如何将微服务部署到云上，并了解如何在使用 Spring Boot 开发应用程序时变得更加高效。


# 第七章：高级 Spring Boot 功能

在上一章中，我们通过异常处理、HATEOAS、缓存和国际化扩展了我们的微服务。在本章中，让我们把注意力转向将我们的服务部署到生产环境。为了能够将服务部署到生产环境，我们需要能够设置和创建功能来配置、部署和监控服务。

以下是本章将回答的一些问题：

+   如何外部化应用程序配置？

+   如何使用配置文件来配置特定环境的值？

+   如何将我们的应用程序部署到云端？

+   嵌入式服务器是什么？如何使用 Tomcat、Jetty 和 Undertow？

+   Spring Boot Actuator 提供了哪些监控功能？

+   如何通过 Spring Boot 成为更高效的开发者？

# 外部化配置

应用程序通常只构建一次（JAR 或 WAR），然后部署到多个环境中。下图显示了应用程序可以部署到的不同环境：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/211bc63c-fe61-4b57-93d9-b9cc0f3afbd8.png)

在前述的每个环境中，应用程序通常具有以下内容：

+   连接到数据库

+   连接到多个服务

+   特定环境配置

将配置在不同环境之间变化的配置外部化到配置文件或数据库中是一个很好的做法。

Spring Boot 提供了一种灵活的、标准化的外部化配置方法。

在本节中，我们将看一下以下内容：

+   如何在我们的服务中使用`application.properties`中的属性？

+   如何使应用程序配置成为一件轻而易举的事情？

+   Spring Boot 为**Spring Profiles**提供了什么样的支持？

+   如何在`application.properties`中配置属性？

在 Spring Boot 中，`application.properties`是默认的配置值来源文件。Spring Boot 可以从类路径的任何位置获取`application.properties`文件。通常，`application.properties`位于`src\main\resources`，如下图所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/43218c35-6975-4e18-a64f-ac06107d47e2.png)

在第六章中，*扩展微服务*，我们看了一些使用`application.properties`中的配置自定义 Spring Security 的示例：

```java
    security.basic.enabled=false
    management.security.enabled=false
    security.user.name=user-name
    security.user.password=user-password
    security.oauth2.client.clientId: clientId
    security.oauth2.client.clientSecret: clientSecret
    security.oauth2.client.authorized-grant-types:                
    authorization_code,refresh_token,password
    security.oauth2.client.scope: openid
```

与此类似，所有其他 Spring Boot starters、模块和框架都可以通过`application.properties`中的配置进行自定义。在下一节中，让我们看一下 Spring Boot 为这些框架提供的一些配置选项。

# 通过`application.properties`自定义框架

在本节中，我们将讨论一些可以通过`application.properties`进行配置的重要事项。

有关完整列表，请参阅[`docs.spring.io/spring-boot/docs/current-SNAPSHOT/reference/htmlsingle/#common-application-properties`](https://docs.spring.io/spring-boot/docs/current-SNAPSHOT/reference/htmlsingle/#common-application-properties)。

# 日志

一些可以配置的事项如下：

+   日志配置文件的位置

+   日志文件的位置

+   日志级别

以下代码片段显示了一些示例：

```java
# Location of the logging configuration file.
  logging.config=
# Log file name.
  logging.file=
# Configure Logging level. 
# Example `logging.level.org.springframework=TRACE`
  logging.level.*=
```

# 嵌入式服务器配置

嵌入式服务器是 Spring Boot 最重要的特性之一。一些可以通过应用程序属性进行配置的嵌入式服务器特性包括：

+   服务器端口

+   SSL 支持和配置

+   访问日志配置

以下代码片段显示了一些可以通过应用程序属性进行配置的嵌入式服务器特性：

```java
# Path of the error controller.
server.error.path=/error
# Server HTTP port.
server.port=8080
# Enable SSL support.
server.ssl.enabled=
# Path to key store with SSL certificate
server.ssl.key-store=
# Key Store Password
server.ssl.key-store-password=
# Key Store Provider
server.ssl.key-store-provider=
# Key Store Type
server.ssl.key-store-type=
# Should we enable access log of Tomcat?
server.tomcat.accesslog.enabled=false
# Maximum number of connections that server can accept
server.tomcat.max-connections=
```

# Spring MVC

Spring MVC 可以通过`application.properties`进行广泛配置。以下是一些重要的配置：

```java
# Date format to use. For instance `dd/MM/yyyy`.
 spring.mvc.date-format=
# Locale to use.
 spring.mvc.locale=
# Define how the locale should be resolved.
 spring.mvc.locale-resolver=accept-header
# Should "NoHandlerFoundException" be thrown if no Handler is found?
 spring.mvc.throw-exception-if-no-handler-found=false
# Spring MVC view prefix. Used by view resolver.
 spring.mvc.view.prefix=
# Spring MVC view suffix. Used by view resolver.
 spring.mvc.view.suffix=
```

# Spring starter security

Spring Security 可以通过`application.properties`进行广泛配置。以下示例显示了与 Spring Security 相关的一些重要配置选项：

```java
# Set true to Enable basic authentication
 security.basic.enabled=true
# Provide a Comma-separated list of uris you would want to secure
 security.basic.path=/**
# Provide a Comma-separated list of paths you don't want to secure
 security.ignored=
# Name of the default user configured by spring security
 security.user.name=user
# Password of the default user configured by spring security. 
 security.user.password=
# Roles granted to default user
 security.user.role=USER
```

# 数据源、JDBC 和 JPA

数据源、JDBC 和还可以通过`application.properties`进行广泛配置。以下是一些重要选项：

```java
# Fully qualified name of the JDBC driver. 
 spring.datasource.driver-class-name=
# Populate the database using 'data.sql'.
 spring.datasource.initialize=true
# JNDI location of the datasource.
 spring.datasource.jndi-name=
# Name of the datasource.
 spring.datasource.name=testdb
# Login password of the database.
 spring.datasource.password=
# Schema (DDL) script resource references.
 spring.datasource.schema=
# Db User to use to execute DDL scripts
 spring.datasource.schema-username=
# Db password to execute DDL scripts
 spring.datasource.schema-password=
# JDBC url of the database.
 spring.datasource.url=
# JPA - Initialize the schema on startup.
 spring.jpa.generate-ddl=false
# Use Hibernate's newer IdentifierGenerator for AUTO, TABLE and SEQUENCE.
 spring.jpa.hibernate.use-new-id-generator-mappings=
# Enable logging of SQL statements.
 spring.jpa.show-sql=false
```

# 其他配置选项

通过`application.properties`可以配置的其他一些事项如下：

+   配置文件

+   HTTP 消息转换器（Jackson/JSON）

+   事务管理

+   国际化

以下示例显示了一些配置选项：

```java
# Comma-separated list (or list if using YAML) of active profiles.
 spring.profiles.active=
# HTTP message conversion. jackson or gson
 spring.http.converters.preferred-json-mapper=jackson
# JACKSON Date format string. Example `yyyy-MM-dd HH:mm:ss`.
 spring.jackson.date-format=
# Default transaction timeout in seconds.
 spring.transaction.default-timeout=
# Perform the rollback on commit failures.
 spring.transaction.rollback-on-commit-failure=
# Internationalisation : Comma-separated list of basenames
 spring.messages.basename=messages
# Cache expiration for resource bundles, in sec. -1 will cache for ever
 spring.messages.cache-seconds=-1
```

# application.properties 中的自定义属性

到目前为止，我们已经看过了使用 Spring Boot 为各种框架提供的预构建属性。在本节中，我们将看看如何创建我们的应用程序特定配置，这些配置也可以在`application.properties`中配置。

让我们考虑一个例子。我们希望能够与外部服务进行交互。我们希望能够外部化此服务的 URL 配置。

以下示例显示了我们如何在`application.properties`中配置外部服务：

```java
   somedataservice.url=http://abc.service.com/something
```

我们想要在我们的数据服务中使用`;`somedataservice.url`属性的值。以下代码片段显示了我们如何在示例数据服务中实现这一点。

```java
    @Component
    public class SomeDataService {
      @Value("${somedataservice.url}")
      private String url;
      public String retrieveSomeData() {
        // Logic using the url and getting the data
       return "data from service";
      }
    }
```

需要注意的一些重要事项如下：

+   `@Component public class SomeDataService`：数据服务 bean 由 Spring 管理，因为有`@Component`注解。

+   `@Value("${somedataservice.url}")`：`somedataservice.url`的值将自动装配到`url`变量中。`url`的值可以在 bean 的方法中使用。

# 配置属性-类型安全的配置管理

虽然`;@Value`注解提供了动态配置，但它也有一些缺点：

+   如果我们想在一个服务中使用三个属性值，我们需要使用`@Value`三次进行自动装配。

+   `@Value`注解和消息的键将分布在整个应用程序中。如果我们想要查找应用程序中可配置的值列表，我们必须搜索`@Value`注解。

Spring Boot 通过强类型的`ConfigurationProperties`功能提供了更好的应用程序配置方法。这使我们能够做到以下几点：

+   在预定义的 bean 结构中具有所有属性

+   这个 bean 将作为所有应用程序属性的集中存储

+   配置 bean 可以在需要应用程序配置的任何地方进行自动装配

示例配置 bean 如下所示：

```java
    @Component
    @ConfigurationProperties("application")
    public class ApplicationConfiguration {
      private boolean enableSwitchForService1;
      private String service1Url;
      private int service1Timeout;
      public boolean isEnableSwitchForService1() {
        return enableSwitchForService1;
      }
     public void setEnableSwitchForService1
     (boolean enableSwitchForService1) {
        this.enableSwitchForService1 = enableSwitchForService1;
      }
     public String getService1Url() {
       return service1Url;
     }
     public void setService1Url(String service1Url) {
       this.service1Url = service1Url;
     }
     public int getService1Timeout() {
       return service1Timeout;
     }
     public void setService1Timeout(int service1Timeout) {
       this.service1Timeout = service1Timeout;
    }
  }
```

需要注意的一些重要事项如下：

+   `@ConfigurationProperties("application")`是外部化配置的注解。我们可以将此注解添加到任何类中，以绑定到外部属性。双引号中的值--application--在将外部配置绑定到此 bean 时用作前缀。

+   我们正在定义 bean 中的多个可配置值。

+   由于绑定是通过 Java bean 属性描述符进行的，因此需要 getter 和 setter。

以下代码片段显示了如何在`application.properties`中定义这些属性的值：

```java
    application.enableSwitchForService1=true
    application.service1Url=http://abc-dev.service.com/somethingelse
    application.service1Timeout=250
```

需要注意的一些重要事项如下：

+   `application`：在定义配置 bean 时，前缀被定义为`@ConfigurationProperties("application")`

+   通过将前缀附加到属性的名称来定义值

我们可以通过将`ApplicationConfiguration`自动装配到 bean 中，在其他 bean 中使用配置属性。

```java
    @Component
    public class SomeOtherDataService {
      @Autowired
      private ApplicationConfiguration configuration;
      public String retrieveSomeData() {
        // Logic using the url and getting the data
        System.out.println(configuration.getService1Timeout());
        System.out.println(configuration.getService1Url());
        System.out.println(configuration.isEnableSwitchForService1());
        return "data from service";
      }
    }
```

需要注意的一些重要事项如下：

+   `@Autowired private ApplicationConfiguration configuration`：`ApplicationConfiguration`被自动装配到`SomeOtherDataService`中

+   `configuration.getService1Timeout(), configuration.getService1Url(), configuration.isEnableSwitchForService1()`：可以使用配置 bean 上的 getter 方法在 bean 方法中访问值

默认情况下，将外部配置的值绑定到配置属性 bean 的任何失败都将导致服务器启动失败。这可以防止因运行在生产环境中的配置错误的应用程序而引起的问题。

让我们使用错误的服务超时来看看会发生什么：

```java
    application.service1Timeout=SOME_MISCONFIGURATION
```

应用程序将因错误而无法启动。

```java
 ***************************
 APPLICATION FAILED TO START
 ***************************
Description:
Binding to target com.mastering.spring.springboot.configuration.ApplicationConfiguration@79d3473e failed:

Property: application.service1Timeout
Value: SOME_MISCONFIGURATION
Reason: Failed to convert property value of type 'java.lang.String' to required type 'int' for property 'service1Timeout'; nested exception is org.springframework.core.convert.ConverterNotFoundException: No converter found capable of converting from type [java.lang.String] to type [int]

Action:
Update your application's configuration
```

# 配置文件

到目前为止，我们看了如何将应用程序配置外部化到属性文件`application.properties`。我们希望能够在不同环境中为相同的属性具有不同的值。

配置文件提供了在不同环境中提供不同配置的方法。

以下代码片段显示了如何在`application.properties`中配置活动配置文件：

```java
    spring.profiles.active=dev
```

一旦配置了活动配置文件，您可以在`application-{profile-name}.properties`中定义特定于该配置文件的属性。对于`dev`配置文件，属性文件的名称将是`application-dev.properties`。以下示例显示了`application-dev.properties`中的配置：

```java
    application.enableSwitchForService1=true
    application.service1Url=http://abc-dev.service.com/somethingelse
    application.service1Timeout=250
```

如果活动配置文件是`dev`，则`application-dev.properties`中的值将覆盖`application.properties`中的默认配置。

我们可以为多个环境进行配置，如下所示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/3a17c5e0-6e81-4e18-9c41-168901db26e2.png)

# 基于配置文件的 Bean 配置

配置文件还可以用于在不同环境中定义不同的 bean 或不同的 bean 配置。所有标有`@Component`或`@Configuration`的类也可以标有额外的`@Profile`注解，以指定启用该 bean 或配置的配置文件。

让我们考虑一个例子。一个应用程序需要在不同环境中启用不同的缓存。在`dev`环境中，它使用非常简单的缓存。在生产环境中，我们希望使用分布式缓存。这可以使用配置文件来实现。

以下 bean 显示了在`dev`环境中启用的配置：

```java
    @Profile("dev")
    @Configuration
    public class DevSpecificConfiguration {
      @Bean
      public String cache() {
        return "Dev Cache Configuration";
      }
    }
```

以下 bean 显示了在生产环境中启用的配置：

```java
    @Profile("prod")
    @Configuration
    public class ProdSpecificConfiguration {
      @Bean
      public String cache() {
        return "Production Cache Configuration - Distributed Cache";
      }
   }
```

根据配置的活动配置文件，选择相应的配置。请注意，在此示例中，我们实际上并没有配置分布式缓存。我们返回一个简单的字符串来说明可以使用配置文件来实现这些变化。

# 其他选项用于应用程序配置值

到目前为止，我们采用的方法是使用`application.properties`或`application-{profile-name}.properties`中的键值对来配置应用程序属性。

Spring Boot 提供了许多其他配置应用程序属性的方法。

以下是提供应用程序配置的一些重要方法：

+   命令行参数

+   创建一个名为`SPRING_APPLICATION_JSON`的系统属性，并包含 JSON 配置

+   ServletConfig 初始化参数

+   ServletContext 初始化参数

+   Java 系统属性（`System.getProperties()`）

+   操作系统环境变量

+   打包在`.jar`之外的特定配置文件，位于应用程序的类路径中（`application-{profile}.properties`）

+   打包在`.jar`中的特定配置文件（`application-{profile}.properties`和 YAML 变体）

+   `.jar`之外的应用程序属性

+   打包在`.jar`中的应用程序属性

有关更多信息，请参阅 Spring Boot 文档[`docs.spring.io/spring-boot/docs/current-SNAPSHOT/reference/htmlsingle/#boot-features-external-config`](http://docs.spring.io/spring-boot/docs/current-SNAPSHOT/reference/htmlsingle/#boot-features-external-config)。

此列表顶部的方法比列表底部的方法具有更高的优先级。例如，如果在启动应用程序时提供了一个名为`spring.profiles.active`的命令行参数，它将覆盖通过`application.properties`提供的任何配置，因为命令行参数具有更高的优先级。

这在确定如何在不同环境中配置应用程序方面提供了很大的灵活性。

# YAML 配置

Spring Boot 还支持 YAML 来配置您的属性。

YAML 是“YAML Ain't Markup Language”的缩写。它是一种人类可读的结构化格式。YAML 通常用于配置文件。

要了解 YAML 的基本语法，请查看下面的示例（`application.yaml`）。这显示了如何在 YAML 中指定我们的应用程序配置。

```java
spring:
   profiles:
      active: prod
security:
   basic:
      enabled: false
   user:
      name=user-name
      password=user-password
oauth2:
   client:
      clientId: clientId
      clientSecret: clientSecret
      authorized-grant-types: authorization_code,refresh_token,password
      scope: openid
application:
   enableSwitchForService1: true
   service1Url: http://abc-dev.service.com/somethingelse
   service1Timeout: 250
```

正如您所看到的，YAML 配置比`application.properties`更易读，因为它允许更好地对属性进行分组。

YAML 的另一个优点是它允许您在单个配置文件中为多个配置文件指定配置。以下代码片段显示了一个示例：

```java
application:
  service1Url: http://service.default.com
---
spring:
  profiles: dev
  application:
    service1Url: http://service.dev.com
---
spring:
   profiles: prod
   application:
    service1Url: http://service.prod.com
```

在这个例子中，`http://service.dev.com`将在`dev`配置文件中使用，而`http://service.prod.com`将在`prod`配置文件中使用。在所有其他配置文件中，`http://service.default.com`将作为服务 URL 使用。

# 嵌入式服务器

Spring Boot 引入的一个重要概念是嵌入式服务器。

让我们首先了解传统 Java Web 应用程序部署与这个称为嵌入式服务器的新概念之间的区别。

传统上，使用 Java Web 应用程序，我们构建 Web 应用程序存档（WAR）或企业应用程序存档（EAR）并将它们部署到服务器上。在我们可以在服务器上部署 WAR 之前，我们需要在服务器上安装 Web 服务器或应用服务器。应用服务器将安装在服务器上的 Java 实例之上。因此，我们需要在可以部署我们的应用程序之前在机器上安装 Java 和应用程序（或 Web 服务器）。以下图显示了 Linux 中的一个示例安装：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/e2025c2a-8089-4876-baae-ecc5695d182c.png)

Spring Boot 引入了嵌入式服务器的概念，其中 Web 服务器是应用程序可部署的一部分--JAR。使用嵌入式服务器部署应用程序时，只需在服务器上安装 Java 即可。以下图显示了一个示例安装：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/78f1c4a9-a5da-4785-a7f2-ff2580ff5ffd.png)

当我们使用 Spring Boot 构建任何应用程序时，默认情况下是构建一个 JAR。使用`spring-boot-starter-web`，默认的嵌入式服务器是 Tomcat。

当我们使用`spring-boot-starter-web`时，在 Maven 依赖项部分可以看到一些与 Tomcat 相关的依赖项。这些依赖项将作为应用程序部署包的一部分包含进去：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/861fd1e9-42d6-4e8f-9cfd-cf4096937d41.png)

要部署应用程序，我们需要构建一个 JAR。我们可以使用以下命令构建一个 JAR：

```java
mvn clean install
```

以下屏幕截图显示了创建的 JAR 的结构。

`BOOT-INF\classes`包含所有与应用程序相关的类文件（来自`src\main\java`）以及来自`src\main\resources`的应用程序属性：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/d5c8e970-8105-467a-bf2a-a4aafd94d908.png)

`BOOT-INF\lib`中的一些库在以下屏幕截图中显示：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/992dfd0f-d8bc-469b-8206-39b56cf20e10.png)

`BOOT-INF\lib`包含应用程序的所有 JAR 依赖项。其中有三个 Tomcat 特定的 JAR 文件。这三个 JAR 文件在将应用程序作为 Java 应用程序运行时启用了嵌入式 Tomcat 服务的启动。因此，只需安装 Java 即可在服务器上部署此应用程序。

# 切换到 Jetty 和 Undertow

以下屏幕截图显示了切换到使用 Jetty 嵌入式服务器所需的更改：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/8c4a532a-5e2d-404b-ab14-65bc6e7b4465.png)

我们所需要做的就是在`spring-boot-starter-web`中排除 Tomcat 启动器依赖项，并在`spring-boot-starter-jetty`中包含一个依赖项。

现在您可以在 Maven 依赖项部分看到许多 Jetty 依赖项。以下截图显示了一些与 Jetty 相关的依赖项：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/2a6f260a-7121-4cd1-b7e7-d4dc8568affe.png)

切换到 Undertow 同样很容易。使用`spring-boot-starter-undertow`代替`spring-boot-starter-jetty`：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-undertow</artifactId>
   </dependency>
```

# 构建 WAR 文件

Spring Boot 还提供了构建传统 WAR 文件而不是使用 JAR 的选项。

首先，我们需要在`pom.xml`中更改我们的打包为`WAR`：

```java
    <packaging>war</packaging>
```

我们希望防止 Tomcat 服务器作为 WAR 文件中的嵌入式依赖项。我们可以通过修改嵌入式服务器（以下示例中的 Tomcat）的依赖项来将其范围设置为提供。以下代码片段显示了确切的细节：

```java
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-tomcat</artifactId>
      <scope>provided</scope>
   </dependency>
```

当构建 WAR 文件时，不包括 Tomcat 依赖项。我们可以使用此 WAR 文件部署到应用服务器，如 WebSphere 或 Weblogic，或 Web 服务器，如 Tomcat。

# 开发工具

Spring Boot 提供了可以改善开发 Spring Boot 应用程序体验的工具。其中之一是 Spring Boot 开发工具。

要使用 Spring Boot 开发工具，我们需要包含一个依赖项：

```java
    <dependencies>
     <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-devtools</artifactId>
       <optional>true</optional>
     </dependency>
   </dependencies>
```

Spring Boot 开发工具默认禁用视图模板和静态文件的缓存。这使开发人员可以在进行更改后立即看到更改。

另一个重要功能是当类路径中的任何文件更改时自动重新启动。因此，在以下情况下应用程序会自动重新启动：

+   当我们对控制器或服务类进行更改时

+   当我们对属性文件进行更改时

Spring Boot 开发工具的优点如下：

+   开发人员不需要每次都停止和启动应用程序。只要有变化，应用程序就会自动重新启动。

+   Spring Boot 开发工具中的重新启动功能是智能的。它只重新加载活跃开发的类。它不会重新加载第三方 JAR（使用两个不同的类加载器）。因此，当应用程序中的某些内容发生变化时，重新启动速度比冷启动应用程序要快得多。

# 实时重新加载

另一个有用的 Spring Boot 开发工具功能是**实时重新加载**。您可以从[`livereload.com/extensions/`](http://livereload.com/extensions/)下载特定的浏览器插件。

您可以通过单击浏览器中的按钮来启用实时重新加载。 Safari 浏览器中的按钮如下截图所示。它位于地址栏旁边的左上角。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/6122df44-dd22-446b-b693-b8df0cf99805.png)

如果在浏览器中显示的页面或服务上进行了代码更改，它们将自动刷新为新内容。不再需要点击刷新按钮！

# Spring Boot 执行器

当应用程序部署到生产环境时：

+   我们希望立即知道某些服务是否宕机或非常缓慢

+   我们希望立即知道任何服务器是否没有足够的可用空间或内存

这被称为**应用程序监控**。

**Spring Boot 执行器**提供了许多生产就绪的监控功能。

我们将通过添加一个简单的依赖项来添加 Spring Boot 执行器：

```java
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-actuator</artifactId>
     </dependency>
   </dependencies>
```

一旦执行器添加到应用程序中，它就会启用许多端点。当我们启动应用程序时，我们会看到许多新添加的映射。以下截图显示了启动日志中这些新映射的摘录：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/dd81e668-f0b5-4a06-bde3-ff017963bc49.png)

执行器公开了许多端点。执行器端点（`http://localhost:8080/application`）充当所有其他端点的发现。当我们从 Postman 执行请求时，以下截图显示了响应：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/6c5b5dc2-d362-4ec3-ae3a-c650d514875b.png)

# HAL 浏览器

许多这些端点暴露了大量数据。为了能够更好地可视化信息，我们将在我们的应用程序中添加一个**HAL 浏览器**：

```java
    <dependency>
      <groupId>org.springframework.data</groupId>
      <artifactId>spring-data-rest-hal-browser</artifactId>
    </dependency>
```

Spring Boot Actuator 在 Spring Boot 应用程序和环境中捕获的所有数据周围暴露了 REST API。HAL 浏览器使得在 Spring Boot Actuator API 周围进行可视化表示成为可能：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/472b7175-368b-46f8-9173-201c8ed29621.png)

当我们在浏览器中启动`http://localhost:8080/application`时，我们可以看到 actuator 暴露的所有 URL。

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/54550026-0c77-4c04-ad52-dd9e018ecf2c.png)

让我们通过 HAL 浏览器浏览 actuator 作为不同端点的一部分暴露的所有信息。

# 配置属性

`configprops`端点提供了关于可以通过应用程序属性进行配置的配置选项的信息。它基本上是所有`@ConfigurationProperties`的汇总列表。下面的屏幕截图显示了 HAL 浏览器中的 configprops：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/2f0189f7-be6c-4343-ac4f-ac24f5f3864b.png)

为了举例说明，以下部分从服务响应中显示了 Spring MVC 可用的配置选项：

```java
"spring.mvc-  org.springframework.boot.autoconfigure.web.WebMvcProperties": {
   "prefix": "spring.mvc",
   "properties": {
                   "dateFormat": null,
                   "servlet": {
                     "loadOnStartup": -1
                  },
   "staticPathPattern": "/**",
   "dispatchOptionsRequest": true,
   "dispatchTraceRequest": false,
   "locale": null,
   "ignoreDefaultModelOnRedirect": true,
   "logResolvedException": true,
   "async": {
              "requestTimeout": null
            },
   "messageCodesResolverFormat": null,
   "mediaTypes": {},
   "view": {
             "prefix": null,
             "suffix": null
           },
   "localeResolver": "ACCEPT_HEADER",
   "throwExceptionIfNoHandlerFound": false
    }
 }
```

为了为 Spring MVC 提供配置，我们将前缀与属性中的路径组合在一起。例如，要配置`loadOnStartup`，我们使用名称为`spring.mvc.servlet.loadOnStartup`的属性。

# 环境细节

**环境（env）**端点提供了有关操作系统、JVM 安装、类路径、系统环境变量以及各种应用程序属性文件中配置的值的信息。以下屏幕截图显示了 HAL 浏览器中的环境端点：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/54f5003f-ab0f-4cae-aaa1-96029fe1e5d1.png)

以下是从`/application/env`服务的响应中提取的内容。它显示了一些系统详细信息以及应用程序配置的详细信息：

```java
"systemEnvironment": {
    "JAVA_MAIN_CLASS_13377": "com.mastering.spring.springboot.Application",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "SHELL": "/bin/bash",
    "JAVA_STARTED_ON_FIRST_THREAD_13019": "1",
    "APP_ICON_13041": "../Resources/Eclipse.icns",
    "USER": "rangaraokaranam",
    "TMPDIR": "/var/folders/y_/x4jdvdkx7w94q5qsh745gzz00000gn/T/",
    "SSH_AUTH_SOCK": "/private/tmp/com.apple.launchd.IcESePQCLV/Listeners",
    "XPC_FLAGS": "0x0",
    "JAVA_STARTED_ON_FIRST_THREAD_13041": "1",
    "APP_ICON_11624": "../Resources/Eclipse.icns",
    "LOGNAME": "rangaraokaranam",
    "XPC_SERVICE_NAME": "0",
    "HOME": "/Users/rangaraokaranam"
  },
  "applicationConfig: [classpath:/application-prod.properties]": {
    "application.service1Timeout": "250",
    "application.service1Url": "http://abc-    prod.service.com/somethingelse",
    "application.enableSwitchForService1": "false"
  },
```

# 健康

健康服务提供了磁盘空间和应用程序状态的详细信息。以下屏幕截图显示了从 HAL 浏览器执行的服务：

![](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ms-spr5/img/06e289c8-103e-491b-93d8-4f2b58bea3e5.png)

# Mappings

Mappings 端点提供了有关从应用程序暴露的不同服务端点的信息：

+   URI

+   请求方法

+   Bean

+   暴露服务的控制器方法

Mappings 提供了所有`@RequestMapping`路径的汇总列表。以下是从`/application/mappings`端点的响应中提取的内容。我们可以看到在本书中之前创建的不同控制器方法的映射：

```java
"{[/welcome-internationalized],methods=[GET]}": {
   "bean": "requestMappingHandlerMapping",
   "method": "public java.lang.String 
    com.mastering.spring.springboot.controller.
    BasicController.msg(java.uti l.Locale)"
 },
 "{[/welcome],methods=[GET]}": {
    "bean": "requestMappingHandlerMapping",
    "method": "public java.lang.String 
     com.mastering.spring.springboot.controller.
     BasicController.welcome()"
 },
 "{[/welcome-with-object],methods=[GET]}": {
     "bean": "requestMappingHandlerMapping",
     "method": "public com.mastering.spring.springboot.
      bean.WelcomeBeancom.mastering.spring.springboot.
      controller.BasicController.welcomeWithObject()"
 },
 "{[/welcome-with-parameter/name/{name}],methods=[GET]}": {
      "bean": "requestMappingHandlerMapping",
      "method": "public 
       com.mastering.spring.springboot.bean.WelcomeBean   
       com.mastering.spring.springboot.controller.
       BasicController.welcomeWithParameter(java.lang.String)"
 },
 "{[/users/{name}/todos],methods=[POST]}": {
       "bean": "requestMappingHandlerMapping",
       "method": "org.springframework.http.ResponseEntity<?>    
        com.mastering.spring.springboot.controller.
        TodoController.add(java.lang.String,com.mastering.spring.
        springboot.bean.Todo)"
  },
 "{[/users/{name}/todos],methods=[GET]}": {
        "bean": "requestMappingHandlerMapping",
        "method": "public java.util.List<com.mastering.spring.
         springboot.bean.Todo> 
         com.mastering.spring.springboot.controller.
         TodoController.retrieveTodos(java.lang.String)"
 },
 "{[/users/{name}/todos/{id}],methods=[GET]}": {
        "bean": "requestMappingHandlerMapping",
        "method": "public 
         org.springframework.hateoas.Resource<com.mastering.
         spring.springboot.bean.Todo>  
         com.mastering.spring.springboot.controller.
         TodoController.retrieveTodo(java.lang.String,int)"
 },
```

# Beans

beans 端点提供了有关加载到 Spring 上下文中的 bean 的详细信息。这对于调试与 Spring 上下文相关的任何问题非常有用。

以下是从`/application/beans`端点的响应中提取的内容：

```java
  {
     "bean": "basicController",
     "aliases": [],
     "scope": "singleton",
     "type": "com.mastering.spring.springboot.
      controller.BasicController",
     "resource": "file [/in28Minutes/Workspaces/
      SpringTutorial/mastering-spring-chapter-5-6-  
      7/target/classes/com/mastering/spring/springboot/
      controller/BasicController.class]",
      "dependencies": [
                     "messageSource"
                    ]
   },
   {
      "bean": "todoController",
      "aliases": [],
      "scope": "singleton",
      "type": "com.mastering.spring.springboot.
       controller.TodoController",
       "resource": "file [/in28Minutes/Workspaces/SpringTutorial/
       mastering-spring-chapter-5-6-
       7/target/classes/com/mastering/spring/
       springboot/controller/TodoController.class]",
       "dependencies": [
                      "todoService"
                     ]
    }
```

它显示了两个 bean：`basicController`和`todoController`的详细信息。您可以看到所有 bean 的以下详细信息：

+   bean 的名称及其别名

+   bean 的范围

+   Bean 的类型

+   创建此 bean 的类的确切位置

+   Bean 的依赖关系

# 指标

指标端点显示以下一些重要的指标：

+   服务器--空闲内存、处理器、正常运行时间等

+   JVM--关于堆、线程、垃圾收集、会话等的详细信息

+   应用程序服务提供的响应

以下是从`/application/metrics`端点的响应中提取的内容：

```java
{
 "mem": 481449,
 "mem.free": 178878,
 "processors": 4,
 "instance.uptime": 1853761,
 "uptime": 1863728,
 "systemload.average": 2.3349609375,
 "heap.committed": 413696,
 "heap.init": 65536,
 "heap.used": 234817,
 "heap": 932352,
 "nonheap.committed": 69248,
 "nonheap.init": 2496,
 "nonheap.used": 67754,
 "nonheap": 0,
 "threads.peak": 23,
 "threads.daemon": 21,
 "threads.totalStarted": 30,
 "threads": 23,
 "classes": 8077,
 "classes.loaded": 8078,
 "classes.unloaded": 1,
 "gc.ps_scavenge.count": 15,
 "gc.ps_scavenge.time": 242,
 "gc.ps_marksweep.count": 3,
 "gc.ps_marksweep.time": 543,
 "httpsessions.max": -1,
 "httpsessions.active": 0,
 "gauge.response.actuator": 8,
 "gauge.response.mappings": 12,
 "gauge.response.beans": 83,
 "gauge.response.health": 14,
 "gauge.response.root": 9,
 "gauge.response.heapdump": 4694,
 "gauge.response.env": 6,
 "gauge.response.profile": 12,
 "gauge.response.browser.star-star": 10,
 "gauge.response.actuator.root": 2,
 "gauge.response.configprops": 272,
 "gauge.response.actuator.star-star": 13,
 "counter.status.200.profile": 1,
 "counter.status.200.actuator": 8,
 "counter.status.200.mappings": 1,
 "counter.status.200.root": 5,
 "counter.status.200.configprops": 1,
 "counter.status.404.actuator.star-star": 3,
 "counter.status.200.heapdump": 1,
 "counter.status.200.health": 1,
 "counter.status.304.browser.star-star": 132,
 "counter.status.302.actuator.root": 4,
 "counter.status.200.browser.star-star": 37,
 "counter.status.200.env": 2,
 "counter.status.302.root": 5,
 "counter.status.200.beans": 1,
 "counter.status.200.actuator.star-star": 210,
 "counter.status.302.actuator": 1
 }
```

# 自动配置

自动配置是 Spring Boot 的最重要特性之一。自动配置端点（`/application/autoconfig`）暴露了与自动配置相关的详细信息。它显示了成功或失败的特定自动配置的原因的正匹配和负匹配。

以下提取显示了响应中一些正匹配的内容：

```java
"positiveMatches": {
  "AuditAutoConfiguration#auditListener": [
   {
     "condition": "OnBeanCondition",
     "message": "@ConditionalOnMissingBean (types:     
      org.springframework.boot.actuate.audit.
      listener.AbstractAuditListener; SearchStrategy: all) did not find 
      any beans"
   }
 ],
 "AuditAutoConfiguration#authenticationAuditListener": [
 {
   "condition": "OnClassCondition",
   "message": "@ConditionalOnClass found required class
   'org.springframework.security.authentication.
   event.AbstractAuthenticationEvent'"
 },
```

以下提取显示了响应中一些负匹配的内容：

```java
"negativeMatches": {
  "CacheStatisticsAutoConfiguration.
   CaffeineCacheStatisticsProviderConfiguration": [
 {
   "condition": "OnClassCondition",
   "message": "@ConditionalOnClass did not find required class  
   'com.github.benmanes.caffeine.cache.Caffeine'"
 }
 ],
   "CacheStatisticsAutoConfiguration.
   EhCacheCacheStatisticsProviderConfiguration": [
 {
   "condition": "OnClassCondition",
   "message": "@ConditionalOnClass did not find required classes
   'net.sf.ehcache.Ehcache',   
   'net.sf.ehcache.statistics.StatisticsGateway'"
 }
 ],
```

所有这些细节对于调试自动配置非常有用。

# 调试

在调试问题时，三个执行器端点非常有用：

+   `/application/heapdump`：提供堆转储

+   `/application/trace`：提供应用程序最近几个请求的跟踪

+   `/application/dump`：提供线程转储

# 将应用程序部署到 Cloud

Spring Boot 对大多数流行的云**平台即服务**（**PaaS**）提供商有很好的支持。

一些流行的云端包括：

+   Cloud Foundry

+   Heroku

+   OpenShift

+   **亚马逊网络服务**（**AWS**）

在本节中，我们将专注于将我们的应用程序部署到 Cloud Foundry。

# Cloud Foundry

Cloud Foundry 的 Java 构建包对 Spring Boot 有很好的支持。我们可以部署基于 JAR 的独立应用程序，也可以部署传统的 Java EE WAR 应用程序。

Cloud Foundry 提供了一个 Maven 插件来部署应用程序：

```java
<build>
   <plugins>
      <plugin>
         <groupId>org.cloudfoundry</groupId>
         <artifactId>cf-maven-plugin</artifactId>
         <version>1.1.2</version>
      </plugin>
   </plugins>
</build>
```

在我们部署应用程序之前，我们需要为应用程序配置目标和空间以部署应用程序。

涉及以下步骤：

1.  我们需要在[`account.run.pivotal.io/sign-up`](https://account.run.pivotal.io/sign-up)创建一个 Pivotal Cloud Foundry 账户。

1.  一旦我们有了账户，我们可以登录到[`run.pivotal.io`](https://run.pivotal.io)创建一个组织和空间。准备好组织和空间的详细信息，因为我们需要它们来部署应用程序。

我们可以使用`org`和`space`的配置更新插件：

```java
<build>
   <plugins>
      <plugin>
         <groupId>org.cloudfoundry</groupId>
         <artifactId>cf-maven-plugin</artifactId>
         <version>1.1.2</version>
         <configuration>
            <target>http://api.run.pivotal.io</target>
            <org>in28minutes</org>
            <space>development</space>
            <memory>512</memory>
            <env>
               <ENV-VAR-NAME>prod</ENV-VAR-NAME>
            </env>
         </configuration>
      </plugin>
   </plugins>
</build>
```

我们需要使用 Maven 插件在命令提示符或终端上登录到 Cloud Foundry：

```java
mvn cf:login -Dcf.username=<<YOUR-USER-ID>> -Dcf.password=<<YOUR-PASSWORD>>
```

如果一切顺利，您将看到一条消息，如下所示：

```java
[INFO] ------------------------------------------------------------------
 [INFO] Building Your First Spring Boot Example 0.0.1-SNAPSHOT
 [INFO] -----------------------------------------------------------------
 [INFO]
 [INFO] --- cf-maven-plugin:1.1.2:login (default-cli) @ springboot-for-beginners-example ---
 [INFO] Authentication successful
 [INFO] -----------------------------------------------------------------
 [INFO] BUILD SUCCESS
 [INFO] -----------------------------------------------------------------
 [INFO] Total time: 14.897 s
 [INFO] Finished at: 2017-02-05T16:49:52+05:30
 [INFO] Final Memory: 22M/101M
 [INFO] -----------------------------------------------------------------
```

一旦您能够登录，您可以将应用程序推送到 Cloud Foundry：

```java
mvn cf:push
```

一旦我们执行命令，Maven 将编译，运行测试，构建应用程序的 JAR 或 WAR，然后将其部署到云端：

```java
[INFO] Building jar: /in28Minutes/Workspaces/SpringTutorial/springboot-for-beginners-example-rest-service/target/springboot-for-beginners-example-0.0.1-SNAPSHOT.jar
 [INFO]
 [INFO] --- spring-boot-maven-plugin:1.4.0.RELEASE:repackage (default) @ springboot-for-beginners-example ---
 [INFO]
 [INFO] <<< cf-maven-plugin:1.1.2:push (default-cli) < package @ springboot-for-beginners-example <<<
 [INFO]
 [INFO] --- cf-maven-plugin:1.1.2:push (default-cli) @ springboot-for-beginners-example ---
 [INFO] Creating application 'springboot-for-beginners-example'
 [INFO] Uploading '/in28Minutes/Workspaces/SpringTutorial/springboot-for-beginners-example-rest-service/target/springboot-for-beginners-example-0.0.1-SNAPSHOT.jar'
 [INFO] Starting application
 [INFO] Checking status of application 'springboot-for-beginners-example'
 [INFO] 1 of 1 instances running (1 running)
 [INFO] Application 'springboot-for-beginners-example' is available at 'http://springboot-for-beginners-example.cfapps.io'
 [INFO] ----------------------------------------------------------------- [INFO] BUILD SUCCESS
 [INFO] ----------------------------------------------------------------- [INFO] Total time: 02:21 min
 [INFO] Finished at: 2017-02-05T16:54:55+05:30
 [INFO] Final Memory: 29M/102M
 [INFO] -----------------------------------------------------------------
```

一旦应用程序在云端运行起来，我们可以使用日志中的 URL 来启动应用程序：[`springboot-for-beginners-example.cfapps.io`](http://springboot-for-beginners-example.cfapps.io)。

您可以在[`docs.run.pivotal.io/buildpacks/java/build-tool-int.html#maven`](https://docs.run.pivotal.io/buildpacks/java/build-tool-int.html#maven)找到有关 Cloud Foundry 的 Java Build Pack 的更多信息。

# 总结

Spring Boot 使开发基于 Spring 的应用程序变得容易。它使我们能够非常快速地创建生产就绪的应用程序。

在本章中，我们了解了 Spring Boot 提供的不同外部配置选项。我们查看了嵌入式服务器，并将一个测试应用程序部署到了 PaaS 云平台--Cloud Foundry。我们探讨了如何使用 Spring Boot 执行器在生产环境中监视我们的应用程序。最后，我们看了一下使开发人员更加高效的功能--Spring Boot 开发人员工具和实时重新加载。

在下一章中，我们将把注意力转向数据。我们将涵盖 Spring Data，并看看它如何使与 JPA 集成和提供 Rest 服务更容易。
