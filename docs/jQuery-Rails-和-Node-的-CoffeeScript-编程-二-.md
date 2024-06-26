# jQuery、Rails 和 Node 的 CoffeeScript 编程（二）

> 原文：[`zh.annas-archive.org/md5/0B0062B2422D4B29BA6F761E6D36A199`](https://zh.annas-archive.org/md5/0B0062B2422D4B29BA6F761E6D36A199)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：CoffeeScript 和 Rails

Ruby on Rails 是一个于 2004 年出现的 Web 框架。它是由 David Heinemeier Hansson 编写的，并从**Basecamp**中提取出来，这是他为他的公司**37signals**用 Ruby 编写的项目管理 Web 应用程序。

Rails 立即给许多人留下了深刻的印象，因为他们可以轻松快速地编写 Web 应用程序，并很快变得非常受欢迎。

在开发时，Ruby 是一个来自日本的鲜为人知的脚本语言。Ruby 实际上是 Rails 如此成功的原因。它已被证明是一种强大而简洁的编程语言，许多程序员表示它让编程再次变得有趣。

# Rails 的特殊之处在哪里？

Rails 推动了 Web 开发人员编写应用程序的方式。其核心理念包括以下两个重要原则：

+   约定优于配置

+   不要重复自己，或者 DRY

## 约定优于配置

Rails 旨在假定程序员将遵循某些已知的约定，如果使用这些约定，将提供巨大的好处，并且几乎不需要配置框架。它通常被称为一种有主见的框架。这意味着框架对典型应用程序的构建和结构有假设，并且不试图过于灵活和可配置。这有助于您花费更少的时间在配置和连接应用程序架构等琐事上，而更多的时间实际构建您的应用程序。

例如，Rails 将使用与其名称对应的对象对数据库中的表进行建模，因此`Transactions`数据库中的记录将自动映射到`Transactions`类实例，`people`数据库表中的记录也将自动映射到`Person`类实例。

Rails 通常会使用约定来为您做一些聪明的事情。比如说，我们的`people`表还有一个名为`created_at`和`updated_at`的`datetime`字段。Rails 将聪明地在记录创建或更新时自动更新这两个字段的时间戳。

Rails 约定的最重要的事情是你应该了解它们，不要与框架对抗，或者试图过多地偏离 Rails 的方式，除非有充分的理由。通常，这可能会抵消您从这些约定中获得的任何好处，甚至使您更难以尝试解决问题。

## 不要重复自己（DRY）

这个软件工程原则也可以表述为：

> 系统中的每个知识都必须具有单一、明确和权威的表示。

这意味着 Rails 努力在任何可能的地方消除重复和样板。

例如，模拟`people`表中的记录的`Person`类将不需要定义其字段，因为它们已经在数据库表中定义为列。在这里，Rails 可以利用 Ruby 的强大的元编程能力，神奇地向`Person`类添加与数据库中的列对应的属性。

### 注意

**元编程**是编写对其他代码起作用的代码的概念。换句话说，元编程是编写编写代码的代码。它在 Ruby 社区和特别是 Rails 源代码中被广泛使用。

Ruby 语言具有非常强大的元编程能力，与开放类和对象的概念相关联，这意味着您可以轻松地“打开”现有的类定义并重新定义和添加成员。

# Rails 和 JavaScript

很长一段时间，Rails 都使用`Prototype.js`和`Script.aculo.us` JavaScript 库进行 AJAX、页面动画和特效。

Rails 有视图助手的概念——这些是可以在视图中使用的 Ruby 方法，用于抽象出常见的 HTML 构造。许多处理客户端代码和 AJAX 的视图助手都是建立在这两个框架之上的，因此它们完全融入了框架，没有使用替代方案的简单方法。

`Prototype.js`与 jQuery 有许多相同的想法和目标，但随着时间的推移，jQuery 被许多程序员认为是一个更加优雅和强大的库。

随着 jQuery 变得越来越受欢迎，许多 Rails 社区的开发人员开始尝试使用 jQuery 代替默认的 JavaScript 库。一套标准的库或**gems**出现了，用于用 jQuery 替换内置的 Prototype 库。

在 Rails 3.1 版本中，宣布 jQuery 将成为默认的 JavaScript 库。因为 jQuery 已经具有大部分`Script.aculo.us`的动画和页面效果功能，所以这个库也不再需要了。

这一举措似乎已经等了很长时间，并且基本上得到了大多数 Rails 社区的祝福。

# Rails 和 CoffeeScript

Rails 3.1 的另一个重要新增功能是资产管道。其主要目标是使在 Rails 应用中处理 JavaScript 和 CSS 等资产变得更加容易。在此之前，JavaScript 和 CSS 只是作为静态内容提供。它还提供了一个组织框架，帮助你组织 JavaScript 和 CSS，并提供了一个用于访问它们的 DSL。

使用资产管道，你可以使用清单文件组织和管理资产之间的依赖关系。Rails 还将使用管道来缩小和连接 JavaScript，并为缓存清除应用指纹。

资产管道还有一个预处理器链，可以让你在提供文件之前通过一系列的输入-输出处理器运行文件。它知道使用文件扩展名来运行哪些预处理器。

在发布 Rails 3.1 之前，宣布 CoffeeScript 编译器将通过资产管道进行支持。这是一个巨大的宣布，因为 CoffeeScript 仍然是一种相当年轻的语言，并且在 Rails 社区内引起了一些争议，一些人为他们不想学习或使用这种新语言而感到惋惜。

Rails 的维护者们一直坚持自己的立场，目前在 Rails 中使用 CoffeeScript 变得非常容易。CoffeeScript 成为编写客户端 JavaScript 代码的默认语言，这对 CoffeeScript 来说是一个巨大的推动力，许多 Rails 开发人员已经开始了解并接受了这种语言。

我们一直在谈论 Rails 有多么美妙，以及它与 CoffeeScript 的良好配合，所以让我们安装 Rails，这样你就可以亲自看看到底是怎么回事。

# 安装 Rails

根据你的操作系统、你想要使用的 Ruby 版本、是否使用版本管理器、是否从源代码构建以及其他几十种选项，你可以在开发机器上安装 Ruby 和 Rails 的许多不同方式。在本书中，我们只会简要介绍在 Windows、Mac 和 Linux 上安装它的最常见方式。请注意，在本书中，我们将使用至少 3.2 及更高版本的 Rails 和 1.9.2 及更高版本的 Ruby。

## 使用 RailsInstaller 安装 Rails

在 Windows 上，或者在 Mac 上，我建议使用**RailsInstaller** ([`railsinstaller.org/`](http://railsinstaller.org/))。它包含了开始使用 Rails 所需的一切，包括最新版本的 Ruby 本身。下载安装程序后，安装过程非常简单；只需运行它并按照向导进行操作。安装完成后，你应该会看到一个打开的控制台命令提示符。尝试输入`rails -v`。如果你看到一个版本号，那么你就可以开始了。

## 使用 RVM 安装 Rails

在 Mac 和 Linux 上安装 Ruby 和 Rails 可能非常容易，使用**RVM**或**Ruby Version Manager**，从[`rvm.io/`](https://rvm.io/)。

在过去几年中，Ruby 语言已经变得非常流行，这导致编写了多个可以在不同平台上运行的语言实现。**Matz's Ruby Interpreter**（**MRI**），Ruby 的标准实现，也经历了几个版本。RVM 非常适合管理和安装不同版本的 Ruby。它配备了一个一站式安装程序 bash 脚本，可以安装最新的 Ruby 和 Rails。只需从终端运行以下命令：

```js
curl -L https://get.rvm.io | bash -s stable --rails
```

这可能需要相当长的时间才能完成。完成后，您应该尝试在终端中输入`rails -v`。如果您看到至少 3.2 的版本号，那么您应该可以继续了。

## 已安装 Rails？

现在我们已经安装了 Rails，让我们继续使用 CoffeeScript 构建一个应用程序。

如果您遇到任何问题或需要更多关于安装 Rails 的信息，最好的起点是 Ruby on Rails 网站的**下载**部分（[`rubyonrails.org/download`](http://rubyonrails.org/download)）。

# 开发我们的 Rails 应用程序

我们将使用现有的待办事项列表应用程序的部分内容，并使用 Rails 扩展它，添加一个服务器端后端。如果您没有在上一章中跟随，那么您应该能够根据需要复制该章节的代码。

### 注意

本章不旨在对 Ruby on Rails 或 Ruby 语言进行完整介绍。在这里，我们想专注于在使用 CoffeeScript 的情况下构建简单的 Rails 应用程序。

我们不会详细介绍所有内容，并且我们相信 Ruby 是一种非常简单和可读的语言，Rails 代码也很容易理解。即使您不熟悉该语言和框架，也不应该太难跟上。

首先，我们将通过使用`rails`命令创建一个空的基本 Rails 应用程序。转到要创建应用程序的文件夹，然后运行此命令：

```js
rails new todo
```

这将创建一个`todo`文件夹，其中包含用于 Web 应用程序的大量文件和文件夹。遵循惯例，Rails 将以一定的方式组织您的 Web 应用程序。

### 注意

`rails`命令用于许多事情，除了生成新应用程序之外，还作为您进入许多日常 Rails 任务的入口点。我们将在本书中涵盖其中的一些内容，如果您想查看它可以做什么的完整列表，可以运行`rails -h`。

让我们简要谈谈 Rails 如何组织我们的应用程序。您的大部分应用程序代码可能都位于顶级`app`文件夹中。此文件夹包含以下四个重要的子文件夹：

+   `资产：`这是资产管道操作的文件夹。这是您的 CoffeeScript（或 JavaScript）和 CSS 源代码，以及我们的 Web 应用程序使用的图像的位置。

+   `控制器`：这是您的控制器所在的位置。它们负责处理应用程序的路由请求，并与视图和模型进行交互。

+   `模型`：这是您将找到领域模型的位置。模型代表系统中的领域对象，并使用`ActiveRecord`基类对应数据库表。

+   `视图`：此文件夹包含用于呈现应用程序 HTML 的视图模板。默认情况下，Rails 使用 ERB 模板，允许我们在 HTML 模板中包含 Ruby 代码片段，这些代码将被评估以生成最终输出的 HTML。

## MVC

**MVC**，或**Model-View-Controller**，是一种广泛使用的应用程序架构模式，旨在通过将应用程序关注点分为三种领域对象类型来简化代码并减少耦合。

Rails 非常密切地遵循 MVC 模式，大多数 Rails 应用程序在模型、控制器和视图方面都会有很强的结构。

在 MVC 之上的另一个模式是“fat models, skinny controllers”，这是在过去几年中被许多 Rails 程序员所推崇的。这个概念鼓励将大部分领域逻辑放在模型中，并且控制器只关注路由和模型与视图之间的交互。

## 运行我们的应用程序

在这个阶段，我们已经可以运行我们的 Rails 应用程序，看看是否一切正常。从终端输入：

```js
cd todo
rails server
```

Rails 现在将在端口**3000**上为我们的应用程序托管一个本地 Web 服务器。您可以通过浏览`http://localhost:3000/`来测试它。如果一切顺利，您应该会看到以下友好的欢迎消息：

![Running our application](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588_04_01.jpg)

### 提示

记得在我们测试应用程序时，将此服务器保持在单独的控制台窗口中运行。您还可以检查此过程的输出，以查看运行时可能发生的任何错误。

## 我们的 todo_items 资源

因此，我们现在有一个正在运行的应用程序，但除了显示欢迎页面外，它并没有做太多事情。

为了实现跟踪待办任务的目标，我们将为待办事项生成一个资源。在 Rails 术语中，资源包括一个模型、一个带有一些操作的控制器，以及用于这些操作的视图。

在终端上运行以下命令：

```js
rails generate resource todo_item title:string completed:boolean
```

这样做有什么作用？这是 Rails 生成器语法的一个例子，可以用来生成样板代码。在这里，我们告诉它创建一个名为`TodoItemsController`的“资源”控制器和一个名为`TodoItem`的模型，该模型具有一个`string`字段作为标题和一个`boolean`标志来标记它是否已完成。

从命令输出中可以看到，它生成了一堆文件，并修改了一个现有文件，在`config/routes.rb`中。让我们首先打开这个文件。

## routes.rb

以下是您应该在`routes.rb`文件顶部看到的内容：

```js
Todo::Application.routes.draw do
 resources :todo_items

```

在 Rails 中，`routes.rb`定义了 HTTP 调用 URL 与可以处理它们的控制器操作之间的映射关系。

在这里，生成器为我们添加了一行，使用了`resources`方法。此方法使用 HTTP 动词 GET、POST、PUT 和 DELETE 为应用程序中的“资源”控制器创建路由。这意味着它使用 HTTP 动词在应用程序中公开单个域资源。

通常，这将为七个不同的控制器操作创建路由，`index`、`show`、`new`、`create`、`edit`、`update`和`destroy`。正如您将在后面看到的，我们不需要为我们的控制器创建所有这些操作，因此我们将告诉`resources`方法仅筛选出我们想要的操作。修改文件，使其看起来像以下代码片段：

```js
Todo::Application.routes.draw do
 resources :todo_items, only: [:index, :create, :update, :destroy]

```

## 控制器

在对`resources`的调用中，Rails 使用`:todo_items`符号来按照惯例将`resources`方法映射到`TodoItemsController`，这也是为我们生成的。

打开`app/controllers/todo_items_controller.rb`文件；您将看到以下内容：

```js
class TodoItemsController < ApplicationController
end
```

如您所见，这里并没有太多内容。声明了一个名为`TodoItemController`的类，并且它派生自`ApplicationController`类。当我们创建应用程序时，还为我们生成了`ApplicationController`类，并且它派生自`ActionController::Base`，这使它具有大量功能，并使其可以像 Rails 控制器一样运行。

我们现在应该能够通过导航到`http://localhost:3000/todo_items` URL 来测试我们的控制器。

你看到了什么？您应该会收到**未知操作**错误页面，指出`TodoItemsController`找不到`index`操作。

这是因为控制器尚未定义`index`操作，如我们的`routes.rb`文件中所指定的。让我们继续向`TodoItemsController`类添加一个方法来处理该操作；以下是示例代码片段：

```js
class TodoItemsController < ApplicationController
 def index
 end
end
```

如果我们刷新页面，我们会得到一个不同的错误消息：**模板丢失**。这是因为我们没有 `index` 动作的模板。默认情况下，Rails 总是会尝试返回与 `index` 动作名称对应的呈现模板。让我们继续添加一个。

## 视图

Rails 视图保存在 `app/views` 文件夹中。每个控制器都会在这里有一个包含其视图的子文件夹。我们已经有一个来自上一章的 `index.html` 文件，我们将在这里重用。为了做到这一点，我们需要将旧的 `index.html` 文件中 `body` 标签内的所有内容（不包括最后两个 `script` 标签）复制到一个名为 `app/views/todo_items/index.html.erb` 的文件中。

你应该最终得到以下标记：

```js
<section id="todoapp">
  <header id="header">
    <h1>todos</h1>
    <input id="new-todo" placeholder="What needs to be done?" autofocus>
  </header>
  <section id="main">
    <ul id="todo-list">

    </ul>
  </section>
  <footer id="footer">
      <button id="clear-completed">Clear completed</button>
  </footer>
</section>
```

看到这里，你可能会想知道其他 HTML 的部分，比如封闭的 `html`、`head` 和 `body` 标签去了哪里。

嗯，Rails 有一个布局文件的概念，它作为所有其他视图的包装器。这样你就可以为你的站点拥有一个一致的骨架，而不需要为每个视图创建。我们的视图将嵌入到默认布局文件中：`app/views/layouts/application.html.erb`。让我们来看看那个文件：

```js
<!DOCTYPE html>
<html>
<head>
  <title>Todo</title>
  <%= stylesheet_link_tag    "application", :media => "all" %>
  <%= javascript_include_tag "application" %>
  <%= csrf_meta_tags %>
</head>
<body>

<%= yield %>

</body>
</html>
```

`stylesheet_link_tag` 和 `javascript_include_tag` 方法将确保在 HTML 中包含在 `assets` 文件夹中指定的所有文件。`<%= yield %>` 行是当前视图将被呈现的地方，这在我们的情况下是 `index.html.erb`。

现在刷新页面，我们会看到 `index` 页面。查看源代码，了解最终的 HTML 输出。

正如你所看到的，我们的页面仍然没有样式，看起来相当沉闷。让我们看看是否可以再次让它看起来漂亮。

## CSS

默认情况下，资产管道将在 `app/assets/stylesheets` 文件夹中查找 CSS 文件。当我们浏览到这个文件夹时，我们会看到一个名为 `todo_items.css.scss` 的文件，这是在我们创建控制器时为我们生成的。

将上一章的 `styles.css` 文件的内容复制到这个文件中。我们的 `index` 页面现在应该看起来还不错。

### 注意

这个带有奇怪 `.css.scss` 扩展名的文件是一个 Saas 文件（[`sass-lang.com/`](http://sass-lang.com/)）。

与 CoffeeScript 一样，Sass 是普通 CSS 语言的扩展版本，具有许多使编写 CSS 更容易和不那么重复的好功能。

与 CoffeeScript 一样，它是 Rails 资产管道中的默认 CSS 编译器。我们使用的 Sass 变体是 CSS 的超集，这意味着我们可以在这个文件中使用普通的 CSS 而不使用任何 Sass 功能，它也可以正常工作。

## 我们的模型

现在我们可以看到我们的待办事项列表，但没有任何项目显示出来。这一次，我们不会将它们存储在本地，而是将它们存储在数据库中。幸运的是，当我们创建资源和 `TodoItem` 模型时，已经为我们生成了一个数据库模型，它在 `app/models/todo_item.rb` 中定义：

```js
class TodoItem < ActiveRecord::Base
  attr_accessible :completed, :title
end
```

在这里，就像控制器一样，你可以看到 Rails 模型通过从 `ActiveRecord::Base` 派生来获得大部分功能。`attr_accessible` 行告诉 `ActiveRecord` 这个模型上的哪些字段可以被分配给用户输入和从用户输入中分配。

我们如何使用模型？在 `todo_items_controller.rb` 中添加以下突出显示的代码：

```js
  def index
 @todo_items = TodoItem.all
  end
```

这一行在 `TodoItem` 类上使用了一个 `all` 类方法，这也是由 `ActiveRecord` 提供的。这将为数据库中的每条记录返回一个 `TodoItem` 类的新实例，我们可以将其分配给一个名为 `@todo_items` 的实例变量（在 Ruby 中，所有实例变量都以 `@` 符号开头）。

当 Rails 执行控制器动作时，它会自动使任何控制器实例变量可用于正在呈现的视图，这就是我们在这里分配它的原因。我们很快就会在我们的视图中使用它。

让我们再次刷新页面，看看这是否有效。再一次，我们得到了一个**找不到表 'todo_items'**的错误。

您可能已经猜到我们应该在某个地方的数据库中创建一个名为`todo_items`的表。幸运的是，Rails 已经通过一种称为迁移的方式处理了这项艰苦的工作。

## 迁移

当我们生成资源时，Rails 不仅为我们创建了一个模型，还创建了一个用 Ruby 编写的数据库脚本，或者**迁移**。我们应该能够在`db/migrations`文件夹中打开它。实际文件将以时间戳为前缀，并以`_create_todo_items.rb`结尾。它应该类似于以下代码片段：

```js
class CreateTodoItems < ActiveRecord::Migration
  def change
    create_table :todo_items do |t|
      t.string :title
      t.boolean :completed

      t.timestamps
    end
  end
end
```

这个脚本将创建一个名为`todo_items`的表，其中包含我们在生成`todo_item`资源时指定的字段。它还使用`t.timestamps`方法创建了两个名为`created_at`和`updated_at`的时间戳字段。Rails 将确保这些名称的字段在记录创建或更新时得到适当的时间戳更新。

迁移脚本是自动化数据库更改的一种很好的方式，甚至可以让您回滚以前的更改。您也不必依赖于资源或模型生成器创建的迁移。可以通过运行以下命令生成自定义迁移：

```js
rails generate migration migration_name
```

生成自定义迁移后，您只需实现`up`和`down`方法，当您的迁移被执行或回滚时将调用这些方法。

迁移是使用`rake`命令执行的。`rake`是一个任务管理工具，允许您将任务编写为 Ruby 脚本，然后使用`rake`命令行实用程序运行这些任务。Rails 带有大量内置的`rake`任务，您可以使用以下命令查看它们的完整列表：

```js
rake –T
```

我们目前感兴趣的任务叫做`db:migrate`，让我们运行它，看看会发生什么：

```js
rake db:migrate
```

您应该看到以下输出：

**== CreateTodoItems: migrating ================================================**

**-- create_table(:todo_items)**

**-> 0.0011s**

**== CreateTodoItems: migrated (0.0013s) =======================================**

这意味着 Rails 已成功在数据库中为我们创建了一个`todo_items`表。当我们刷新应用程序页面时，应该看到错误已经消失，我们看到了空白的待办事项列表。

### 提示

**数据库在哪里？**

您可能想知道我们的实际数据库目前在哪里。Rails 默认使用嵌入式 SQLite 数据库。SQLite ([`www.sqlite.org`](http://www.sqlite.org))是一个自包含的基于文件的数据库，不需要配置服务器即可运行。这使得在开发应用程序时快速启动变得非常简单和方便。

一旦您实际部署您的 Web 应用程序，您可能希望使用更传统的数据库服务器，如 MySQL 或 PostgreSQL。您可以在`config/database.yml`文件中轻松更改数据库连接设置。

我们还没有将我们的视图连接起来，以实际显示待办事项列表。在这之前，让我们在数据库中手动创建一些待办事项。

## Rails 控制台

Rails 有一种巧妙的方式可以通过使用 Rails 控制台与您的代码进行交互。这是一个交互式的 Ruby 解释器，或者**irb**，会话加载了所有 Rails 项目代码。让我们使用以下命令启动它：

```js
rails console
```

一旦您进入控制台，您可以输入任何有效的 Ruby 代码。您还可以访问 Rails 应用程序中的所有模型。让我们尝试一下我们之前使用的`TodoItem.all`方法；这在以下截图中显示：

![The Rails consoleRails consoleabout](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588_04_02.jpg)

目前它返回一个空数组，因为我们的表还是空的。请注意，Rails 还输出了它生成的 SQL 查询，以获取所有记录。

从这里，我们还可以使用我们的模型创建一个新的待办事项。以下代码将完成这个任务：

```js
TodoItem.create(title: "Hook up our index view", completed: false)
```

现在，我们的表中应该有一个待办事项。您可以使用`TodoItem.first`来验证这一点，它将返回我们表中的第一项。

我想确保我们的模型始终有一个标题。`ActiveRecord`具有非常强大的内置验证功能，允许以非常声明性的方式指定模型属性的约束。让我们确保我们的模型在保存之前始终检查标题是否存在；为此，请添加以下突出显示的代码：

```js
class TodoItem < ActiveRecord::Base
  attr_accessible :completed, :title
 validates :title,  :presence => true
end
```

继续创建另外几个待办事项。完成后，尝试再次运行`TodoItem.all`。这次它将返回一个`TodoItem`实例数组。

### 注意

要退出 rails 控制台，只需输入`exit`。

## 使用 ERB 在视图中显示项目

为了在我们的视图中显示待办事项，我们将使用在控制器动作中创建的`@todo_items`实例变量。让我们修改`app/views/todo_items.html.erb`文件，并使用 ERB 混合一些 Ruby；添加以下代码片段中突出显示的代码：

```js
<section id="todoapp">
  <header id="header">
    <h1>todos</h1>
    <input id="new-todo" placeholder="What needs to be done?" autofocus>
  </header>
  <section id="main">
    <ul id="todo-list">
 <% @todo_items.each do |item| %>
 <li class="<%= item.completed ? "completed" : "" %>" data-id="<%= item.id %>">
 <div class="view">
 <input class="toggle" type="checkbox" <%= "checked" if item.completed %>>
 <label><%= item.title %></label>
 <button class="destroy"></button>
 </div>
 </li> 
 <% end %>
    </ul>
  </section>
  <footer id="footer">
      <button id="clear-completed">Clear completed</button>
  </footer>
</section>
```

ERB 模板非常简单易懂。基本思想是你按照正常方式编写 HTML，并使用 ERB 标记混合 Ruby。以下三个标记很重要：

```js
<% These tags will be just be executed  %>
<%= These should contain a Ruby expression that will be evaluated and included in the document %>
<%# This is a comment and will be ignored %>
```

在我们的`index` ERB 模板中，我们使用 Ruby 的`each`迭代器来循环遍历`@todo_items`数组实例变量中的所有元素；`each`以 Ruby 块作为参数。块是可以作为数据传递给方法的代码片段，类似于 CoffeeScript 中可以作为参数传递函数。

这个块将针对数组中的每个项目执行，将其作为 item 变量传递进来。对于每个项目，我们使用项目的`title`和`completed`属性在我们的 ERB 标记内部创建其标记。

当我们刷新页面时，现在应该终于看到我们的待办事项列表了！如果你好奇的话，可以查看文档的 HTML 源代码，并将其与 ERB 模板进行比较，这应该让你对它是如何生成的有一个很好的了解。输出页面如下截图所示：

![使用 ERB 在视图中显示项目](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588_04_03.jpg)

## 创建一个部分

目前，我们的视图代码开始变得有点混乱，特别是待办事项列表。我们可以通过使用**视图部分**来稍微整理一下，这允许我们将视图的片段提取到一个单独的文件中。然后可以在主视图中渲染它。将以下代码片段中突出显示的代码行添加到您的文件中：

```js
  <section id="main">
    <ul id="todo-list">
      <% @todo_items.each do |item| %>
 <%= render partial: 'todo_item', locals: {item: item} %>
      <% end %>
    </ul>

  </section>
```

我们将待办事项的标记移到自己的部分文件中。按照惯例，部分文件名以下划线开头，当渲染部分时，Rails 将查找与指定部分相同名称的文件，以下划线开头。继续创建一个文件：`app/views/todo_items/_todo_item.html.erb`，内容如下：

```js
<li class="<%= item.completed ? "completed" : "" %>" data-id="<%= item.id %>">
  <div class="view">
    <input class="toggle" type="checkbox" <%= "checked" if item.completed %>>
    <label><%= item.title %></label>
    <button class="destroy"></button>
  </div>
</li>
```

如果一切顺利，我们的视图应该像以前一样工作，而且我们已经很好地清理了主视图代码。使用部分简化视图对于可重用性也非常有用，我们稍后会看到。

我们的待办事项应用程序仍然需要一些工作。目前，我们无法添加新任务，已完成的任务和删除操作也无法正常工作。这需要一些客户端代码，这意味着我们终于可以开始使用一些 CoffeeScript 了。

## 添加新项目

为了向待办事项列表中添加新项目，我们将使用 Rails 的一些原生 AJAX 功能。以下代码片段是我们`index`视图上`todo`输入的修改版本：

```js
  <header id="header">
    <h1>todos</h1>
 <%= form_for TodoItem.new, :method => :post, :remote => true do |f| %> 
 <%= f.text_field :title, id:'new-todo', placeholder: 'What needs to be done?', autofocus: true  %>
 <% end %>
  </header>
```

那么这里有什么变化呢？首先，你会注意到我们已经包含了`form_for`方法，并在其块内部再次调用了`text_field`。这些是 Rails 的视图助手，它们是视图内部可用的 Ruby 方法，提供了构建 HTML 输出的方式。

`form_for`方法将输出一个 HTML`form`标签，而`text_field`方法将在表单内生成一个`input`标签，类型为`text`。

我们将一个新的`TodoItem`实例作为参数传递给`form_for`方法。Rails 足够聪明，能够从`TodoItem`实例中知道表单的 URL 应该指向`TodoItemController`，并且将使用`TodoItem`模型的属性作为表单内部输入的名称。

真正的魔力在于发送给`form_for`方法的`remote => true`参数。这告诉 Rails 你希望使用 AJAX 提交这个表单。Rails 将在后台处理所有这些。

那么我的表单将提交到哪个控制器动作？由于我们指定了它的动作为`post`，它将映射到`TodoItemController`中的`create`动作。我们还没有这个动作，所以让我们去写它：

```js
  def create 
    @todo_item = TodoItem.create(params[:todo_item])
  end
```

在这里，我们使用`params`中的`:todo_item`键创建`TodoItem`—`params`是 Rails 创建的 Ruby 哈希。它包含一个带有键`:todo_items`的值，这是一个包含从表单提交的所有参数值的哈希。当我们将这个哈希传递给`TodoItem.create`方法时，Rails 将知道如何将它们映射到我们新模型上的属性并保存到数据库中。

## 让我们尝试添加一个待办事项

在我们的输入框中输入一个新的待办事项标题，然后按*Enter*。

然而，似乎什么都没有发生。我们可以前往正在运行的 Rails 服务器会话的输出，看看是否能发现任何错误。如果你滚动一下，你应该会看到一个类似以下错误消息的错误：

**ActionView::MissingTemplate (Missing template todo_items/create, application/create with {:locale=>[:en], :formats=>[:js, "application/**

**ecmascript", "application/x-ecmascript", :html, :text, :js, :css, :ics, :csv, :png, :jpeg, :gif, :bmp, :tiff, :mpeg, :xml, :rss, :atom,**

**:yaml, :multipart_form, :url_encoded_form, :json, :pdf, :zip], :handlers=>[:erb, :builder, :coffee]}. Searched in:**

*** "/home/michael/dev/todo/app/views"**

**)**

## 添加 CoffeeScript 视图

所以，看起来我们还需要做一件事。所有控制器动作默认都会尝试渲染视图。当我们现在尝试添加待办事项时，我们会得到与之前相同的**模板丢失**错误。可能不清楚应该发生什么，因为表单是使用 AJAX 提交的。我们是否仍然应该渲染一个视图？它会是什么样子？

仔细看一下错误消息可能会给我们一些线索。由于我们的动作是使用 AJAX 调用的，Rails 默认会寻找一个 CoffeeScript 视图来渲染为 JavaScript。

生成的 JavaScript 将作为对 AJAX 调用的响应，并在完成时执行。这似乎也是更新我们的待办事项列表的完美地方，之后在服务器上创建它。

我们将为`app/views/todo_items/create.js.coffee`中的`create`动作创建一个 CoffeeScript 视图模板。

```js
$('#new-todo').val('')
html = "<%= escape_javascript(render partial: 'todo_item', locals: {item: @todo_item}) %>"
$("#todo-list").append(html)
```

在前面的代码片段中，我们获取`#new-todo`输入并清除其值。然后我们渲染与之前相同的`todo_item`部分，传入我们在控制器动作中创建的`@todo_item`实例变量。

我们将渲染调用包装在`escape_javascript`辅助方法中，这将确保我们字符串中的任何特殊 JavaScript 字符都会被转义。然后我们将新渲染的部分附加到我们的`#todo-list`元素中。

试一下。我们现在终于可以创建待办事项列表了！

### 提示

**jQuery 是从哪里来的？**

Rails 已经为我们包含了 jQuery。Rails 资产管道使用一个清单文件`app/assets/javascript/application.js`来包含所需的依赖项，例如 jQuery。

## 资产管道中的 CoffeeScript

注意这一切是多么无缝？Rails 将 CoffeeScript 视为其堆栈中的一等公民，并确保在使用之前将`.coffee`文件编译为 JavaScript。事实上，你还可以在服务器上使用 ERB 模板预处理你的 CoffeeScript，这使其更加强大。

## 完成待办事项

让我们连接这个功能。这一次，我们将以稍有不同的方式来展示在 Rails 中编写 CoffeeScript 的不同风格。我们将遵循更传统的方法来处理 AJAX 调用。

Rails 已经创建了一个文件，我们可以在其中放置我们的客户端代码，当我们创建控制器时。每个控制器都将有自己的 CoffeeScript 文件，它将自动包含在该控制器的任何操作的页面中。

### 提示

还有一个`application.js.coffee`文件，可以在其中添加全局客户端代码。

我们感兴趣的文件将是`app/assets/views/javascripts/todo_items.js.coffee`。我们可以用以下代码替换它的内容，这将在完成任务时处理 AJAX 调用：

```js
toggleItem = (elem) ->
  $li = $(elem).closest('li').toggleClass("completed")
  id = $li.data 'id'

  data = "todo_item[completed]=#{elem.checked}"
  url = "/todo_items/#{id}"
  $.ajax
    type: 'PUT'
    url: url
    data: data

$ ->
  $("#todo-list").on 'change', '.toggle', (e) -> toggleItem e.target
```

首先，我们定义一个名为`toggleItem`的函数，我们设置当复选框值改变时调用它。在这个函数中，我们切换父`li`元素的`completed`类，并使用其`data`属性获取待办事项的 ID。然后，我们发起一个 AJAX 调用到`TodoItemController`，以更新复选框的当前选中值。

在我们可以运行这段代码之前，我们需要在我们的控制器中添加一个`update`动作，如下面的代码片段所示：

```js
  def update
    item = TodoItem.find params[:id]
    item.update_attributes params[:todo_item]
    render nothing: true
  end
```

`params[:id]`将是 URL 中 ID 的值。我们使用这个来找到待办事项，然后调用`update_attributes`方法，它就是更新我们的模型并将其保存到数据库。请注意，我们明确告诉 Rails 在这里不要渲染视图，通过调用`render nothing: true`。

设置任务为已完成现在应该可以工作了。请注意，当你刷新页面时，任务保持已完成状态，因为它们已保存到数据库中。

## 移除任务

对于移除任务，我们将遵循非常相似的模式。

在`todo_items.js.coffee`中，添加以下代码：

```js
destroyItem = (elem) ->
 $li = $(elem).closest('li')
 id = $li.data 'id'
 url = "/todo_items/#{id}"
 $.ajax
 url: url
 type: 'DELETE'
 success: -> $li.remove()

$ ->
  $("#todo-list").on 'change', '.toggle', (e) -> toggleItem e.target
 $("#todo-list").on 'click', '.destroy', (e) -> destroyItem e.target

```

在我们的控制器中，添加以下代码：

```js
  def destroy
    TodoItem.find(params[:id]).destroy
    render nothing: true
  end
```

这应该是我们需要移除列表项的全部内容。请注意，这里只有在 AJAX 调用成功时才移除元素，通过处理`success`回调。

## 现在轮到你了

作为对你的最后一项练习，我要求你让“清除已完成”按钮起作用。作为提示，你应该能够使用现有的`destroyItem`方法功能。

# 总结

本章以 Ruby on Rails 的风风火火开始。你已经希望能够欣赏到 Rails 为 Web 开发人员提供的一些魔力，以及开发 Rails 应用程序可以有多么有趣。我们还花了一些时间发现在 Rails 应用程序中使用 CoffeeScript 是多么容易，以及你通常会使用哪些不同的方法和技术来编写客户端代码。

如果你还没有这样做，我鼓励你花一些时间学习 Rails 以及 Ruby，并沉浸在它们支持的美妙社区中。

在下一章中，我们将探索另一个使用 JavaScript 构建的令人兴奋的新服务器框架，以及 CoffeeScript 与其的关系。


# 第五章：CoffeeScript 和 Node.js

Ryan Dahl 于 2009 年创建了 Node.js。他的目标是创建一个可以使用 JavaScript 编写高性能网络服务器应用程序的系统。当时，JavaScript 主要在浏览器中运行，因此需要一种在没有浏览器的情况下运行 JavaScript 的服务器端框架。Node 使用了 Google 的 V8 JavaScript 引擎，最初是为 Chrome 浏览器编写的，但由于它是一个独立的软件，因此可以在任何地方运行 JavaScript 代码。Node.js 允许您编写可以在服务器上执行的 JavaScript 代码。它可以充分利用您的操作系统、数据库和其他外部网络资源。

让我们谈谈 Node.js 的一些特性。

# Node 是事件驱动的

Node.js 框架只允许非阻塞的异步 I/O。这意味着任何访问外部资源（如操作系统、数据库或网络资源）的 I/O 操作必须以异步方式进行。这是通过使用事件或回调来实现的，一旦操作成功或失败，就会触发这些事件或回调。

这样做的好处是，您的应用程序变得更加可扩展，因为请求不必等待慢速 I/O 操作完成，而是可以处理更多的传入请求。

其他语言中也存在类似的框架，比如 Python 中的**Twisted**和**Tornado**，以及 Ruby 中的**EventMachine**。这些框架的一个大问题是，它们使用的所有 I/O 库也必须是非阻塞的。通常，人们可能会意外地使用阻塞 I/O 操作的代码。

Node.js 是从头开始以事件驱动的理念构建的，并且只允许非阻塞 I/O，因此避免了这个问题。

# Node 快速且可扩展

Node.js 使用的 V8 JavaScript 引擎经过高度优化，因此使 Node.js 应用程序非常快速。Node 是非阻塞的事实将确保您的应用程序能够处理许多并发客户端请求，而不会使用大量系统资源。

# Node 不是 Rails

尽管 Node 和 Rails 经常用于构建类似类型的应用程序，但它们实际上是非常不同的。Rails 致力于成为构建 Web 应用程序的全栈解决方案，而 Node.js 更像是一种用于编写任何类型的快速和可扩展网络应用程序的低级系统。它对应用程序的结构几乎没有做出太多假设，除了您将使用基于事件的架构。

因此，Node 开发人员通常可以从许多在 Node 之上构建的用于编写 Web 应用程序的框架和模块中进行选择，比如 Express 或 Flatiron。

# Node 和 CoffeeScript

正如我们之前所看到的，CoffeeScript 作为一个 npm 模块是可用的。因此，使用 CoffeeScript 编写 Node.js 应用程序变得非常容易。事实上，我们之前讨论过的`coffee`命令将默认使用 Node 运行`.coffee`脚本。要使用 CoffeeScript 安装 Node，请参阅第二章 *运行 CoffeeScript*。

# Node 中的“Hello World”

让我们用 CoffeeScript 编写最简单的 Node 应用程序。创建一个名为`hello.coffee`的文件，并输入以下代码：

```js
http = require('http')

server = http.createServer (req, res) ->
  res.writeHead 200
  res.end 'Hello World'

server.listen 8080
```

这使用了 Node.js 的`http`模块，该模块提供了构建 HTTP 服务器的功能。`require('http')`函数将返回`http`模块的一个实例，该实例导出了一个`createServer`函数。这个函数接受一个`requestListener`参数，这是一个响应客户端请求的函数。在这种情况下，我们以 HTTP 状态码`200`做出响应，并以`Hello World`作为请求体结束响应。最后，我们调用返回的服务器的`listen`方法来启动它。当调用这个方法时，服务器将监听并处理请求，直到我们停止它。

我们可以使用 coffee 命令运行这个文件，如下命令所示：

```js
coffee hello.coffee
```

我们可以通过浏览`http://localhost:8080/`来测试我们的服务器。我们应该看到一个只有**Hello World**文本的简单页面。

# Express

正如你所看到的，Node 默认是非常低级和基本的。构建 Web 应用程序基本上意味着编写原始的 HTTP 服务器。幸运的是，在过去几年中已经开发了许多库来帮助在 Node 上编写 Web 应用程序，并抽象掉许多低级细节。

可以说，其中最受欢迎的是**Express**（[`expressjs.com/`](http://expressjs.com/)）。类似于 Rails，它具有许多很好的功能，使得执行常见的 Web 应用程序任务更容易，比如路由、渲染视图和托管静态资源。

在本章中，我们将使用 CoffeeScript 在 Express 中编写 Web 应用程序。

# WebSocket

由于我想展示一些 Node 的可伸缩性特性以及它通常用于的应用程序类型，我们将利用另一种有趣的现代网络技术，称为**WebSocket**。

WebSocket 协议是允许在标准 HTTP 端口**80**上进行原始、双向和全双工（同时双向）TCP 连接的标准。这允许客户端和服务器建立长时间运行的 TCP 连接，服务器可以执行推送操作，这在传统的 HTTP 中通常是不可能的。它经常用于需要在客户端和服务器之间进行大量低延迟交互的应用程序中。

# Jade

Jade 是一种轻量级的标记模板语言，它让你以类似于 CoffeeScript 的语法编写优雅而简短的 HTML。它使用了许多功能，比如语法空白，以减少你编写 HTML 文档所需的按键次数。通常在运行 Express 时默认安装，我们将在本书中使用它。

# 我们的应用程序

在本章中，我们将构建一个协作待办事项列表应用程序。这意味着你将能够实时与其他人分享你的待办事项列表。一个或多个人将能够同时添加、完成或删除待办事项列表项目。待办事项列表的更改将自动传播到所有用户。这是 Node 非常适合的应用类型。

我们的 Node.js 代码将包括两个不同的部分，一个是正常的 Web 应用程序，将提供静态 HTML、CSS 和 JavaScript，另一个是处理实时更新所有待办事项列表客户端的 WebSocket 服务器。除此之外，我们还将有一个由 jQuery 驱动的客户端，看起来与我们在第三章中的应用程序非常相似，*CoffeeScript 和 jQuery*。

我们将使用现有待办事项列表应用程序的一些资源（样式表和图像）。我们还将重用第三章中的客户端 jQuery 代码，并对其进行调整以适应我们的应用程序。如果你之前没有跟着前几章的内容，你应该可以根据需要从本章的代码中复制资源。

# 让我们开始吧

为了开始，我们将执行以下步骤：

1.  为我们的应用程序创建一个文件夹。

1.  使用`package.json`文件指定我们的应用程序依赖项。

1.  安装我们的依赖项。

1.  创建一个`app.coffee`文件。

1.  第一次运行我们的应用程序。

## package.json

创建一个名为`todo`的新文件夹。在这个文件夹中，我们将创建一个名为`package.json`的文件。将以下代码添加到这个文件中：

```js
{
  "name": "todo",
  "version": "0.0.1",
  "private": true,
  "scripts": {
    "start": "node app"
  },
  "dependencies": {
    "express": "3.0.0beta6",
    "jade": "*",
    "socket.io": "*",
    "coffee-script": "*",
    "connect-assets": "*"
  }
}
```

这是一个简单的 JSON 文件，用作应用程序清单，并用于告诉 npm 您的应用程序依赖哪些。在这里，我们将 Express 用作我们的 Web 框架，Jade 用作我们的模板语言。由于我们将使用 WebSocket，我们将引入`socket.io`。我们还可以通过将其添加到我们的文件中来确保 CoffeeScript 已安装。最后，我们将使用`connect-assets`，这是一个管理客户端资产的模块，其方式与 Rails 资产管道非常相似。

在处理 Node.js 框架时，您会注意到应用程序通常是以这种方式由 npm 模块编织在一起的。查找 npm 模块的好地方是 Node 工具箱网站（[nodetoolbox.com](http://nodetoolbox.com)）。

## 安装我们的模块

要安装`package.json`文件中的依赖项，请在命令行工具上导航到项目文件夹并运行以下命令：

```js
npm install
```

如果一切顺利，那么我们现在应该已经安装了所有项目依赖项。要验证这一点，或者只是查看 npm 的操作，您可以运行以下命令：

```js
npm ls
```

这将以树状格式输出已安装模块及其依赖关系的列表。

## 创建我们的应用程序

我们只需要运行我们的应用程序是创建一个主入口文件，用于连接我们的 Express 应用程序并指定我们的路由。在根文件夹中，创建一个名为`app.coffee`的文件，并将以下代码添加到其中：

```js
express = require 'express'
app = express()

app.get '/', (req, res) ->
  res.send('Hello Express')

app.listen(3000)
console.log('Listening on port 3000')
```

这看起来与我们的“Hello World”示例非常相似。

首先，使用`require`函数加载 Express 模块。Node 模块很简单；每个模块对应一个单独的文件。每个模块都可以声明代码，在需要时导出。当您调用`require`时，如果模块的名称不是原生模块或文件路径，Node 将自动在`node_modules`文件夹中查找文件。当然，这就是 npm 安装模块的地方。

在下一行，通过调用`express`函数并将其分配给`app`变量来创建我们的 Express 应用程序。

然后，我们使用`get`方法为我们的应用程序创建一个索引路由。我们指定路径为`'/'`，然后传入一个匿名函数来处理请求。它接受两个参数，`req`和`res`参数。现在，我们只需向响应中写入`Hello Express`并返回。

然后，我们使用`listen`方法启动我们的应用程序，并告诉它在端口`3000`上运行。最后，我们将写入标准输出，以便我们知道应用程序已启动。

正如您所看到的，Express 的魔力在于声明性地设置路由。使用 Express，您可以通过指定 HTTP 方法、URL 路径和处理请求的函数轻松创建路由。

## 运行我们的应用程序

让我们运行我们的应用程序，看看是否一切正常。在我们的应用程序文件夹中，在命令行工具上键入以下内容：

```js
coffee app.coffee
```

您应该会看到输出为**Listening on port 3000**。

将浏览器指向`http://localhost:3000/`。您应该会看到文本**Hello Express**。

要在命令行工具上停止 Node 进程，只需使用*Ctrl* + *C*。

# 创建一个视图

与其他 Web 框架（如 Rails）类似，Express 具有视图的概念，它可以让您使用单独的文件将 UI 与应用程序分离开来。通常，这些是使用 Jade 等模板语言编写的。让我们为我们的根操作创建一个视图。

为此，我们需要：

1.  创建一个`views`文件夹并添加一个 Jade 视图文件。

1.  配置我们的 Express 应用程序以了解存储视图的文件夹，并使用的模板库。

1.  更改我们的索引路由以呈现我们的视图。

让我们在项目根目录中创建一个名为`views`的新文件夹。在此文件夹中，我们创建一个名为`index.jade`的新文件。它应该如下所示：

```js
doctype 5
html
  head
    title Our Jade view
  body
    p= message
```

正如你所看到的，Jade 为普通 HTML 提供了非常干净简洁的语法。你不需要用尖括号来包围标签。与 CoffeeScript 类似，它还使用缩进来界定块，这样你就不必输入闭合标签。`p= message`这一行创建了一个`<p>`标签，其内容将被评估为`message`字段的值，这个值应该被传递到我们的视图选项中。

在我们的`app.coffee`文件中，我们将添加以下代码：

```js
express = require 'express'
path = require 'path'
app = express()

app.set 'views', path.join __dirname, 'views'
app.set 'view engine', 'jade'

app.get '/', (req, res) ->
 res.render 'index', message: "Now we're cooking with gas!"

app.listen(3000)
console.log('Listening on port 3000')
```

在这里，我们使用`set`函数设置`views`文件夹，并分配`'views'`键。我们使用在文件顶部包含的`path`模块来创建和连接我们当前文件夹名到`views`子文件夹。`__dirname`是一个全局变量，指的是当前工作文件夹。我们还将视图引擎设置为`'jade'`。

接下来，我们将改变我们的`get '/'`路由，渲染 index 模板并传递一个包含消息的哈希选项。这个值将在我们的视图中被渲染出来。

一旦我们再次运行我们的应用程序并刷新页面，我们应该能够看到我们的页面已经更新了新的文本。

# node-supervisor

到目前为止，你可能会想知道每次更改代码时是否需要重新启动我们的 Node 应用程序。在开发中，我们希望我们的代码在每次更改时都能自动重新加载，类似于 Rails 的工作方式。

幸运的是，有一个整洁的开源库可以做到这一点：**node-supervisor**（[`github.com/isaacs/node-supervisor`](https://github.com/isaacs/node-supervisor)）。我们像安装其他 npm 模块一样安装它，只是要确保传递`-g`标志来全局安装它，如下面的命令所示：

```js
npm install supervisor -g
```

在终端中，你现在应该能够通过以下命令运行监督者：

```js
supervisor app.coffee
```

在一个单独的窗口中保持这个过程运行。为了查看这是否起作用，让我们编辑发送到我们视图的消息；在下面的代码片段中，高亮显示了编辑后的消息：

```js
app.get '/', (req, res) ->
 res.render 'index', message: "Now we're cooking with supervisor!"

```

如果我们现在刷新页面，我们将看到它已经更新了。从现在开始，我们可以确保监督者在运行，并且我们不需要重新启动我们的 Node 进程来进行更改。

# 待办事项列表视图

现在让我们扩展我们的视图，使其看起来像我们真正的待办事项应用程序。编辑`index.jade`文件如下所示：

```js
doctype 5
html
  head
 title Collaborative Todo
  body
 section#todoapp
 header#header
 h1 todos
 input#new-todo(placeholder="What needs to be done?", autofocus=true)
 section#main
 ul#todo-list
 footer#footer
 button#clear-completed Clear completed

```

这是一些我们以前没有见过的新的 Jade 语法。标签 ID 由`#`符号表示，所以`header#header`变成了`<header id="header">`。标签属性在括号内指定，就像这样：`tag(name="value")`。

由于我们不再在模板中使用`message`变量，我们将从`app.coffee`文件的`render`调用中删除它，如下面的代码片段所示：

```js
app.get '/', (req, res) ->
 res.render 'index'

```

我们的页面现在将被更新，但看起来不太好。我们将使用在上一个项目中使用的相同样式表来为我们的页面设置样式。

### 提示

**没有按预期工作？**

记得要留意监督者进程的输出，看看你的 CoffeeScript 或 Jade 模板中是否有语法错误，特别是如果你没有看到预期的输出。

在使用样式表之前，我们需要设置 Express 为我们提供静态文件服务。修改`app.coffee`文件如下所示：

```js
express = require 'express'
path = require 'path'

app = express()

app.set 'views', path.join __dirname, 'views'
app.set 'view engine', 'jade'
app.use(express.static(path.join __dirname, 'public'))

```

在前面的代码片段中发生了什么？我们添加了一行支持为静态文件提供服务，但这是如何工作的呢？答案在于 Node 如何使用中间件。

## 中间件

Express 框架是建立在一个名为**Connect**的低级框架之上的（[`www.senchalabs.org/connect/`](http://www.senchalabs.org/connect/)）。Connect 的基本思想是为 Web 请求提供中间件。

中间件可以链接在一起形成一个 Web 应用程序堆栈。每个中间件只关心通过修改输出响应或请求的控制流来提供一小部分功能。

在我们的示例中，我们告诉我们的应用程序使用`express.static`函数创建的中间件。这个函数将为提供的文件路径创建一个静态文件服务器。

## 我们的样式表

创建一个名为`public`的文件夹，其中包含一个名为`css`的子文件夹。将样式表保存为此文件夹中的`todo.css`。我们仍然需要在我们的`index`视图中包含样式表。在`views`文件夹中的`index.jade`文件中添加以下行-在代码片段中突出显示：

```js
doctype 5
html
  head
  title  Collaborative Todo
 link(rel="stylesheet", href="css/todo.css")
  body
```

一旦我们链接到我们的样式表，我们应该能够刷新我们的视图。现在它应该看起来更好。

# 客户端

为了使我们的待办事项应用程序工作，我们将复制在第三章中创建的客户端 jQuery 代码，*CoffeeScript 和 jQuery*。我们将把它放在一个名为`todo.coffee`的文件中。

我们接下来的决定是，我们应该把这个文件放在哪里？我们如何编译和在我们的应用程序中使用它的输出？

我们可以做与我们在第三章中构建应用程序时一样的事情，也就是创建一个包含客户端 CoffeeScript 代码的`src`文件夹，然后使用`coffee`命令和`--watch`标志进行编译。输出的 JavaScript 然后可以放在我们的`public`文件夹中，我们可以像平常一样包含它。但这意味着我们将有两个独立的后台任务运行，一个是运行我们的服务器的监督任务，另一个是编译我们的客户端代码的任务。

幸运的是有更好的方法。您可能还记得我们在`package.json`文件中有一个对`connect-assets`模块的引用。它为我们提供了一个类似于 Rails 的资产管道。它将透明地处理编译和依赖管理。

我们需要在我们的`app.coffee`文件中使用中间件，如下面的代码片段中所示：

```js
app.set 'views', path.join __dirname, 'views'
app.set 'view engine', 'jade'
app.use(express.static(path.join __dirname, 'public'))
app.use require('connect-assets')()

```

`connect-assets`模块将默认使用`assets`文件夹来管理和提供资产。让我们在我们的根文件夹内创建一个名为`assets/js`的文件夹。我们将在这个文件夹中创建一个名为`todo.coffee`的新文件，其中包含以下代码：

```js
Storage::setObj = (key, obj) ->
  localStorage.setItem key, JSON.stringify(obj)

Storage::getObj = (key) ->
  JSON.parse this.getItem(key)

class TodoApp

  constructor: ->
    @cacheElements()
    @bindEvents()
    @displayItems()

  cacheElements: ->
    @$input = $('#new-todo')
    @$todoList = $('#todo-list')
    @$clearCompleted = $('#clear-completed')

  bindEvents: ->
    @$input.on 'keyup', (e) => @create e
    @$todoList.on 'click', '.destroy', (e) => @destroy e.target
    @$todoList.on 'change', '.toggle', (e) => @toggle e.target
    @$clearCompleted.on 'click', (e) => @clearCompleted()

  create: (e) ->
    val = $.trim @$input.val()
    return unless e.which == 13 and val

    randomId = Math.floor Math.random()*999999

    localStorage.setObj randomId,{
      id: randomId
      title: val
        completed: false
    }
    @$input.val ''
    @displayItems()

  displayItems: ->
    @clearItems()
    @addItem(localStorage.getObj(id)) for id in Object.keys(localStorage)

  clearItems: ->
    @$todoList.empty()

  addItem: (item) ->
    html = """
      <li #{if item.completed then 'class="completed"' else ''} data-id="#{item.id}">
        <div class="view">
          <input class="toggle" type="checkbox" #{if item.completed then 'checked' else ''}>
          <label>#{item.title}</label>
          <button class="destroy"></button>
        </div>
     </li>
    """
    @$todoList.append html

  destroy: (elem) ->
    id = ($(elem).closest 'li').data('id')
    localStorage.removeItem id
    @displayItems()

  toggle: (elem) ->
    id = $(elem).closest('li').data('id')
    item = localStorage.getObj(id)
    item.completed = !item.completed
    localStorage.setObj(id, item)

  clearCompleted: ->
    (localStorage.removeItem id for id in Object.keys(localStorage) \
      when (localStorage.getObj id).completed)
    @displayItems()

$ ->
  app = new TodoApp()
```

如果您在第三章中跟着做，*CoffeeScript 和 jQuery*，那么这段代码应该很熟悉。这是我们完整的客户端应用程序，显示待办事项并在`localStorage`中创建、更新和销毁项目。

为了在我们的 HTML 中使用这个文件，我们仍然需要包含一个`script`标签。因为我们使用了 jQuery，我们还需要在我们的 HTML 中包含这个库。

在`index.jade`文件的底部添加以下代码：

```js
script(src="img/jquery.min.js")
!= js('todo')
```

正如你所看到的，我们使用 Google CDN 包含了一个指向 jQuery 的链接。然后我们使用`connect-assets`提供的`js`辅助函数创建一个指向我们编译后的`todo.js`文件的`script`标签（`connect-assets`模块会透明地编译我们的 CoffeeScript）。`!=`符号是 Jade 语法中用来运行 JavaScript 函数及其结果的表示方式。

如果一切顺利，我们应该能够刷新页面并拥有一个工作的客户端页面应用程序。尝试添加新项目，标记项目为完成，删除项目和清除已完成的项目。

# 添加协作

现在我们准备为我们的待办事项列表应用程序添加协作。我们需要创建一个页面，多个用户可以连接到同一个待办事项列表，并可以同时编辑它，实时看到结果。

我们希望支持命名列表的概念，您可以加入其他人一起协作。

在我们深入功能之前，让我们稍微调整一下我们的 UI，以支持所有这些。

# 创建协作 UI

首先，我们将添加一个输入字段来指定一个列表名称和一个按钮来加入指定的列表。

对我们的`index.jade`文件进行以下更改（在代码片段中突出显示），将添加一个`input`元素和一个`button`元素来指定我们的列表名称并加入它：

```js
      footer#footer
 | Join list:
 input#join-list-name
 button#join Join
        button#clear-completed Clear completed
  script(src="img/jquery.min.js")
  != js('todo')
```

我们的页面现在应该看起来像以下截图中显示的页面：

![创建协作 UI](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588_05_01.jpg)

# 客户端上的 WebSocket

现在让我们为用户点击**加入**按钮时连接到一个房间添加一个事件处理程序。

在我们的`todo.coffee`文件中，我们将在`cacheElements`和`bindEvents`函数中添加以下代码：

```js
cacheElements: ->
    @$input = $('#new-todo')
    @$todoList = $('#todo-list')
    @$clearCompleted = $('#clear-completed')
 @$joinListName = $("#join-list-name")
 @$join = $('#join')

  bindEvents: ->
    @$input.on 'keyup', (e) => @create e
    @$todoList.on 'click', '.destroy', (e) => @destroy e.target
    @$todoList.on  'change', '.toggle', (e) => @toggle e.target
    @$clearCompleted.on 'click', (e) => @clearCompleted()
 @$join.on 'click', (e) => @joinList()

```

我们获取`join-list-name`输入和`join`按钮元素，并将它们存储在两个实例变量中。然后我们在`@$join`按钮上设置`click`处理程序，以调用一个名为`joinList`的新函数。让我们继续定义这个函数。在定义`bindEvents`函数之后，将其添加到类的末尾：

```js
clearCompleted: ->
    (localStorage.removeItem id for id in Object.keys(localStorage) \
      when (localStorage.getObj id).completed)
    @displayItems()

 joinList: ->
 @socket = io.connect('http://localhost:3000')

 @socket.on 'connect', =>
@socket.emit 'joinList', @$joinListName.val()

```

这是我们开始使用 Socket.IO 的地方。Socket.IO 库分为两部分：用于打开 WebSocket 连接、发出请求和接收响应的客户端库，以及用于处理请求的服务器端节点模块。

在上述代码中，`joinList`函数使用`io.connect`函数打开一个新的套接字，并传入 URL。然后它使用`on`函数传递一个处理程序函数，在 WebSocket 连接建立后运行。

成功连接处理程序函数将反过来使用`socket.emit`函数，这允许我们使用`joinList`作为标识符向服务器发送自定义消息。我们将`@joinListName`输入的值作为其值传递。

在我们开始实现服务器端代码之前，我们仍然需要包含一个`script`标签来使用`socket.io`客户端库。在`index.jade`文件的底部添加以下突出显示的`script`标签：

```js
script(src="img/jquery.min.js")
script(src="img/socket.io.js")
!= js('todo')
```

您可能想知道这个文件是从哪里来的。接下来，我们将在`app.coffee`文件中设置 Socket.IO 中间件。这将为我们托管客户端库。

# 服务器端的 WebSocket

我们的客户端代码已准备好发出 WebSocket 请求；现在我们可以转向我们的 Node 后端。首先，我们需要设置 Socket.IO 中间件。这有一个小问题，即我们不能直接将 Socket.IO 用作 Express 应用程序的中间件，因为 Socket.IO 需要一个 Node.js HTTP 服务器，并且不直接支持 Express。相反，我们将使用内置的 Node.js HTTP 模块创建一个 Web 服务器，将我们的 Express 应用程序作为`requestListener`传递。然后我们可以使用 Socket.IO 的`listen`函数连接到服务器。

以下是我们的`app.coffee`文件中代码的样子：

```js
express = require 'express'
path = require 'path'

app = express()
server = (require 'http').createServer app
io = (require 'socket.io').listen server

app.set 'views', path.join __dirname, 'views'
app.set 'view engine', 'jade'
app.use(express.static(path.join __dirname, 'public'))
app.use (require 'connect-assets')()

app.get '/', (req, res) ->
  res.render 'index'

io.sockets.on 'connection', (socket) =>
 console.log('connected')
 socket.on 'joinList', (list) => console.log "Joining list #{list}"

server.listen(3000)
console.log('Listening on port 3000')
```

`io.sockets.on 'connection'`函数处理客户端连接时的事件。在这里，我们记录到控制台我们已连接，并设置`joinList`消息处理程序。现在，我们将只是将从客户端接收到的值记录到控制台。

现在我们应该能够测试连接到一个列表。刷新我们的待办事项列表主页并输入要加入的列表名称。点击**加入**按钮后，转到我们的后台监督任务。您应该会看到类似以下消息的内容：

**连接**

**加入列表迈克尔的列表**

成功了！我们已成功创建了双向 WebSocket 连接。到目前为止，我们还没有真正加入任何列表，所以让我们继续做这件事。

# 加入列表

要加入列表，我们将使用 Socket.IO 的一个特性叫做**rooms**。它允许 Socket.IO 服务器对其客户端进行分段，并向所有连接的客户端的子集发出消息。在服务器端，我们将跟踪每个房间的待办事项列表，然后告诉客户端在连接时同步其本地列表。

我们将在`app.coffee`文件中添加以下突出显示的代码：

```js
@todos = {}
io.sockets.on 'connection', (socket) =>
  console.log('connected')
  socket.on 'joinList', (list) =>
    console.log "Joining list #{list}"
 socket.list = list
 socket.join(list)
 @todos[list] ?= []
 socket.emit 'syncItems', @todos[list]

```

我们将`@todos`实例变量初始化为空哈希。它将使用列表名称作为键，保存每个房间的待办事项列表。在`joinList`处理程序函数中，我们将`socket`变量的`list`属性设置为客户端传入的列表名称。

然后，我们使用`socket.join`函数将我们的列表加入到具有该名称的房间中。如果房间尚不存在，它将被创建。然后，我们将空数组值分配给`@todos`中键等于`list`的项目。`?=`运算符只会在右侧的值为`null`时将右侧的值分配给左侧的对象。

最后，我们使用`socket.emit`函数向客户端发送消息。`syncItems`标识符将告诉它将其本地数据与我们传递给它的待办事项列表同步。

要处理`syncItems`消息，我们需要使用以下突出显示的代码更新`todo.coffee`文件：

```js
  joinList: ->
    @socket = io.connect('http://localhost:3000')
    @socket.on 'connect', => 
   @socket.emit 'joinList', @$joinListName.val()

 @socket.on 'syncItems', (items) =>
 @syncItems(items)

 syncItems: (items) ->
 console.log 'syncing items'
 localStorage.clear()
 localStorage.setObj item.id, item for item in items
 @displayItems()

```

加入列表后，我们设置客户端连接以处理`syncItems`消息。我们期望接收刚刚加入的列表的所有待办事项。`syncItems`函数将清除`localStorage`中的所有当前项目，添加所有新项目，然后显示它们。

## UI

最后，让我们更新我们的 UI，以便用户知道他们何时加入了列表，并让他们离开。我们将在我们的`index.jade`文件中修改我们的`#footer div`标记如下：

```js
doctype 5
html
  head
  title  Collaborative Todo
  link(rel="stylesheet", href="css/todo.css")
  body
    section#todoapp
      header#header
        h1 todos
        input#new-todo(placeholder="What needs to be done?", autofocus=true)
      section#main
        ul#todo-list
 footer#footer
 section#connect
          | Join list:
          input#join-list-name
          button#join Join
          button#clear-completed Clear completed
 section#disconnect.hidden
 | Joined list: &nbsp
 span#connected-list List name
 button#leave Leave
    script(src="img/jquery.min.js")
    script(src="img/socket.io.js")
    != js('todo')
```

在先前的标记中，我们已经在`footer div`标记中添加了两个新部分。每个部分将根据我们所处的状态（`connected`或`disconnected`）而隐藏或显示。`connect`部分与以前相同。`disconnect`部分将显示您当前连接到的列表，并有一个**Leave**按钮。

现在我们将在`todo.coffee`文件中添加代码，以便在加入列表时更新 UI。

首先，我们将在我们的`cacheElements`函数中缓存新元素，如下面的代码段所示：

```js
cacheElements: ->
    @$input = $('#new-todo')
    @$todoList = $('#todo-list')
    @$clearCompleted = $('#clear-completed')
 @$joinListName = $("#join-list-name")
 @$join = $('#join')
 @$connect = $('#connect')
 @$disconnect = $('#disconnect')
 @$connectedList = $('#connected-list')
 @$leave = $('#leave')

```

接下来，我们将更改 UI 以显示在调用`syncItems`（在成功加入列表后由服务器触发）时我们处于`connected`状态。我们使用`@currentList`函数，我们将在`joinList`函数中设置；添加以下代码段中突出显示的代码：

```js
  joinList: ->
    @socket = io.connect('http://localhost:3000')
    @socket.on 'connect', =>
 @currentList = @$joinListName.val()
      @socket.emit 'joinList', @currentList

    @socket.on 'syncItems', (items) => @syncItems(items)

  syncItems: (items) ->
    console.log 'syncing items'
    localStorage.clear()
    localStorage.setObj item.id, item for item in items
    @displayItems()
 @displayConnected(@currentList)

 displayConnected: (listName) ->
 @$disconnect.removeClass 'hidden'
 @$connectedList.text listName
 @$connect.addClass 'hidden'

```

`displayConnected`函数将隐藏`connect`部分并显示`disconnect`部分。

## 离开列表

离开列表应该很容易。我们断开当前的 socket 连接，然后更新 UI。

当点击按钮时处理`disconnect`操作，我们在我们的`bindEvents`函数中添加一个处理程序，如下面的代码段所示：

```js
bindEvents: ->
    @$input.on 'keyup', (e) => @create e
    @$todoList.on 'click', '.destroy', (e) => @destroy e.target
    @$todoList.on  'change', '.toggle', (e) => @toggle e.target
    @$clearCompleted.on 'click', (e) => @clearCompleted()
    @$join.on 'click', (e) => @joinList()
 @$leave.on 'click', (e) => @leaveList()

```

如您所见，我们添加的处理程序将只调用一个`leaveList`函数。我们仍然需要实现它。在我们的`TodoApp`类中最后一个函数之后，添加以下两个函数：

```js
 leaveList: ->
    @socket.disconnect() if @socket
    @displayDisconnected()

  displayDisconnected: () ->
    @$disconnect.addClass 'hidden'
    @$connect.removeClass 'hidden'
```

## 测试全部

现在让我们测试我们的列表加入和离开代码。要看到所有操作，请按照以下步骤进行：

1.  在浏览器中打开`http://localhost:3000/`。

1.  在浏览器窗口中，输入一个列表名称，然后点击**Join List**。UI 应该如预期般更新。

1.  加入列表后，添加一些待办事项。

1.  现在再次打开网站，这次使用第二个浏览器。由于`localStorage`是特定于浏览器的，我们这样做是为了拥有一个干净的待办事项列表。

1.  再次在另一个浏览器中输入与之前相同的列表名称，然后点击**Join List**。

1.  当列表同步时，您现在应该看到之前添加的列表项显示出来。

1.  最后，使用**Leave**按钮从列表中断开。

![测试全部](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/cffs-prog-jq-els-node/img/9588_05_02.jpg)

从不同浏览器同步的两个列表

太棒了！我们现在可以看到 WebSockets 的威力。我们的客户端在无需轮询服务器的情况下，会在应该同步项目时收到通知。

然而，一旦我们连接到列表，我们仍然无法添加新项目以使其显示在房间中的所有其他客户端中。让我们实现这一点。

# 向共享列表添加待办事项

首先，我们将在服务器上处理添加新项目。处理这个的最佳位置是现有的用于创建待办事项的`create`函数。我们不仅将它们添加到`localStorage`中，还会向服务器发出消息，告诉它已创建新的待办事项，并将其作为参数传递。修改`create`函数如下所示：

```js
create: (e) ->
    val = $.trim @$input.val()
    return unless e.which == 13 and val

    randomId = Math.floor Math.random()*999999

 newItem =
 id: randomId
 title: val
 completed: false

 localStorage.setObj randomId, newItem
 @socket.emit 'newItem', newItem if @socket
    @$input.val ''
    @displayItems()
```

我们需要在服务器上处理`newItem`消息。当客户端加入列表时，我们将设置代码来处理这个消息，在`app.coffee`中。

让我们修改之前添加的`joinList`事件处理程序；在以下代码片段中添加突出显示的代码：

```js
io.sockets.on 'connection', (socket) =>
  console.log("connected")
  socket.on 'joinList', (list) =>
    console.log "Joining list #{list}"
    socket.list = list
    socket.join(list)
    @todos[list] ?= []

    socket.emit 'syncItems', @todos[list]

 socket.on 'newItem', (todo) =>
 console.log "new todo #{todo.title}"
 @todos[list].push todo
 io.sockets.in(socket.list).emit('itemAdded', todo)

```

在这段代码片段中，当用户加入列表时，我们设置了另一个`socket`事件。在这种情况下，是为了`newItem`事件。我们使用`push`函数将新的待办事项添加到我们的`@todos`数组中。然后我们向当前列表中的所有客户端发出一个新的`itemAdded`消息。

这个`itemAdded`消息会发生什么？你猜对了；它将再次在客户端处理。这种来回的消息传递在 WebSocket 应用程序中非常常见，需要一些时间来适应。不过不要担心；一旦掌握了，就会变得更容易。

与此同时，让我们在客户端处理`itemAdded`事件。我们还通过在我们的`joinList`方法中添加以下代码来设置这个代码片段：

```js
joinList: ->
    @socket = io.connect('http://localhost:3000')
    @socket.on 'connect', =>
      @currentList = @$joinListName.val()
      @socket.emit 'joinList', @currentList

    @socket.on 'syncItems', (items) => @syncItems(items)

 @socket.on 'itemAdded', (item) =>
 localStorage.setObj item.id, item
 @displayItems()

```

我们通过调用`localStorage.setObject`处理`itemAdded`事件，其中包括项目 ID 和值。这将在`localStorage`中创建一个新的待办事项，如果它在`localStorage`中不存在，或者更新现有值。

就是这样！现在我们应该能够向列表中的所有客户端添加项目。要测试它，我们将按照之前的类似步骤进行：

1.  在浏览器中打开`http://localhost:3000/`。

1.  在浏览器窗口中，输入一个列表名称，然后点击**加入列表**。UI 应该如预期般更新。

1.  现在再次打开网站，这次使用第二个浏览器。

1.  再次输入与另一个浏览器中相同的列表名称，然后点击**加入列表**。

1.  在任一浏览器中添加新的待办事项。你会立即看到待办事项出现在另一个浏览器中。

哇！这不是很令人印象深刻吗？

# 从共享列表中移除待办事项

要从共享列表中移除待办事项，我们将遵循与添加项目类似的模式。在`todo.coffee`的`destroy`函数中，我们将向我们的 socket 发出一个`removeItem`消息，让服务器知道应该移除一个项目，如下面的代码片段所示：

```js
destroy: (elem) ->
    id = ($(elem).closest 'li').data('id')
    localStorage.removeItem id
 @socket.emit 'removeItem', id if @socket
    @displayItems()
```

再次，我们设置了服务器端代码来处理这个消息，通过从内存中的共享列表中移除项目，然后通知连接到列表的所有客户端项目已被移除：

```js
io.sockets.on 'connection', (socket) =>
  console.log("connected")
  socket.on 'joinList', (list) =>
    console.log "Joining list #{list}"
    socket.list = list
    socket.join(list)
    @todos[list] ?= []

    socket.emit 'syncItems', @todos[list]

    socket.on 'newItem', (todo) =>
      console.log "new todo #{todo.title}"
      @todos[list].push todo
      io.sockets.in(socket.list).emit('itemAdded', todo)

 socket.on 'removeItem', (id) =>
 @todos[list] = @todos[list].filter (item) -> item.id isnt id
 io.sockets.in(socket.list).emit('itemRemoved', id)

```

`removeItem` socket 事件处理程序获取要移除的任务的 ID。它通过使用 JavaScript 的数组`filter`函数将共享列表的当前值分配给我们创建的新值来从列表中移除待办事项。这将选择所有不具有传递 ID 的项目。然后，它通过共享列表中的所有客户端 socket 连接调用`emit`，发送`itemRemoved`消息。

最后，我们需要在客户端处理`itemRemoved`消息。与添加项目时类似，我们将在`todo.coffee`的`joinList`函数中设置这个消息，如下面的代码片段所示：

```js
joinList: ->
    @socket = io.connect('http://localhost:3000')
    @socket.on 'connect', =>
      @currentList = @$joinListName.val()
      @socket.emit 'joinList', @currentList

    @socket.on 'syncItems', (items) => @syncItems(items)

    @socket.on 'itemAdded', (item) =>
      localStorage.setObj item.id, item
      @displayItems()

 @socket.on 'itemRemoved', (id) =>
 localStorage.removeItem id
 @displayItems()

```

我们从`localStorage`中移除项目并更新 UI。

要测试移除项目，请按照以下步骤操作：

1.  在浏览器中打开`http://localhost:3000/`。

1.  在浏览器窗口中，输入一个列表名称，然后点击**加入列表**。UI 应该如预期般更新。

1.  一旦连接到共享列表，添加一些待办事项。

1.  现在再次打开网站，这次使用第二个浏览器。

1.  再次输入与另一个浏览器中相同的列表名称，然后点击**加入列表**。您的待办事项列表将与共享列表同步，并包含您在另一个浏览器中添加的项目。

1.  单击删除图标以删除浏览器中的待办事项。您将立即看到另一个浏览器中已删除的待办事项消失。

## 现在轮到你了

作为对您的最后一项练习，我将要求您使“清除已完成”按钮起作用。作为提示，您应该能够使用现有的`destroyItem`方法功能。

# 总结

在本章中，我们通过探索 Node.js 作为一个快速、事件驱动的平台，让您可以使用 JavaScript 或 CoffeeScript 来编写服务器应用程序，完成了对 CoffeeScript 生态系统的巡回。我希望您已经对能够同时在服务器和浏览器上使用 CoffeeScript 编写 Web 应用程序的乐趣有所了解。

我们还花了一些时间使用一些为 Node.js 编写的精彩开源库和框架，比如 expressjs、connect 和 Socket.IO，并看到了我们如何成功地使用 npm 来管理应用程序中的依赖项和模块。

我们的示例应用程序恰好是您可以使用 Node.js 的类型，我们看到它的事件驱动模型适用于编写客户端和服务器之间有大量常量交互的应用程序。

现在我们的旅程已经结束，我希望已经在您心中灌输了渴望和技能，让您走出去使用 CoffeeScript 改变世界。我们花了一些时间不仅探索语言，还有让我们能够更快速地开发强大应用程序的精彩工具、库和框架。

CoffeeScript 和 JavaScript 生态系统的未来是光明的，希望您能成为其中的一部分！
