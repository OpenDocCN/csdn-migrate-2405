# NodeJS Web 开发第五版（三）

> 原文：[`zh.annas-archive.org/md5/E4F616CD5ADA487AF57868CB589CA6CA`](https://zh.annas-archive.org/md5/E4F616CD5ADA487AF57868CB589CA6CA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

数据存储和检索

在前两章中，我们构建了一个小型且有些有用的存储笔记的应用程序，然后使其在移动设备上运行。虽然我们的应用程序运行得相当不错，但它并没有将这些笔记存储在长期基础上，这意味着当您停止服务器时，笔记会丢失，并且如果您运行多个`Notes`实例，每个实例都有自己的笔记集。我们的下一步是引入一个数据库层，将笔记持久化到长期存储中。

在本章中，我们将研究 Node.js 中的数据库支持，目标是获得对几种数据库的暴露。对于`Notes`应用程序，用户应该在访问任何`Notes`实例时看到相同的笔记集，并且用户应该能够随时可靠地访问笔记。

我们将从前一章中使用的`Notes`应用程序代码开始。我们从一个简单的内存数据模型开始，使用数组来存储笔记，然后使其适用于移动设备。在本章中，我们将涵盖以下主题：

+   数据库和异步代码之间的关系

+   配置操作和调试信息的记录

+   捕获重要的系统错误

+   使用`import()`来启用运行时选择要使用的数据库

+   使用多个数据库引擎为`Notes`对象实现数据持久化

+   设计简单的配置文件与 YAML

第一步是复制上一章的代码。例如，如果你在`chap06/notes`中工作，复制它并将其更改为`chap07/notes`。

让我们从回顾一下在 Node.js 中为什么数据库代码是异步的一些理论开始。

让我们开始吧！

# 第十章：记住数据存储需要异步代码

根据定义，外部数据存储系统需要异步编码技术，就像我们在前几章中讨论的那样。Node.js 架构的核心原则是，任何需要长时间执行的操作必须具有异步 API，以保持事件循环运行。从磁盘、另一个进程或数据库检索数据的访问时间总是需要足够的时间来要求延迟执行。

现有的`Notes`数据模型是一个内存数据存储。理论上，内存数据访问不需要异步代码，因此现有的模型模块可以使用常规函数，而不是`async`函数。

我们知道`Notes`应该使用数据库，并且需要一个异步 API 来访问`Notes`数据。因此，现有的`Notes`模型 API 使用`async`函数，所以在本章中，我们可以将 Notes 数据持久化到数据库中。

这是一个有用的复习。现在让我们谈谈生产应用程序所需的一个管理细节——使用日志系统来存储使用数据。

# 记录和捕获未捕获的错误

在我们进入数据库之前，我们必须解决高质量 Web 应用程序的一个属性——管理记录信息，包括正常系统活动、系统错误和调试信息。日志为开发人员提供了对系统行为的洞察。它们为开发人员回答以下问题：

+   应用程序的流量有多大？

+   如果是一个网站，人们最常访问哪些页面？

+   发生了多少错误，以及是什么类型的错误？是否发生了攻击？是否发送了格式不正确的请求？

日志管理也是一个问题。如果管理不当，日志文件很快就会填满磁盘空间。因此，在删除旧日志之前，处理旧日志变得非常重要，希望在删除旧日志之前提取有用的数据。通常，这包括**日志轮换**，即定期将现有日志文件移动到存档目录，然后开始一个新的日志文件。之后，可以进行处理以提取有用的数据，如错误或使用趋势。就像您的业务分析师每隔几周查看利润/损失报表一样，您的 DevOps 团队需要各种报告，以了解是否有足够的服务器来处理流量。此外，可以对日志文件进行筛查以查找安全漏洞。

当我们使用 Express 生成器最初创建`Notes`应用程序时，它使用以下代码配置了一个活动日志系统，使用了`morgan`：

```

This module is what prints messages about HTTP requests on the terminal window. We'll look at how to configure this in the next section.

Visit [`github.com/expressjs/morgan`](https://github.com/expressjs/morgan) for more information about `morgan`.

Another useful type of logging is debugging messages about an application. Debugging traces should be silent in most cases; they should only print information when debugging is turned on, and the level of detail should be configurable. 

The Express team uses the `debug` package for debugging logs. These are turned on using the `DEBUG` environment variable, which we've already seen in use. We will see how to configure this shortly and put it to use in the `Notes` application. For more information, refer to [`www.npmjs.com/package/debug`](https://www.npmjs.com/package/debug).

Finally, the application might generate uncaught exceptions or unhandled Promises. The `uncaughtException` and `unhandledRejection` errors must be captured, logged, and dealt with appropriately. We do not use the word *must* lightly; these errors *must* be handled.

Let's get started.

## Request logging with morgan

The `morgan` package generates log files from the HTTP traffic arriving on an Express application. It has two general areas for configuration:

*   Log format
*   Log location

As it stands, `Notes` uses the `dev` format, which is described as a concise status output for developers. This can be used to log web requests as a way to measure website activity and popularity. The Apache log format already has a large ecosystem of reporting tools and, sure enough, `morgan` can produce log files in this format. 

To enable changing the logging format, simply change the following line in `app.mjs`:

```

这是我们在整本书中遵循的模式；即将默认值嵌入应用程序，并使用环境变量来覆盖默认值。如果我们没有通过环境变量提供配置值，程序将使用`dev`格式。接下来，我们需要运行`Notes`，如下所示：

```

To revert to the previous logging output, simply do not set this environment variable. If you've looked at Apache access logs, this logging format will look familiar. The `::1` notation at the beginning of the line is IPV6 notation for `localhost`, which you may be more familiar with as `127.0.0.1`.

Looking at the documentation for `morgan`, we learn that it has several predefined logging formats available. We've seen two of them—the `dev` format is meant to provide developer-friendly information, while the `common` format is compatible with the Apache log format. In addition to these predefined formats, we can create a custom log format by using various tokens.

We could declare victory on request logging and move on to debugging messages. However, let's look at logging directly to a file. While it's possible to capture `stdout` through a separate process, `morgan` is already installed on `Notes` and it provides the capability to direct its output to a file.

The `morgan` documentation suggests the following:

```

然而，这存在一个问题；无法在不关闭和重新启动服务器的情况下执行日志轮换。术语“日志轮换”指的是 DevOps 实践，其中每个快照覆盖了几小时的活动。通常，应用服务器不会持续打开文件句柄到日志文件，DevOps 团队可以编写一个简单的脚本，每隔几个小时运行一次，并使用`mv`命令移动日志文件，使用`rm`命令删除旧文件。不幸的是，`morgan`在这里配置时，会持续打开文件句柄到日志文件。

相反，我们将使用`rotating-file-stream`包。这个包甚至自动化了日志轮换任务，这样 DevOps 团队就不必为此编写脚本。

有关此内容的文档，请参阅包页面[`www.npmjs.com/package/rotating-file-stream`](https://www.npmjs.com/package/rotating-file-stream)。

首先，安装包：

```

Then, add the following code to `app.mjs`:

```

在顶部的`import`部分，我们将`rotating-file-stream`加载为`rfs`。如果设置了`REQUEST_LOG_FILE`环境变量，我们将把它作为要记录的文件名。`morgan`的`stream`参数只需接受一个可写流。如果`REQUEST_LOG_FILE`没有设置，我们使用`?:`运算符将`process.stdout`的值作为可写流。如果设置了，我们使用`rfs.createStream`创建一个可写流，通过`rotating-file-stream`模块处理日志轮换。

在`rfs.createStream`中，第一个参数是日志文件的文件名，第二个是描述要使用的行为的`options`对象。这里提供了一套相当全面的选项。这里的配置在日志文件达到 10 兆字节大小（或 1 天后）时进行日志轮换，并使用`gzip`算法压缩旋转的日志文件。

可以设置多个日志。例如，如果我们想要将日志记录到控制台，除了记录到文件中，我们可以添加以下`logger`声明：

```

If the `REQUEST_LOG_FILE` variable is set, the other logger will direct logging to the file. Then, because the variable is set, this logger will be created and will direct logging to the console. Otherwise, if the variable is not set, the other logger will send logging to the console and this logger will not be created.

We use these variables as before, specifying them on the command line, as follows:

```

使用这个配置，将在`log.txt`中创建一个 Apache 格式的日志。在进行一些请求后，我们可以检查日志：

```

As expected, our log file has entries in Apache format. Feel free to add one or both of these environment variables to the script in `package.json` as well.

We've seen how to make a log of the HTTP requests and how to robustly record it in a file. Let's now discuss how to handle debugging messages.

## Debugging messages

How many of us debug our programs by inserting `console.log` statements? Most of us do. Yes, we're supposed to use a debugger, and yes, it is a pain to manage the `console.log` statements and make sure they're all turned off before committing our changes. The `debug` package provides a better way to handle debug tracing, which is quite powerful.

For the documentation on the `debug` package, refer to [`www.npmjs.com/package/debug`](https://www.npmjs.com/package/debug).

The Express team uses `DEBUG` internally, and we can generate quite a detailed trace of what Express does by running `Notes` this way:

```

如果要调试 Express，这非常有用。但是，我们也可以在我们自己的代码中使用这个。这类似于插入`console.log`语句，但无需记住注释掉调试代码。

要在我们的代码中使用这个，需要在任何想要调试输出的模块顶部添加以下声明：

```

This creates two functions—`debug` and `dbgerror`—which will generate debugging traces if enabled. The Debug package calls functions *debuggers*. The debugger named `debug` has a `notes:debug` specifier, while `dbgerror` has a `notes:error` specifier. We'll talk in more detail about specifiers shortly.

Using these functions is as simple as this:

```

当为当前模块启用调试时，这会导致消息被打印出来。如果当前模块未启用调试，则不会打印任何消息。再次强调，这类似于使用`console.log`，但您可以动态地打开和关闭它，而无需修改您的代码，只需适当设置`DEBUG`变量。

`DEBUG`环境变量包含描述哪些代码将启用调试的标识符。最简单的标识符是`*`，它是一个通配符，可以打开每个调试器。否则，调试标识符使用`identifer:identifier`格式。当我们说要使用`DEBUG=express:*`时，该标识符使用`express`作为第一个标识符，并使用`*`通配符作为第二个标识符。

按照惯例，第一个标识符应该是您的应用程序或库的名称。因此，我们之前使用`notes:debug`和`notes:error`作为标识符。但是，这只是一个惯例；您可以使用任何您喜欢的标识符格式。

要向`Notes`添加调试，让我们添加一些代码。将以下内容添加到`app.mjs`的底部：

```

This is adapted from the `httpsniffer.mjs` example from Chapter 4, *HTTP Servers and Clients*, and for every HTTP request, a little bit of information will be printed.

Then, in `appsupport.mjs`, let's make two changes. Add the following to the top of the `onError` function:

```

这将在 Express 捕获的任何错误上输出错误跟踪。

然后，将`onListening`更改为以下内容：

```

This changes the `console.log` call to a `debug` call so that a `Listening on` message is printed only if debugging is enabled.

If we run the application with the `DEBUG` variable set appropriately, we get the following output:

```

仔细看一下，你会发现输出既是来自`morgan`的日志输出，也是来自`debug`模块的调试输出。在这种情况下，调试输出以`notes:debug`开头。由于`REQUEST_LOG_FORMAT`变量，日志输出是以 Apache 格式的。

我们现在有一个准备好使用的调试跟踪系统。下一个任务是看看是否可能在文件中捕获这个或其他控制台输出。

## 捕获 stdout 和 stderr

重要消息可以打印到`process.stdout`或`process.stderr`，如果您不捕获输出，这些消息可能会丢失。最佳做法是捕获这些输出以供将来分析，因为其中可能包含有用的调试信息。更好的做法是使用系统设施来捕获这些输出流。

**系统设施**可以包括启动应用程序并将标准输出和标准错误流连接到文件的进程管理应用程序。

尽管它缺乏这种设施，但事实证明，在 Node.js 中运行的 JavaScript 代码可以拦截`process.stdout`和`process.stderr`流。在可用的包中，让我们看看`capture-console`。对于可写流，该包将调用您提供的回调函数来处理任何输出。

请参考`capture-console`包页面，了解相关文档：[`www.npmjs.com/package/capture-console`](https://www.npmjs.com/package/capture-console)。

最后一个行政事项是确保我们捕获其他未捕获的错误。

## 捕获未捕获的异常和未处理的拒绝的 Promises

未捕获的异常和未处理的拒绝的 Promises 是其他重要信息可能丢失的地方。由于我们的代码应该捕获所有错误，任何未捕获的错误都是我们的错误。如果我们不捕获这些错误，我们的失败分析可能会缺少重要信息。

Node.js 通过进程对象发送的事件指示这些条件，`uncaughtException`和`unhandledRejection`。在这些事件的文档中，Node.js 团队严厉地表示，在任何一种情况下，应用程序都处于未知状态，因为某些事情失败了，可能不安全继续运行应用程序。

要实现这些处理程序，请将以下内容添加到`appsupport.mjs`中：

```

Because these are events that are emitted from the `process` object, the way to handle them is to attach an event listener to these events. That's what we've done here.

The names of these events describe their meaning well. An `uncaughtException` event means an error was thrown but was not caught by a `try/catch` construct. Similarly, an `unhandledRejection` event means a Promise ended in a rejected state, but there was no `.catch` handler.

Our DevOps team will be happier now that we've handled these administrative chores. We've seen how to generate useful log files for HTTP requests, how to implement debug tracing, and even how to capture it to a file. We wrapped up this section by learning how to capture otherwise-uncaught errors.

We're now ready to move on to the real purpose of this chapter—storing notes in persistent storage, such as in a database. We'll implement support for several database systems, starting with a simple system using files on a disk.

# Storing notes in a filesystem

Filesystems are an often-overlooked database engine. While filesystems don't have the sort of query features supported by database engines, they are still a reliable place to store files. The Notes schema is simple enough, so the filesystem can easily serve as its data storage layer.

Let's start by adding two functions to the `Note` class in `models/Notes.mjs`:

```

我们将使用这个将`Note`对象转换为 JSON 格式的文本，以及从 JSON 格式的文本转换为`Note`对象。

`JSON`方法是一个 getter，这意味着它检索对象的值。在这种情况下，`note.JSON`属性/getter（没有括号）将简单地给我们提供笔记的 JSON 表示。我们稍后将使用它来写入 JSON 文件。

`fromJSON` 是一个静态函数，或者工厂方法，用于帮助构造 `Note` 对象，如果我们有一个 JSON 字符串。由于我们可能会得到任何东西，我们需要仔细测试输入。首先，如果字符串不是 JSON 格式，`JSON.parse` 将失败并抛出异常。其次，我们有 TypeScript 社区所谓的**类型保护**，或者 `if` 语句，来测试对象是否符合 `Note` 对象所需的条件。这检查它是否是一个带有 `key`、`title` 和 `body` 字段的对象，这些字段都必须是字符串。如果对象通过了这些测试，我们使用数据来构造一个 `Note` 实例。

这两个函数可以如下使用：

```

This example code snippet produces a simple `Note` instance and then generates the JSON version of the note. Then, a new note is instantiated from that JSON string using `from JSON()`.

Now, let's create a new module, `models/notes-fs.mjs`, to implement the filesystem datastore:

```

这导入了所需的模块；一个额外的添加是使用 `fs-extra` 模块。这个模块被用来实现与核心 `fs` 模块相同的 API，同时添加了一些有用的额外函数。在我们的情况下，我们对 `fs.ensureDir` 感兴趣，它验证指定的目录结构是否存在，如果不存在，则创建一个目录路径。如果我们不需要 `fs.ensureDir`，我们将简单地使用 `fs.promises`，因为它也提供了在 `async` 函数中有用的文件系统函数。

有关 `fs-extra` 的文档，请参考 [`www.npmjs.com/package/fs-extra`](https://www.npmjs.com/package/fs-extra)。

现在，将以下内容添加到 `models/notes-fs.mjs` 中：

```

The `FSNotesStore` class is an implementation of `AbstractNotesStore`, with a focus on storing the `Note` instances as JSON in a directory. These methods implement the API that we defined in Chapter 5, *Your First Express Application*. This implementation is incomplete since a couple of helper functions still need to be written, but you can see that it relies on files in the filesystem. For example, the `destroy` method simply uses `fs.unlink` to delete the note from the disk. In `keylist`, we use `fs.readdir` to read each `Note` object and construct an array of keys for the notes.

Let's add the helper functions:

```

`crupdate` 函数用于支持 `update` 和 `create` 方法。对于这个 `Notes` 存储，这两种方法都是相同的，它们将内容写入磁盘作为一个 JSON 文件。

代码中，笔记存储在由 `notesDir` 函数确定的目录中。这个目录可以在 `NOTES_FS_DIR` 环境变量中指定，也可以在 `Notes` 根目录中的 `notes-fs-data` 中指定（从 `approotdir` 变量中得知）。无论哪种方式，我们都使用 `fs.ensureDir` 来确保目录存在。

`Notes` 的路径名是由 `filePath` 函数计算的。

由于路径名是 `${notesDir}/${key}.json`，因此键不能使用文件名中不能使用的字符。因此，如果键包含 `/` 字符，`crupdate` 将抛出错误。

`readJSON` 函数的功能与其名称所示的一样——它从磁盘中读取一个 `Note` 对象作为 JSON 文件。

我们还添加了另一个依赖项：

```

We're now almost ready to run the `Notes` application, but there's an issue that first needs to be resolved with the `import()` function.

## Dynamically importing ES6 modules

Before we start modifying the router functions, we have to consider how to account for multiple `AbstractNotesStore` implementations. By the end of this chapter, we will have several of them, and we want an easy way to configure `Notes` to use any of them. For example, an environment variable, `NOTES_MODEL`, could be used to specify the `Notes` data model to use, and the `Notes` application would dynamically load the correct module.

In `Notes`, we refer to the `Notes` datastore module from several places. To change from one datastore to another requires changing the source in each of these places. It would be better to locate that selection in one place, and further, to make it dynamically configurable at runtime.

There are several possible ways to do this. For example, in a CommonJS module, it's possible to compute the pathname to the module for a `require` statement. It would consult the environment variable, `NOTES_MODEL`, to calculate the pathname for the datastore module, as follows:

```

然而，我们的意图是使用 ES6 模块，因此让我们看看在这种情况下它是如何工作的。因为在常规的 `import` 语句中，模块名不能像这样是一个表达式，所以我们需要使用 `动态导入` 来加载模块。`动态导入` 功能——即 `import()` 函数——允许我们动态计算要加载的模块名。

为了实现这个想法，让我们创建一个新文件 `models/notes-store.mjs`，其中包含以下内容：

```

This is what we might call a factory function. It uses `import()` to load a module whose filename is calculated from the `model` parameter. We saw in `notes-fs.mjs` that the `FSNotesStore` class is the default export. Therefore, the `NotesStoreClass` variable gets that class, then we call the constructor to create an instance, and then we stash that instance in a global scope variable. That global scope variable is then exported as `NotesStore`.

We need to make one small change in `models/notes-memory.mjs`:

```

任何实现 `AbstractNotesStore` 的模块都将默认导出定义的类。

在 `app.mjs` 中，我们需要对调用这个 `useModel` 函数进行另一个更改。在第五章中，*你的第一个 Express 应用程序*，我们让 `app.mjs` 导入 `models/notes-memory.mjs`，然后设置 `NotesStore` 包含 `InMemoryNotesStore` 的一个实例。具体来说，我们有以下内容：

```

We need to remove these two lines of code from `app.mjs` and then add the following:

```

我们导入 `useModel`，将其重命名为 `useNotesModel`，然后通过传入 `NOTES_MODEL` 环境变量来调用它。如果 `NOTES_MODEL` 变量未设置，我们将默认使用“memory” `NotesStore`。由于 `useNotesModel` 是一个 `async` 函数，我们需要处理生成的 Promise。`.then` 处理成功的情况，但由于没有需要执行的操作，所以我们提供了一个空函数。重要的是任何错误都会关闭应用程序，因此我们添加了 `.catch`，它调用 `onError` 来处理错误。

为了支持这个错误指示器，我们需要在 `appsupport.mjs` 的 `onError` 函数中添加以下内容：

```

This added error handler will also cause the application to exit.

These changes also require us to make another change. The `NotesStore` variable is no longer in `app.mjs`, but is instead in `models/notes-store.mjs`. This means we need to go to `routes/index.mjs` and `routes/notes.mjs`, where we make the following change to the imports:

```

我们从`notes-store.mjs`中导入`NotesStore`导出，并将其重命名为`notes`。因此，在两个路由模块中，我们将进行诸如`notes.keylist()`的调用，以访问动态选择的`AbstractNotesStore`实例。

这种抽象层提供了期望的结果——设置一个环境变量，让我们在运行时决定使用哪个数据存储。

现在我们已经拥有了所有的部件，让我们运行`Notes`应用程序并看看它的行为。

## 使用文件系统存储运行 Notes 应用程序

在`package.json`中，将以下内容添加到`scripts`部分：

```

When you add these entries to `package.json`, make sure you use the correct JSON syntax. In particular, if you leave a comma at the end of the `scripts` section, it will fail to parse and `npm` will throw an error message.

With this code in place, we can now run the `Notes` application, as follows:

```

我们可以像以前一样在`http://localhost:3000`上使用应用程序。因为我们没有更改任何模板或 CSS 文件，所以应用程序看起来与您在第六章结束时一样。

因为`notes:*`的调试已打开，我们将看到`Notes`应用程序正在执行的任何操作的日志。通过简单地不设置`DEBUG`变量，可以轻松关闭此功能。

您现在可以关闭并重新启动`Notes`应用程序，并查看完全相同的注释。您还可以使用常规文本编辑器（如**vi**）在命令行中编辑注释。您现在可以在不同端口上启动多个服务器，使用`fs-server1`和`fs-server2`脚本，并查看完全相同的注释。

就像我们在第五章结束时所做的那样，*您的第一个 Express 应用程序*，我们可以在两个单独的命令窗口中启动两个服务器。这将在不同的端口上运行两个应用程序实例。然后，在不同的浏览器窗口中访问这两个服务器，您会发现两个浏览器窗口显示相同的注释。

另一个尝试的事情是指定`NOTES_FS_DIR`以定义一个不同的目录来存储注释。

最后的检查是创建一个带有`/`字符的键的注释。请记住，键用于生成我们存储注释的文件名，因此键不能包含`/`字符。在浏览器打开的情况下，单击“添加注释”，并输入一条注释，确保在“键”字段中使用`/`字符。单击提交按钮后，您将看到一个错误，指出这是不允许的。

我们现在已经演示了向`Notes`添加持久数据存储。但是，这种存储机制并不是最好的，还有其他几种数据库类型可以探索。我们列表中的下一个数据库服务是 LevelDB。

# 使用 LevelDB 数据存储存储注释

要开始使用实际数据库，让我们看一下一个极其轻量级、占用空间小的数据库引擎：`level`。这是一个 Node.js 友好的包装器，它包装了 LevelDB 引擎，并由 Google 开发。它通常用于 Web 浏览器进行本地数据持久化，并且是一个非索引的 NoSQL 数据存储，最初是为在浏览器中使用而设计的。Level Node.js 模块使用 LevelDB API，并支持多个后端，包括 leveldown，它将 C++ LevelDB 数据库集成到 Node.js 中。

访问[`www.npmjs.com/package/level`](https://www.npmjs.com/package/level)了解有关此模块的信息。

要安装数据库引擎，请运行以下命令：

```

This installs the version of `level` that the following code was written against.

Then, create the `models/notes-level.mjs` module, which will contain the `AbstractNotesStore` implementation:

```

我们从`import`语句和一些声明开始模块。`connectDB`函数用于连接数据库，`createIfMissing`选项也是如其名所示，如果不存在具有所使用名称的数据库，则创建一个数据库。从模块`level`导入的是一个构造函数，用于创建与第一个参数指定的数据库连接的`level`实例。这个第一个参数是文件系统中的位置，换句话说，是数据库将被存储的目录。

`level`构造函数通过返回一个`db`对象来与数据库进行交互。我们将`db`作为模块中的全局变量存储，以便于使用。在`connectDB`中，如果`db`对象已经设置，我们立即返回它；否则，我们使用构造函数打开数据库，就像刚才描述的那样。

数据库的位置默认为当前目录中的`notes.level`。`LEVELDB_LOCATION`环境变量可以设置，如其名称所示，以指定数据库位置。

现在，让我们添加这个模块的其余部分：

```

As expected, we're creating a `LevelNotesStore` class to hold the functions.  

In this case, we have code in the `close` function that calls `db.close` to close down the connection. The `level` documentation suggests that it is important to close the connection, so we'll have to add something to `app.mjs` to ensure that the database closes when the server shuts down. The documentation also says that `level` does not support concurrent connections to the same database from multiple clients, meaning if we want multiple `Notes` instances to use the database, we should only have the connection open when necessary.

Once again, there is no difference between the `create` and `update` operations, and so we use a `crupdate` function again. Notice that the pattern in all the functions is to first call `connectDB` to get `db`, and then to call a function on the `db` object. In this case, we use `db.put` to store the `Note` object in the database.

In the `read` function, `db.get` is used to read the note. Since the `Note` data was stored as JSON, we use `Note.fromJSON` to decode and instantiate the `Note` instance.

The `destroy` function deletes a record from the database using the `db.del` function.

Both `keylist` and `count` use the `createKeyStream` function. This function uses an event-oriented interface to stream through every database entry, emitting events as it goes. A `data` event is emitted for each key in the database, while the `end` event is emitted at the end of the database, and the `error` event is emitted on errors. Since there is no simple way to present this as a simple `async` function, we have wrapped it with a Promise so that we can use `await`. We then invoke `createKeyStream`, letting it run its course and collect data as it goes. For `keylist`, in the `data` events, we add the data (in this case, the key to a database entry) to an array. 

For `count`, we use a similar process, and in this case, we simply increment a counter. Since we have this wrapped in a Promise, in an `error` event, we call `reject`, and in an `end` event, we call `resolve`.

Then, we add the following to `package.json` in the `scripts` section:

```

最后，您可以运行`Notes`应用程序：

```

The printout in the console will be the same, and the application will also look the same. You can put it through its paces to check whether everything works correctly.

Since `level` does not support simultaneous access to a database from multiple instances, you won't be able to use the multiple `Notes` application scenario. You will, however, be able to stop and restart the application whenever you want to without losing any notes.

Before we move on to looking at the next database, let's deal with a issue mentioned earlier—closing the database connection when the process exits.

## Closing database connections when closing the process

The `level` documentation says that we should close the database connection with `db.close`. Other database servers may well have the same requirement. Therefore, we should make sure we close the database connection before the process exits, and perhaps also on other conditions.

Node.js provides a mechanism to catch signals sent by the operating system. What we'll do is configure listeners for these events, then close `NotesStore` in response.

 Add the following code to `appsupport.mjs`:

```

我们导入`NotesStore`以便可以调用其方法，`server`已经在其他地方导入。

前三个`process.on`调用监听操作系统信号。如果您熟悉 Unix 进程信号，这些术语会很熟悉。在每种情况下，事件调用`catchProcessDeath`函数，然后调用`NotesStore`和`server`上的`close`函数，以确保关闭。

然后，为了确认一些事情，我们附加了一个`exit`监听器，这样当进程退出时我们可以打印一条消息。Node.js 文档表示，`exit`监听器被禁止执行需要进一步事件处理的任何操作，因此我们不能在此处理程序中关闭数据库连接。

让我们试一下运行`Notes`应用程序，然后立即按下*Ctrl* + *C*：

```

Sure enough, upon pressing *Ctrl* + *C*, the `exit` and `catchProcessDeath` listeners are called.

That covers the `level` database, and we also have the beginning of a handler to gracefully shut down the application. The next database to cover is an embedded SQL database that requires no server processes.

# Storing notes in SQL with SQLite3

To get started with more normal databases, let's see how we can use SQL from Node.js. First, we'll use SQLite3, which is a lightweight, simple-to-set-up database engine eminently suitable for many applications.

To learn more about this database engine, visit [`www.sqlite.org/`](http://www.sqlite.org/).

To learn more about the Node.js module, visit [`github.com/mapbox/node-sqlite3/wiki/API`](https://github.com/mapbox/node-sqlite3/wiki/API) or [`www.npmjs.com/package/sqlite3`](https://www.npmjs.com/package/sqlite3).

The primary advantage of SQLite3 is that it doesn't require a server; it is a self-contained, no-set-up-required SQL database. The SQLite3 team also claims that it is very fast and that large, high-throughput applications have been built with it. The downside to the SQLite3 package is that its API requires callbacks, so we'll have to use the Promise wrapper pattern.

The first step is to install the module:

```

当然，这会安装`sqlite3`包。

要管理 SQLite3 数据库，您还需要安装 SQLite3 命令行工具。该项目网站为大多数操作系统提供了预编译的二进制文件。您还会发现这些工具在大多数软件包管理系统中都是可用的。

我们可以使用的一个管理任务是设置数据库表，我们将在下一节中看到。

## SQLite3 数据库模式

接下来，我们需要确保我们的数据库配置了适合`Notes`应用程序的数据库表。这是上一节末尾提到的一个示例数据库管理员任务。为此，我们将使用`sqlite3`命令行工具。`sqlite3.org`网站有预编译的二进制文件，或者该工具可以通过您的操作系统的软件包管理系统安装——例如，您可以在 Ubuntu/Debian 上使用`apt-get`，在 macOS 上使用 MacPorts。

对于 Windows，请确保已经安装了 Chocolatey 软件包管理工具，然后以管理员权限启动 PowerShell，并运行"`choco install sqlite`"。这将安装 SQLite3 的 DLL 和其命令行工具，让您可以运行以下指令。

我们将使用以下的 SQL 表定义作为模式（将其保存为`models/schema-sqlite3.sql`）：

```

To initialize the database table, we run the following command:

```

虽然我们可以这样做，但最佳实践是自动化所有管理过程。为此，我们应该编写一小段脚本来初始化数据库。

幸运的是，`sqlite3`命令为我们提供了一种方法来做到这一点。将以下内容添加到`package.json`的`scripts`部分：

```

Run the setup script:

```

这并不是完全自动化，因为我们必须在`sqlite`提示符下按*Ctrl* + *D*，但至少我们不必费心去记住如何做。我们本可以轻松地编写一个小的 Node.js 脚本来做到这一点；然而，通过使用软件包提供的工具，我们在自己的项目中需要维护的代码更少。

有了数据库表的设置，让我们继续编写与 SQLite3 交互的代码。

## SQLite3 模型代码

我们现在准备为 SQLite3 实现一个`AbstractNotesStore`实现。

创建`models/notes-sqlite3.mjs`文件：

```

This imports the required packages and makes the required declarations. The `connectDB` function has a similar purpose to the one in `notes-level.mjs`: to manage the database connection. If the database is not open, it'll go ahead and open it, and it will even make sure that the database file is created (if it doesn't exist). If the database is already open, it'll simply be returned.

Since the API used in the `sqlite3` package requires callbacks, we will have to wrap every function call in a Promise wrapper, as shown here.

Now, add the following to `models/notes-sqlite3.mjs`:

```

由于有许多成员函数，让我们逐个讨论它们：

```

In `close`, the task is to close the database. There's a little dance done here to make sure the global `db` variable is unset while making sure we can close the database by saving `db` as `_db`. The `sqlite3` package will report errors from `db.close`, so we're making sure we report any errors:

```

我们现在有理由定义`Notes`模型的`create`和`update`操作是分开的，因为每个函数的 SQL 语句是不同的。`create`函数当然需要一个`INSERT INTO`语句，而`update`函数当然需要一个`UPDATE`语句。

`db.run`函数在这里使用了多次，它执行一个 SQL 查询，同时给我们机会在查询字符串中插入参数。

这遵循了 SQL 编程接口中常见的参数替换范式。程序员将 SQL 查询放在一个字符串中，然后在查询字符串中的任何位置放置一个问号，以便在查询字符串中插入一个值。查询字符串中的每个问号都必须与程序员提供的数组中的一个值匹配。该模块负责正确编码这些值，以便查询字符串格式正确，同时防止 SQL 注入攻击。

`db.run`函数只是运行它所给出的 SQL 查询，并不检索任何数据。

```

To retrieve data using the `sqlite3` module, you use the `db.get`, `db.all`, or `db.each` functions. Since our `read` method only returns one item, we use the `db.get` function to retrieve just the first row of the result set. By contrast, the `db.all` function returns all of the rows of the result set at once, and the `db.each` function retrieves one row at a time, while still allowing the entire result set to be processed.

By the way, this `read` function has a bug in it—see whether you can spot the error. We'll read more about this in Chapter 13, *Unit Testing and Functional Testing*, when our testing efforts uncover the bug:

```

在我们的`destroy`方法中，我们只需使用`db.run`执行`DELETE FROM`语句来删除相关笔记的数据库条目：

```

In `keylist`, the task is to collect the keys for all of the `Note` instances. As we said, `db.get` returns only the first entry of the result set, while the `db.all` function retrieves all the rows of the result set. Therefore, we use `db.all`, although `db.each` would have been a good alternative.

The contract for this function is to return an array of note keys. The `rows` object from `db.all` is an array of results from the database that contains the data we are to return, but we use the `map` function to convert the array into the format required by this function:

```

在`count`中，任务类似，但我们只需要表中行的计数。SQL 提供了一个`count()`函数来实现这个目的，我们已经使用了，然后因为这个结果只有一行，我们可以再次使用`db.get`。

这使我们能够使用`NOTES_MODEL`设置为`sqlite3`运行`Notes`。现在我们的代码已经设置好，我们可以继续使用这个数据库运行`Notes`。

## 使用 SQLite3 运行 Notes

我们现在准备使用 SQLite3 运行`Notes`应用程序。将以下代码添加到`package.json`的`scripts`部分：

```

This sets up the commands that we'll use to test `Notes` on SQLite3.

We can run the server as follows:

```

现在你可以在`http://localhost:3000`上浏览应用程序，并像以前一样运行它。

因为我们还没有对`View`模板或 CSS 文件进行任何更改，所以应用程序看起来和以前一样。

当然，你可以使用`sqlite`命令，或其他 SQLite3 客户端应用程序来检查数据库：

```

The advantage of installing the SQLite3 command-line tools is that we can perform any database administration tasks without having to write any code.  

We have seen how to use SQLite3 with Node.js. It is a worthy database for many sorts of applications, plus it lets us use a SQL database without having to set up a server.

The next package that we will cover is an **Object Relations Management** (**ORM**) system that can run on top of several SQL databases.

# Storing notes the ORM way with Sequelize

There are several popular SQL database engines, such as PostgreSQL, MySQL, and MariaDB. Corresponding to each are Node.js client modules that are similar in nature to the `sqlite3` module that we just used. The programmer is close to SQL, which can be good in the same way that driving a stick shift car is fun. But what if we want a higher-level view of the database so that we can think in terms of objects, rather than rows of a database table? **ORM** systems provide a suitable higher-level interface, and even offer the ability to use the same data model with several databases. Just as driving an electric car provides lots of benefits at the expense of losing out on the fun of stick-shift driving, ORM produces lots of benefits, while also distancing ourselves from the SQL.

The **Sequelize** package ([`www.sequelizejs.com/`](http://www.sequelizejs.com/)) is Promise-based, offers strong, well-developed ORM features, and can connect to SQLite3, MySQL, PostgreSQL, MariaDB, and MSSQL databases. Because Sequelize is Promise-based, it will fit naturally with the Promise-based application code we're writing.

A prerequisite to most SQL database engines is having access to a database server. In the previous section, we skirted around this issue by using SQLite3, which requires no database server setup. While it's possible to install a database server on your laptop, right now, we want to avoid the complexity of doing so, and so we will use Sequelize to manage a SQLite3 database. We'll also see that it's simply a matter of using a configuration file to run the same Sequelize code against a hosted database such as MySQL. In Chapter 11, *Deploying Node.js Microservices with Docker*, we'll learn how to use Docker to easily set up a service, including database servers, on our laptop and deploy the exact same configuration to a live server. Most web-hosting providers offer MySQL or PostgreSQL as part of their service.

Before we start on the code, let's install two modules:

```

第一个安装了 Sequelize 包。第二个`js-yaml`是安装的，以便我们可以实现一个以 YAML 格式存储 Sequelize 连接配置的文件。YAML 是一种人类可读的**数据序列化语言**，这意味着它是一种易于使用的文本文件格式，用于描述数据对象。

也许最好了解 YAML 的地方是它的维基百科页面，可以在[`en.wikipedia.org/wiki/YAML`](https://en.wikipedia.org/wiki/YAML)找到。

让我们从学习如何配置 Sequelize 开始，然后我们将为 Sequelize 创建一个`AbstractNotesStore`实例，最后，我们将使用 Sequelize 测试`Notes`。

## 配置 Sequelize 并连接到数据库

我们将以与以前不同的方式组织 Sequelize 支持的代码。我们预见到`Notes`表不是`Notes`应用程序将使用的唯一数据模型。我们可以支持其他功能，比如上传笔记的图片或允许用户评论笔记。这意味着需要额外的数据库表，并建立数据库条目之间的关系。例如，我们可能会有一个名为`AbstractCommentStore`的类来存储评论，它将有自己的数据库表和自己的模块来管理评论数据。`Notes`和`Comments`存储区域都应该在同一个数据库中，因此它们应该共享一个数据库连接。

有了这个想法，让我们创建一个文件`models/sequlz.mjs`，来保存管理 Sequelize 连接的代码：

```

As with the SQLite3 module, the `connectDB` function manages the connection through Sequelize to a database server. Since the configuration of the Sequelize connection is fairly complex and flexible, we're not using environment variables for the whole configuration, but instead we use a YAML-formatted configuration file that will be specified in an environment variable. Sequelize uses four items of data—the database name, the username, the password, and a parameters object.

When we read in a YAML file, its structure directly corresponds to the object structure that's created. Therefore, with a YAML configuration file, we don't need to use up any brain cells developing a configuration file format. The YAML structure is dictated by the Sequelize `params` object, and our configuration file simply has to use the same structure.

We also allow overriding any of the fields in this file using environment variables. This will be useful when we deploy `Notes` using Docker so that we can configure database connections without having to rebuild the Docker container.

For a simple SQLite3-based database, we can use the following YAML file for configuration and name it `models/sequelize-sqlite.yaml`:

```

`params.dialect`的值决定了要使用的数据库类型；在这种情况下，我们使用的是 SQLite3。根据方言的不同，`params`对象可以采用不同的形式，比如连接到数据库的连接 URL。在这种情况下，我们只需要一个文件名，就像这样给出的。

`authenticate` 调用是为了测试数据库是否正确连接。

`close` 函数做你期望的事情——关闭数据库连接。

有了这个设计，我们可以很容易地通过添加一个运行时配置文件来更改数据库以使用其他数据库服务器。例如，很容易设置一个 MySQL 连接；我们只需创建一个新文件，比如 `models/sequelize-mysql.yaml`，其中包含类似以下代码的内容：

```

This is straightforward. The `username` and `password` fields must correspond to the database credentials, while `host` and `port` will specify where the database is hosted. Set the database's `dialect` parameter and other connection information and you're good to go.

To use MySQL, you will need to install the base MySQL driver so that Sequelize can use MySQL:

```

运行 Sequelize 对其支持的其他数据库，如 PostgreSQL，同样简单。只需创建一个配置文件，安装 Node.js 驱动程序，并安装/配置数据库引擎。

从 `connectDB` 返回的对象是一个数据库连接，正如我们将看到的，它被 Sequelize 使用。因此，让我们开始这一部分的真正目标——定义 `SequelizeNotesStore` 类。

## 为 Notes 应用程序创建一个 Sequelize 模型

与我们使用的其他数据存储引擎一样，我们需要为 Sequelize 创建一个 `AbstractNotesStore` 的子类。这个类将使用 Sequelize `Model` 类来管理一组注释。

让我们创建一个新文件，`models/notes-sequelize.mjs`：

```

The database connection is stored in the `sequelize` object, which is established by the `connectDB` function that we just looked at (which we renamed `connectSequlz`) to instantiate a Sequelize instance. We immediately return if the database is already connected.

In Sequelize, the `Model` class is where we define the data model for a given object. Each `Model` class corresponds to a database table. The `Model` class is a normal ES6 class, and we start by subclassing it to define the `SQNote` class. Why do we call it `SQNote`? That's because we already defined a `Note` class, so we had to use a different name in order to use both classes.

By calling `SQNote.init`, we initialize the `SQNote` model with the fields—that is, the schema—that we want it to store. The first argument to this function is the schema description and the second argument is the administrative data required by Sequelize.

As you would expect, the schema has three fields: `notekey`, `title`, and `body`. Sequelize supports a long list of data types, so consult the documentation for more on that. We are using `STRING` as the type for `notekey` and `title` since both handle a short text string up to 255 bytes long. The `body` field is defined as `TEXT` since it does not need a length limit. In the `notekey` field, you see it is an object with other parameters; in this case, it is described as the primary key and the `notekey` values must be unique.

Online documentation can be found at the following locations:
Sequelize class: [`docs.sequelizejs.com/en/latest/api/sequelize/`](http://docs.sequelizejs.com/en/latest/api/sequelize/) [](http://docs.sequelizejs.com/en/latest/api/sequelize/) Defining models: [`docs.sequelizejs.com/en/latest/api/model/`](http://docs.sequelizejs.com/en/latest/api/model/)

That manages the database connection and sets up the schema. Now, let's add the `SequelizeNotesStore` class to `models/notes-sequelize.mjs`:

```

首先要注意的是，在每个函数中，我们调用在 `SQNote` 类中定义的静态方法来执行数据库操作。Sequelize 模型类就是这样工作的，它的文档中有一个全面的这些静态方法的列表。

在创建 Sequelize 模型类的新实例时——在本例中是 `SQNote`——有两种模式可供选择。一种是调用 `build` 方法，然后创建对象和 `save` 方法将其保存到数据库。或者，我们可以像这样使用 `create` 方法，它执行这两个步骤。此函数返回一个 `SQNote` 实例，在这里称为 `sqnote`，如果您查阅 Sequelize 文档，您将看到这些实例有一长串可用的方法。我们的 `create` 方法的约定是返回一个注释，因此我们构造一个 `Note` 对象来返回。

在这个和其他一些方法中，我们不想向调用者返回一个 Sequelize 对象。因此，我们构造了我们自己的 `Note` 类的实例，以返回一个干净的对象。

我们的 `update` 方法首先调用 `SQNote.findOne`。这是为了确保数据库中存在与我们给定的键对应的条目。此函数查找第一个数据库条目，其中 `notekey` 匹配提供的键。在快乐路径下，如果存在数据库条目，我们然后使用 `SQNote.update` 来更新 `title` 和 `body` 值，并通过使用相同的 `where` 子句，确保 `update` 操作针对相同的数据库条目。

Sequelize 的 `where` 子句提供了一个全面的匹配操作符列表。如果您仔细考虑这一点，很明显它大致对应于以下 SQL：

```

That's what Sequelize and other ORM libraries do—convert the high-level API into database operations such as SQL queries.

To read a note, we use the `findOne` operation again. There is the possibility of it returning an empty result, and so we have to throw an error to match. The contract for this function is to return a `Note` object, so we take the fields retrieved using Sequelize to create a clean `Note` instance.

To destroy a note, we use the `destroy` operation with the same `where` clause to specify which entry to delete. This means that, as in the equivalent SQL statement (`DELETE FROM SQNotes WHERE notekey = ?`), if there is no matching note, no error will be thrown.

Because the `keylist` function acts on all `Note` objects, we use the `findAll` operation. The difference between `findOne` and `findAll` is obvious from the names. While `findOne` returns the first matching database entry, `findAll` returns all of them. The `attributes` specifier limits the result set to include the named field—namely, the `notekey` field. This gives us an array of objects with a field named `notekey`. We then use a `.map` function to convert this into an array of note keys.

For the `count` function, we can just use the `count()` method to calculate the required result.

This allows us to use Sequelize by setting `NOTES_MODEL` to `sequelize`.

Having set up the functions to manage the database connection and defined the `SequelizeNotesStore` class, we're now ready to test the `Notes` application.

## Running the Notes application with Sequelize

Now, we can get ready to run the `Notes` application using Sequelize. We can run it against any database server, but let's start with SQLite3\. Add the following declarations to the `scripts` entry in `package.json`:

```

这设置了命令以运行单个服务器实例（或两个）。

然后，按以下方式运行它：

```

As before, the application looks exactly the same because we haven't changed the `View` templates or CSS files. Put it through its paces and everything should work.

You will be able to start two instances; use separate browser windows to visit both instances and see whether they show the same set of notes.

To reiterate, to use the Sequelize-based model on a given database server, do the following:

1.  Install and provision the database server instance; otherwise, get the connection parameters for an already-provisioned database server.
2.  Install the corresponding Node.js driver.
3.  Write a YAML configuration file corresponding to the connection parameters.
4.  Create new `scripts` entries in `package.json` to automate starting `Notes` against the database.

By using Sequelize, we have dipped our toes into a powerful library for managing data in a database. Sequelize is one of several ORM libraries available for Node.js. We've already used the word *comprehensive* several times in this section as it's definitely the best word to describe Sequelize. 

An alternative that is worthy of exploration is not an ORM library but is what's called a query builder. `knex` supports several SQL databases, and its role is to simplify creating SQL queries by using a high-level API.

In the meantime, we have one last database to cover before wrapping up this chapter: MongoDB, the leading NoSQL database.

# Storing notes in MongoDB

MongoDB is widely used with Node.js applications, a sign of which is the popular **MEAN** acronym: **MongoDB (or MySQL), Express, Angular, and Node.js**. MongoDB is one of the leading NoSQL databases, meaning it is a database engine that does not use SQL queries. It is described as a *scalable, high-performance, open source, document-oriented database*. It uses JSON-style documents with no predefined, rigid schema and a large number of advanced features. You can visit their website for more information and documentation at [`www.mongodb.org`](http://www.mongodb.org).

Documentation on the Node.js driver for MongoDB can be found at [`www.npmjs.com/package/mongodb`](https://www.npmjs.com/package/mongodb) and [`mongodb.github.io/node-mongodb-native/`](http://mongodb.github.io/node-mongodb-native/).

Mongoose is a popular ORM for MongoDB ([`mongoosejs.com/`](http://mongoosejs.com/)). In this section, we'll use the native MongoDB driver instead, but Mongoose is a worthy alternative.

First, you will need a running MongoDB instance. The Compose- ([`www.compose.io/`](https://www.compose.io/)) and ScaleGrid- ([`scalegrid.io/`](https://scalegrid.io/)) hosted service providers offer hosted MongoDB services. Nowadays, it is straightforward to host MongoDB as a Docker container as part of a system built of other Docker containers. We'll do this in Chapter 13, *Unit Testing and Functional Testing*.

It's possible to set up a temporary MongoDB instance for testing on, say, your laptop. It is available in all the operating system package management systems, or you can download a compiled package from [mongodb.com](https://www.mongodb.com). The MongoDB website also has instructions ([`docs.mongodb.org/manual/installation/`](https://docs.mongodb.org/manual/installation/)).

For Windows, it may be most expedient to use a cloud-hosted MongoDB instance.

Once installed, it's not necessary to set up MongoDB as a background service. Instead, you can run a couple of simple commands to get a MongoDB instance running in the foreground of a command window, which you can kill and restart any time you like.

In a command window, run the following:

```

这将创建一个数据目录，然后运行 MongoDB 守护程序来对该目录进行操作。

在另一个命令窗口中，您可以按以下方式进行测试：

```

This runs the Mongo client program with which you can run commands. The command language used here is JavaScript, which is comfortable for us.

This saves a *document* in the collection named `foo`. The second command finds all documents in `foo`, printing them out for you. There is only one document, the one we just inserted, so that's what gets printed. The `_id` field is added by MongoDB and serves as a document identifier.

This setup is useful for testing and debugging. For a real deployment, your MongoDB server must be properly installed on a server. See the MongoDB documentation for these instructions.

With a working MongoDB installation in our hands, let's get started with implementing the `MongoNotesStore` class.

## A MongoDB model for the Notes application

The official Node.js MongoDB driver ([`www.npmjs.com/package/mongodb`](https://www.npmjs.com/package/mongodb)) is created by the MongoDB team. It is very easy to use, as we will see, and its installation is as simple as running the following command:

```

这为我们设置了驱动程序包，并将其添加到 `package.json`。

现在，创建一个新文件，`models/notes-mongodb.mjs`：

```

This sets up the required imports, as well as the functions to manage a connection with the MongoDB database.

The `MongoClient` class is used to connect with a MongoDB instance. The required URL, which will be specified through an environment variable, uses a straightforward format: `mongodb://localhost/`. The database name is specified via another environment variable.

The documentation for the MongoDB Node.js driver can be found at [`mongodb.github.io/node-mongodb-native/`](http://mongodb.github.io/node-mongodb-native/).

There are both reference and API documentation available. In the *API* section, the `MongoClient` and `Db` classes are the ones that most relate to the code we are writing ([`mongodb.github.io/node-mongodb-native/`](http://mongodb.github.io/node-mongodb-native/)).

The `connectDB` function creates the database client object. This object is only created as needed. The connection URL is provided through the `MONGO_URL` environment variable.

The `db` function is a simple wrapper around the client object to access the database that is used for the `Notes` application, which we specify via the `MONGO_DBNAME` environment variable. Therefore, to access the database, the code will have to call `db().mongoDbFunction()`.

Now, we can implement the `MongoDBNotesStore` class:

```

MongoDB 将所有文档存储在集合中。*集合* 是一组相关文档，类似于关系数据库中的表。这意味着创建一个新文档或更新现有文档始于将其构造为 JavaScript 对象，然后要求 MongoDB 将对象保存到数据库中。MongoDB 自动将对象编码为其内部表示形式。

`db().collection` 方法为我们提供了一个 `Collection` 对象，我们可以使用它来操作命名集合。在这种情况下，我们使用 `db().collection('notes')` 访问 `notes` 集合。

有关 `Collection` 类的文档，请参阅之前引用的 MongoDB Node.js 驱动程序文档。

在`create`方法中，我们使用`insertOne`；顾名思义，它将一个文档插入到集合中。这个文档用于`Note`类的字段。同样，在`update`方法中，`updateOne`方法首先找到一个文档（在这种情况下，通过查找具有匹配`notekey`字段的文档），然后根据指定的内容更改文档中的字段，然后将修改后的文档保存回数据库。

`read`方法使用`db().findOne`来搜索笔记。

`findOne`方法采用所谓的*查询选择器*。在这种情况下，我们要求与`notekey`字段匹配。MongoDB 支持一套全面的查询选择器操作符。

另一方面，`updateOne`方法采用所谓的*查询过滤器*。作为一个`update`操作，它在数据库中搜索与过滤器匹配的记录，根据更新描述符更新其字段，然后将其保存回数据库。

关于 MongoDB CRUD 操作的概述，包括插入文档、更新文档、查询文档和删除文档，请参阅[`docs.mongodb.com/manual/crud/`](https://docs.mongodb.com/manual/crud/)。

有关查询选择器的文档，请参阅[`docs.mongodb.com/manual/reference/operator/query/#query-selectors`](https://docs.mongodb.com/manual/reference/operator/query/#query-selectors)。

有关查询过滤器的文档，请参阅[`docs.mongodb.com/manual/core/document/#query-filter-documents`](https://docs.mongodb.com/manual/core/document/#query-filter-documents)。

有关更新描述符的文档，请参阅[`docs.mongodb.com/manual/reference/operator/update/`](https://docs.mongodb.com/manual/reference/operator/update/)。

MongoDB 有许多基本操作的变体。例如，`findOne`是基本`find`方法的一个变体。

在我们的`destroy`方法中，我们看到另一个`find`变体，`findOneAndDelete`。顾名思义，它查找与查询描述符匹配的文档，然后删除该文档。

在`keylist`方法中，我们需要处理集合中的每个文档，因此`find`查询选择器为空。`find`操作返回一个`Cursor`，这是一个用于导航查询结果的对象。`Cursor.forEach`方法采用两个回调函数，不是一个 Promise 友好的操作，因此我们必须使用一个 Promise 包装器。第一个回调函数对查询结果中的每个文档都会调用，而在这种情况下，我们只是将`notekey`字段推送到一个数组中。第二个回调函数在操作完成时调用，并且我们通知 Promise 它是成功还是失败。这给我们了我们的键数组，它返回给调用者。

有关`Cursor`类的文档，请参阅[`mongodb.github.io/node-mongodb-native/3.1/api/Cursor.html`](http://mongodb.github.io/node-mongodb-native/3.1/api/Cursor.html)。

在我们的`count`方法中，我们简单地调用 MongoDB 的`count`方法。`count`方法采用查询描述符，并且顾名思义，计算与查询匹配的文档数量。由于我们给出了一个空的查询选择器，它最终计算整个集合。

这使我们可以将`NOTES_MODEL`设置为`mongodb`来使用 MongoDB 数据库运行 Notes。

现在我们已经为 MongoDB 编写了所有的代码，我们可以继续测试`Notes`。

## 使用 MongoDB 运行 Notes 应用程序

我们准备使用 MongoDB 数据库测试`Notes`。到目前为止，你知道该怎么做；将以下内容添加到`package.json`的`scripts`部分：

```

The `MONGO_URL` environment variable is the URL to connect with your MongoDB database. This URL is the one that you need to use to run MongoDB on your laptop, as outlined at the top of this section. If you have a MongoDB server somewhere else, you'll be provided with the relevant URL to use.

You can start the `Notes` application as follows:

```

`MONGO_URL`环境变量应包含与您的 MongoDB 数据库连接的 URL。这里显示的 URL 对于在本地机器上启动 MongoDB 服务器是正确的，就像您在本节开始时在命令行上启动 MongoDB 一样。否则，如果您在其他地方提供了 MongoDB 服务器，您将被告知访问 URL 是什么，您的`MONGO_URL`变量应该有该 URL。

您可以启动两个`Notes`应用程序实例，并查看它们都共享相同的笔记集。

我们可以验证 MongoDB 数据库最终是否具有正确的值。首先，这样启动 MongoDB 客户端程序：

```

再次强调，这是基于迄今为止所呈现的 MongoDB 配置，如果您的配置不同，请在命令行上添加 URL。这将启动与 Notes 配置的数据库连接的交互式 MongoDB shell。要检查数据库的内容，只需输入命令：`db.notes.find()`。这将打印出每个数据库条目。

有了这一点，我们不仅完成了对`Notes`应用程序中 MongoDB 的支持，还支持了其他几种数据库，因此我们现在准备结束本章。

# 总结

在本章中，我们经历了不同的数据库技术的真正风暴。虽然我们一遍又一遍地看了同样的七个函数，但接触到各种数据存储模型和完成任务的方式是有用的。即便如此，在 Node.js 中访问数据库和数据存储引擎的选项只是触及了表面。

通过正确抽象模型实现，我们能够轻松地在不改变应用程序其余部分的情况下切换数据存储引擎。这种技术让我们探索了 JavaScript 中子类化的工作原理，以及创建相同 API 的不同实现的概念。此外，我们还对`import()`函数进行了实际介绍，并看到它可以用于动态选择要加载的模块。

在现实生活中的应用程序中，我们经常为类似的目的创建抽象。它们帮助我们隐藏细节或允许我们更改实现，同时使应用程序的其余部分与更改隔离。我们用于我们的应用程序的动态导入对于动态拼接应用程序非常有用；例如，加载给定目录中的每个模块。

我们避免了设置数据库服务器的复杂性。正如承诺的那样，当我们探索将 Node.js 应用程序部署到 Linux 服务器时，我们将在第十章中进行讨论，*将 Node.js 应用程序部署到 Linux 服务器*。

通过将我们的模型代码专注于存储数据，模型和应用程序应该更容易测试。我们将在第十三章中更深入地研究这一点，*单元测试和功能测试*。

在下一章中，我们将专注于支持多个用户，允许他们登录和退出，并使用 OAuth 2 对用户进行身份验证。


通过微服务对用户进行身份验证

现在我们的 Notes 应用程序可以将数据保存在数据库中，我们可以考虑下一步，即使这成为一个真正的应用程序的下一阶段，即对用户进行身份验证。

登录网站并使用其服务是非常自然的。我们每天都这样做，甚至信任银行和投资机构通过网站上的登录程序来保护我们的财务信息。超文本传输协议（HTTP）是一种无状态协议，网页应用程序无法通过 HTTP 请求比较多了解用户的信息。因为 HTTP 是无状态的，HTTP 请求本身并不知道用户的身份，也不知道驱动网络浏览器的用户是否已登录，甚至不知道 HTTP 请求是否由人发起。

用户身份验证的典型方法是向浏览器发送包含令牌的 cookie，以携带用户的身份，并指示该浏览器是否已登录。

使用 Express，最好的方法是使用`express-session`中间件，它可以处理带有 cookie 的会话管理。它易于配置，但不是用户身份验证的完整解决方案，因为它不处理用户登录/注销。

在用户身份验证方面，似乎领先的包是 Passport（[`passportjs.org/`](http://passportjs.org/)）。除了对本地用户信息进行身份验证外，它还支持对长列表的第三方服务进行身份验证。有了这个，可以开发一个网站，让用户使用来自另一个网站（例如 Twitter）的凭据进行注册。

我们将使用 Passport 来对用户进行身份验证，无论是存储在本地数据库中还是 Twitter 账户中。我们还将利用这个机会来探索基于 REST 的微服务，使用 Node.js。

原因是通过将用户信息存储在高度保护的飞地中，可以增加安全性的机会更大。许多应用团队将用户信息存储在一个受到严格控制的 API 和甚至物理访问用户信息数据库的严格控制区域中，尽可能多地实施技术屏障以防止未经批准的访问。我们不会走得那么远，但在本书结束时，用户信息服务将部署在自己的 Docker 容器中。

在本章中，我们将讨论以下三个方面：

+   创建一个微服务来存储用户资料/身份验证数据。

+   使用本地存储的密码对用户进行身份验证。

+   使用 OAuth2 支持通过第三方服务进行身份验证。具体来说，我们将使用 Twitter 作为第三方身份验证服务。

让我们开始吧！

首先要做的是复制上一章节使用的代码。例如，如果你将该代码保存在`chap07/notes`目录中，那么创建一个新目录`chap08/notes`。

# 第十一章：创建用户信息微服务

我们可以通过简单地向现有的*Notes*应用程序添加用户模型、一些路由和视图来实现用户身份验证和账户。虽然这很容易，但在真实的生产应用程序中是否会这样做呢？

考虑到用户身份信息的高价值和对强大可靠用户身份验证的极大需求。网站入侵经常发生，而似乎最经常被盗窃的是用户身份。因此，我们之前宣布了开发用户信息微服务的意图，但首先我们必须讨论这样做的技术原因。

当然，微服务并不是万能药，这意味着我们不应该试图将每个应用程序都强行塞进微服务的框架中。类比一下，微服务与 Unix 哲学中的小工具相契合，每个工具都做一件事情很好，然后我们将它们混合/匹配/组合成更大的工具。这个概念的另一个词是可组合性。虽然我们可以用这种哲学构建许多有用的软件工具，但它适用于诸如 Photoshop 或 LibreOffice 之类的应用程序吗？

这就是为什么微服务在应用团队中如此受欢迎的原因。如果使用得当，微服务架构更加灵活。正如我们之前提到的，我们的目标是实现高度安全的微服务部署。

决定已经做出，还有两个关于安全性影响的决定需要做。它们如下：

+   我们要创建自己的 REST 应用程序框架吗？

+   我们要创建自己的用户登录/身份验证框架吗？

在许多情况下，最好使用一个声誉良好的现有库，其中维护者已经解决了许多 bug，就像我们在上一章中使用 Sequelize **ORM** (**Object-Relational Mapping**)库一样，因为它很成熟。我们已经为 Notes 项目的这个阶段确定了两个库。

我们已经提到使用 Passport 来支持用户登录，以及对 Twitter 用户进行身份验证。

对于 REST 支持，我们本可以继续使用 Express，但我们将使用 Restify ([`restify.com/`](http://restify.com/))，这是一个流行的面向 REST 的应用程序框架。

为了测试服务，我们将编写一个命令行工具，用于管理数据库中的用户信息。我们不会在 Notes 应用程序中实现管理用户界面，而是依靠这个工具来管理用户。作为一个副作用，我们将拥有一个用于测试用户服务的工具。

一旦这项服务正常运行，我们将开始修改 Notes 应用程序，以从服务中访问用户信息，同时使用 Passport 来处理身份验证。

第一步是创建一个新目录来保存用户信息微服务。这应该是 Notes 应用程序的同级目录。如果您创建了一个名为`chap08/notes`的目录来保存 Notes 应用程序，那么请创建一个名为`chap08/users`的目录来保存微服务。

然后，在`chap08/users`目录中，运行以下命令：

```

This gets us ready to start coding. We'll use the `debug` module for logging messages, `js-yaml` to read the Sequelize configuration file, `restify` for its REST framework, and `sequelize/sqlite3` for database access.

In the sections to come, we will develop a database model to store user information, and then create a REST service to manage that data. To test the service, we'll create a command-line tool that uses the REST API.

## Developing the user information model

We'll be storing the user information using a Sequelize-based model in a SQL database. We went through that process in the previous chapter, but we'll do it a little differently this time. Rather than go for the ultimate flexibility of using any kind of database, we'll stick with Sequelize since the user information model is very simple and a SQL database is perfectly adequate.

The project will contain two modules. In this section, we'll create `users-sequelize.mjs`, which will define the SQUser schema and a couple of utility functions. In the next section, we'll start on `user-server.mjs`, which contains the REST server implementation. 

First, let's ponder an architectural preference. Just how much should we separate between the data model code interfacing with the database from the REST server code? In the previous chapter, we went for a clean abstraction with several implementations of the database storage layer. For a simple server such as this, the REST request handler functions could contain all database calls, with no abstraction layer. Which is the best approach? We don't have a hard rule to follow. For this server, we will have database code more tightly integrated to the router functions, with a few shared functions.

Create a new file named `users-sequelize.mjs` in `users` containing the following code:

```

与我们基于 Sequelize 的 Notes 模型一样，我们将使用**YAML Ain't Markup Language** (**YAML**)文件来存储连接配置。我们甚至使用相同的环境变量`SEQUELIZE_CONNECT`，以及相同的覆盖配置字段的方法。这种方法类似，通过`connectDB`函数设置连接并初始化 SQUsers 表。

通过这种方法，我们可以使用`SEQUELIZE_CONNECT`变量中的基本配置文件，然后使用其他环境变量来覆盖其字段。当我们开始部署 Docker 容器时，这将非常有用。

这里显示的用户配置文件模式是从 Passport 提供的规范化配置文件派生出来的，有关更多信息，请参阅[`www.passportjs.org/docs/profile`](http://www.passportjs.org/docs/profile)。

Passport 项目通过将多个第三方服务提供的用户信息协调为单个对象定义来开发了这个对象。为了简化我们的代码，我们只是使用了 Passport 定义的模式。

有几个函数需要创建，这些函数将成为管理用户数据的 API。让我们将它们添加到`users-sequelize.mjs`的底部，从以下代码开始：

```

In Restify, the route handler functions supply the same sort of `request` and `response` objects we've already seen. We'll go over the configuration of the REST server in the next section. Suffice to say that REST parameters arrive in the request handlers as the `req.params` object, as shown in the preceding code block. This function simplifies the gathering of those parameters into a simple object that happens to match the SQUser schema, as shown in the following code block:

```

当我们从数据库中获取 SQUser 对象时，Sequelize 显然会给我们一个具有许多额外字段和 Sequelize 使用的函数的 Sequelize 对象。我们不希望将这些数据发送给我们的调用者。此外，我们认为不提供*密码*数据超出此服务器的边界将增加安全性。这个函数从 SQUser 实例中产生一个简单的、经过消毒的匿名 JavaScript 对象。我们本可以定义一个完整的 JavaScript 类，但那有什么用呢？这个匿名的 JavaScript 类对于这个简单的服务器来说已经足够了，如下面的代码块所示：

```

The pair of functions shown in the preceding code block provides some database operations that are used several times in the `user-server.mjs` module. 

In `findOneUser`, we are looking up a single SQUser, and then returning a sanitized copy. In `createUser`, we gather the user parameters from the request object, create the SQUser object in the database, and then retrieve that newly created object to return it to the caller.

If you refer back to the `connectDB` function, there is a `SEQUELIZE_CONNECT` environment variable for the configuration file. Let's create one for SQLite3 that we can name `sequelize-sqlite.yaml`, as follows:

```

这就像我们在上一章中使用的配置文件一样。

这是我们在服务的数据库端所需要的。现在让我们继续创建 REST 服务。

## 为用户信息创建一个 REST 服务器

用户信息服务是一个用于处理用户信息数据和身份验证的 REST 服务器。我们的目标当然是将其与 Notes 应用程序集成，但在一个真实的项目中，这样的用户信息服务可以与多个 Web 应用程序集成。REST 服务将提供我们在开发 Notes 中用户登录/注销支持时发现有用的功能，我们稍后将在本章中展示。

在`package.json`文件中，将`main`标签更改为以下代码行：

```

This declares that the module we're about to create, `user-server.mjs`, is the main package of this project.

Make sure the scripts section contains the following script:

```

显然，这是我们启动服务器的方式。它使用上一节的配置文件，并指定我们将在端口`5858`上监听。

然后，创建一个名为`user-server.mjs`的文件，其中包含以下代码：

```

We're using Restify, rather than Express, to develop this server. Obviously, the Restify API has similarities with Express, since both point to the Ruby framework Sinatra for inspiration. We'll see even more similarities when we talk about the route handler functions.

What we have here is the core setup of the REST server. We created the server object and added a few things that, in Express, were called *middleware*, but what Restify simply refers to as *handlers*. A Restify handler function serves the same purpose as an Express middleware function. Both frameworks let you define a function chain to implement the features of your service. One calls it a *middleware* function and the other calls it a *handler* function, but they're almost identical in form and function.

We also have a collection of listener functions that print a startup message and handle uncaught errors. You do remember that it's important to catch the uncaught errors?

An interesting thing is that, since REST services are often versioned, Restify has built-in support for handling version numbers. Restify supports **semantic versioning** (**SemVer**) version matching in the `Accept-Version` HTTP header. 

In the *handlers* that were installed, they obviously have to do with authorization and parsing parameters from the **Uniform Resource Locator** (**URL**) query string and from the HTTP body. The handlers with names starting with `restify.plugins` are maintained by the Restify team, and documented on their website.

That leaves the handler simply named *check*. This handler is in `user-server.mjs` and provides a simple mechanism of token-based authentication for REST clients.

Add the following code to the bottom of `user-server.mjs`:

```

这个处理程序对每个请求都执行，并紧随`restify.plugins.authorizationParser`。它查找授权数据，特别是 HTTP 基本授权，是否已在 HTTP 请求中提供。然后它循环遍历`apiKeys`数组中的键列表，如果基本授权参数匹配，则接受调用者。

这不应被视为最佳实践的示例，因为 HTTP 基本认证被广泛认为极不安全，还有其他问题。但它演示了基本概念，并且还表明通过类似的处理程序轻松实现基于令牌的授权。

这也向我们展示了 Restify 处理程序函数的函数签名，即与 Express 中间件使用的相同签名，`request`和`result`对象以及`next`回调。

Restify 和 Express 在`next`回调的使用上有很大的区别。在 Express 中，记住中间件函数调用`next`，除非该中间件函数是处理链上的最后一个函数，例如，如果函数已经调用了`res.send`（或等效的）来向调用者发送响应。在 Restify 中，每个处理程序函数都调用`next`。如果处理程序函数知道它应该是处理程序链上的最后一个函数，那么它使用`next(false)`；否则，它调用`next()`。如果处理程序函数需要指示错误，它调用`next(err)`，其中`err`是一个对象，`instanceof Error`为`true`。

考虑以下假设的处理程序函数：

```

This shows the following three cases: 

1.  Errors are indicated with `next(new Error('Error description'))`.
2.  Completion is indicated with `next(false)`. 
3.  The continuation of processing is indicated with `next()`. 

We have created the starting point for a user information data model and the matching REST service. The next thing we need is a tool to test and administer the server.

What we want to do in the following sections is two things. First, we'll create the REST handler functions to implement the REST API. At the same time, we'll create a command-line tool that will use the REST API and let us both test the server and add or delete users.

### Creating a command-line tool to test and administer the user authentication server

To give ourselves assurance that the user authentication server works, let's write a tool with which to exercise the server that can also be used for administration. In a typical project, we'd create not only a customer-facing web user interface, but also an administrator-facing web application to administer the service. Instead of doing that here, we'll create a command-line tool.

The tool will be built with Commander, a popular framework for developing command-line tools in Node.js. With Commander, we can easily build a **command-line interface** (**CLI**) tool supporting the `program verb --option optionValue parameter` pattern.

For documentation on Commander, see [`www.npmjs.com/package/commander`](https://www.npmjs.com/package/commander).

Any command-line tool looks at the `process.argv` array to know what to do. This array contains strings parsed from what was given on the command line. The concept for all this goes way back to the earliest history of Unix and the C programming language. 

For documentation on the `process.argv` array, refer to [`nodejs.org/api/process.html#process_process_argv`](https://nodejs.org/api/process.html#process_process_argv).

By using Commander, we have a simpler path of dealing with the command line. It uses a declarative approach to handling command-line parameters. This means we use Commander functions to declare the options and sub-commands to be used by this program, and then we ask Commander to parse the command line the user supplies. Commander then calls the functions we declare based on the content of the command line.

Create a file named `cli.mjs` containing the following code:

```

这只是命令行工具的起点。对于大多数 REST 处理程序函数，我们还将在此工具中实现一个子命令。我们将在后续章节中处理该代码。现在，让我们专注于命令行工具的设置方式。

Commander 项目建议我们将默认导入命名为`program`，如前面的代码块所示。如前所述，我们通过在此对象上调用方法来声明命令行选项和子命令。

为了正确解析命令行，`cli.mjs`中的最后一行代码必须如下所示：

```

The `process.argv` variable is, of course, the command-line arguments split out into an array. Commander, then, is processing those arguments based on the options' declarations.

For the REST client, we use the `restify-clients` package. As the name implies, this is a companion package to Restify and is maintained by the Restify team.

At the top of this script, we declare a few variables to hold connection parameters. The goal is to create a connection URL to access the REST service. The `connect_url` variable is initialized with the default value, which is port `5858` on the localhost. 

The function named `client` looks at the information Commander parses from the command line, as well as a number of environment variables. From that data, it deduces any modification to the `connect_url` variable. The result is that we can connect to this service on any server from our laptop to a faraway cloud-hosted server.

We've also hardcoded the access token and the use of Basic Auth. Put on the backlog a high-priority task to change to a stricter form of authentication.

Where do the values of `program.port`, `program.host`, and `program.url` come from? We declared those variables—that's where they came from.

Consider the following line of code:

```

这声明了一个选项，要么是`-p`要么是`--port`，Commander 将从命令行中解析出来。请注意，我们所做的只是写一个文本字符串，从中 Commander 就知道它必须解析这些选项。这不是很容易吗？

当它看到这些选项之一时，`<port>`声明告诉 Commander 这个选项需要一个参数。它会从命令行中解析出该参数，然后将其分配给`program.port`。

因此，`program.port`、`program.host`和`program.url`都是以类似的方式声明的。当 Commander 看到这些选项时，它会创建相应的变量，然后我们的`client`函数将获取这些数据并适当地修改`connect_url`。

这些声明的一个副作用是 Commander 可以自动生成帮助文本。我们将能够输入以下代码来实现结果：

```

The text comes directly from the descriptive text we put in the declarations. Likewise, each of the sub-commands also takes a `--help` option to print out corresponding help text.

With all that out of the way, let's start creating these commands and REST functions.

### Creating a user in the user information database

We have the starting point for the REST server, and the starting point for a command-line tool to administer the server. Let's start creating the functions—and, of course, the best place to start is to create an SQUser object.

In `user-server.mjs`, add the following route handler:

```

这个函数处理了`/create-user` URL 上的`POST`请求。这应该看起来非常类似于 Express 路由处理程序函数，除了使用`next`回调。回顾一下关于这一点的讨论。就像我们在 Notes 应用程序中所做的那样，我们将处理程序回调声明为异步函数，然后使用`try`/`catch`结构来捕获所有错误并将它们报告为错误。

处理程序以`connectDB`开始，以确保数据库设置正确。然后，如果你回顾`createUser`函数，你会看到它从请求参数中收集用户数据，然后使用`SQUser.create`在数据库中创建一个条目。我们将在这里收到经过处理的用户对象，并简单地将其返回给调用者。

让我们还向`user-server.mjs`中添加以下代码： 

```

This is a variation on creating an SQUser. While implementing login support in the Notes application, there was a scenario in which we had an authenticated user that may or may not already have an SQUser object in the database. In this case, we look to see whether the user already exists and, if not, then we create that user.

Let's turn now to `cli.mjs` and implement the sub-commands to handle these two REST functions, as follows:

```

通过使用`program.command`，我们声明了一个子命令——在这种情况下是`add`。`<username>`声明表示这个子命令需要一个参数。Commander 将会在`action`方法中传递`username`参数的值。

`program.command`声明的结构首先声明子命令的语法。`description`方法提供用户友好的文档。`option`方法调用是针对这个子命令的选项，而不是全局选项。最后，`action`方法是我们提供的回调函数，当 Commander 在命令行中看到这个子命令时将被调用。

在`program.command`字符串中声明的任何参数最终都会成为回调函数的参数。

这个子命令的选项值都会落在`cmdObj`对象中。相比之下，全局选项的值会附加到`program`对象上。

有了这个理解，我们可以看到这个子命令从命令行收集信息，然后使用`client`函数连接到服务器。它调用`/create-user` URL，传递从命令行收集的数据。收到响应后，它将打印出错误或结果对象。

现在让我们添加对应于`/find-or-create` URL 的子命令，如下所示：

```

This is very similar, except for calling `/find-or-create`.

We have enough here to run the server and try the following two commands:

```

我们在一个命令窗口中运行这个命令来启动服务器。在另一个命令窗口中，我们可以运行以下命令：

```

Over in the server window, it will print a trace of the actions taken in response to this. But it's what we expect: the values we gave on the command line are in the database, as shown in the following code block:

```

同样，我们成功地使用了`find-or-create`命令。

这使我们能够创建 SQUser 对象。接下来，让我们看看如何从数据库中读取。

### 从用户信息服务中读取用户数据

我们想要支持的下一件事是在用户信息服务中查找用户。不是一个通用的搜索功能，而是需要为给定的用户名检索一个 SQUser 对象。我们已经有了这个目的的实用函数；现在只需要连接一个 REST 端点。

在`user-server.mjs`中，添加以下函数：

```

And, as expected, that was easy enough. For the `/find` URL, we need to supply the username in the URL. The code simply looks up the SQUser object using the existing utility function.

A related function retrieves the SQUser objects for all users. Add the following code to `user-server.mjs`:

```

我们从上一章知道，`findAll`操作会检索所有匹配的对象，并且传递一个空的查询选择器，比如这样，会导致`findAll`匹配每个 SQUser 对象。因此，这执行了我们描述的任务，检索所有用户的信息。

然后，在`cli.mjs`中，我们添加以下子命令声明：

```

This is similarly easy. We pass the username provided on our command line in the `/find` URL and then print out the result. Likewise, for the `list-users` sub-command, we simply call `/list` on the server and print out the result.

After restarting the server, we can test the commands, as follows:

```

而且，结果正如我们所预期的那样。

我们需要的下一个操作是更新 SQUser 对象。

### 在用户信息服务中更新用户信息

要添加的下一个功能是更新用户信息。为此，我们可以使用 Sequelize 的`update`函数，并将其简单地公开为 REST 操作。

为此，在`user-server.mjs`中添加以下代码：

```

The caller is to provide the same set of user information parameters, which will be picked up by the `userParams` function. We then use the `update` function, as expected, and then retrieve the modified SQUser object, sanitize it, and send it as the result.

To match that function, add the following code to `cli.mjs`:

```

预期的是，这个子命令必须使用相同的用户信息参数集。然后，它将这些参数捆绑到一个对象中，将其发布到 REST 服务器上的`/update-user`端点。

然后，为了测试结果，我们运行以下命令：

```

And, indeed, we managed to change Snuffy's email address.

The next operation is to delete an SQUser object.

### Deleting a user record from the user information service

Our next operation will complete the **create, read, update, and delete** (**CRUD**) operations by letting us delete a user.

Add the following code to `user-server.mjs`:

```

这很简单。我们首先查找用户以确保它存在，然后在 SQUser 对象上调用`destroy`函数。不需要任何结果，所以我们发送一个空对象。

为了运行这个函数，将以下代码添加到`cli.mjs`中：

```

This is simply to send a `DELETE` request to the server on the `/destroy` URL. 

And then, to test it, run the following command:

```

首先，我们删除了 Snuffy 的用户记录，得到了一个预期的空响应。然后，我们尝试检索他的记录，预期地出现了错误。

虽然我们已经完成了 CRUD 操作，但还有最后一个任务要完成。

### 在用户信息服务中检查用户的密码

我们怎么能够有一个用户登录/注销服务而不能检查他们的密码呢？问题是：密码检查应该发生在哪里？似乎，不用深入研究，最好在用户信息服务内部执行此操作。我们之前描述过这个决定，可能更安全的做法是永远不要将用户密码暴露到用户信息服务之外。因此，密码检查应该发生在该服务中，以便密码不会流出服务范围。

让我们从`user-server.mjs`中的以下函数开始：

```

This lets us support the checking of user passwords. There are three conditions to check, as follows:

*   Whether there is no such user
*   Whether the passwords matched
*   Whether the passwords did not match

The code neatly determines all three conditions and returns an object indicating, via the `check` field, whether the user is authenticated. The caller is to send `username` and `password` parameters that will be checked.

To check it out, let's add the following code to `cli.mjs`:

```

并且，预期的是，调用此操作的代码很简单。我们从命令行获取`username`和`password`参数，将它们发送到服务器，然后打印结果。

为了验证它是否有效，运行以下命令：

```

Indeed, the correct password gives us a `true` indicator, while the wrong password gives us `false`.

We've done a lot in this section by implementing a user information service. We successfully created a REST service while thinking about architectural choices around correctly handling sensitive user data. We were also able to verify that the REST service is functioning using an ad hoc testing tool. With this command-line tool, we can easily try any combination of parameters, and we can easily extend it if the need arises to add more REST operations.

Now, we need to start on the real goal of the chapter: changing the Notes user interface to support login/logout. We will see how to do this in the following sections.

# Providing login support for the Notes application

Now that we have proved that the user authentication service is working, we can set up the Notes application to support user logins. We'll be using Passport to support login/logout, and the authentication server to store the required data.

Among the available packages, Passport stands out for simplicity and flexibility. It integrates directly with the Express middleware chain, and the Passport community has developed hundreds of so-called strategy modules to handle authentication against a long list of third-party services.

Refer to [`www.passportjs.org/`](http://www.passportjs.org/) for information and documentation.

Let's start this by adding a module for accessing the user information REST server we just created.

## Accessing the user authentication REST API

The first step is to create a user data model for the Notes application. Rather than retrieving data from data files or a database, it will use REST to query the server we just created. Recall that we created this REST service in the theory of walling off the service since it contains sensitive user information.

Earlier, we suggested duplicating Chapter 7, *Data Storage and Retrieval*, code for Notes in the `chap08/notes` directory and creating the user information server as `chap08/users`.

Earlier in this chapter, we used the `restify-clients` module to access the REST service. That package is a companion to the Restify library; the `restify` package supports the server side of the REST protocol and `restify-clients` supports the client side. 

However nice the `restify-clients` library is, it doesn't support a Promise-oriented API, as is required to play well with `async` functions. Another library, SuperAgent, does support a Promise-oriented API and plays well in `async` functions, and there is a companion to that package, SuperTest, that's useful in unit testing. We'll use SuperTest in Chapter 13, *Unit Testing and Functional Testing* when we talk about unit testing.

For documentation, refer to [`www.npmjs.com/package/superagent`](https://www.npmjs.com/package/superagent) and [`visionmedia.github.io/superagent/`](http://visionmedia.github.io/superagent/).

To install the package (again, in the Notes application directory), run the following command:

```

然后，创建一个新文件`models/users-superagent.mjs`，其中包含以下代码：

```

The `reqURL` function is similar in purpose to the `connectDB` functions that we wrote in earlier modules. Remember that we used `connectDB` in earlier modules to open a database connection that will be kept open for a long time. With SuperAgent, we don't leave a connection open to the service. Instead, we open a new server connection on each request. For every request, we will formulate the request URL. The base URL, such as `http://localhost:3333/`, is to be provided in the `USER_SERVICE_URL` environment variable. The `reqURL` function modifies that URL, using the new **Web Hypertext Application Technology Working Group** (**WHATWG**) URL support in Node.js, to use a given URL path.

We also added the authentication ID and code required for the server. Obviously, when the backlog task comes up to use a better token authentication system, this will have to change.

To handle creating and updating user records, run the following code:

```

这些是我们的`create`和`update`函数。在每种情况下，它们接受提供的数据，构造一个匿名对象，并将其`POST`到服务器。该函数应提供与 SQUser 模式对应的值。它将提供的数据捆绑在`send`方法中，设置各种参数，然后设置基本身份验证令牌。

SuperAgent 库使用一种称为*方法链*的 API 风格。编码者将方法调用链接在一起以构建请求。方法调用链可以以`.then`或`.end`子句结束，其中任何一个都接受一个回调函数。但是如果两者都不加，它将返回一个 Promise，当然，Promise 让我们可以直接从异步函数中使用它。

每个函数末尾的`res.body`值包含了 REST 服务器返回的值。在整个库中，我们将使用`.auth`子句来设置所需的身份验证密钥。

这些匿名对象与普通对象有些不同。我们在这里使用了一个新的**ECMAScript 2015** (**ES-2015**)特性，到目前为止我们还没有讨论过。与使用`fieldName: fieldValue`表示对象字段不同，ES-2015 给了我们一个选项，当用于`fieldValue`的变量名与所需的`fieldName`匹配时，可以缩短这个表示法。换句话说，我们只需列出变量名，字段名将自动匹配变量名。

在这种情况下，我们故意选择了参数的变量名，以匹配服务器使用的参数名称与对象字段名称。这样做，我们可以使用匿名对象的缩写表示法，通过始终使用一致的变量名，使我们的代码更清晰。

现在，添加以下函数以支持检索用户记录：

```

This is following the same pattern as before. The `set` methods are, of course, used for setting HTTP headers in the REST call. This means having at least a passing knowledge of the HTTP protocol.

The `Content-Type` header says the data sent to the server is in **JavaScript Object Notation** (**JSON**) format. The `Accept` header says that this REST client can handle JSON data. JSON is, of course, easiest for a JavaScript program—such as what we're writing—to utilize.

Let's now create the function for checking passwords, as follows:

```

这种方法值得注意的一点是，它可以在 URL 中获取参数，而不是在请求体中获取，就像这里所做的那样。但是，由于请求 URL 经常被记录到文件中，将用户名和密码参数放在 URL 中意味着用户身份信息将被记录到文件中并成为活动报告的一部分。这显然是一个非常糟糕的选择。将这些参数放在请求体中不仅避免了这种糟糕的结果，而且如果使用了与服务的 HTTPS 连接，交易将被加密。

然后，让我们创建我们的 `find-or-create` 函数，如下所示：

```

The `/find-or-create` function either discovers the user in the database or creates a new user. The `profile` object will come from Passport, but take careful note of what we do with `profile.id`. The Passport documentation says it will provide the username in the `profile.id` field, but we want to store it as `username` instead.

Let's now create a function to retrieve the list of users, as follows:

```

和以前一样，这非常简单。

有了这个模块，我们可以与用户信息服务进行接口，现在我们可以继续修改 Notes 用户界面。

## 在 Notes 应用程序中整合登录和注销路由函数

到目前为止，我们构建了一个用户数据模型，用一个 REST API 包装该模型来创建我们的身份验证信息服务。然后，在 Notes 应用程序中，我们有一个模块从这个服务器请求用户数据。到目前为止，Notes 应用程序中没有任何内容知道这个用户模型的存在。下一步是创建一个用于登录/注销 URL 的路由模块，并更改 Notes 的其余部分以使用用户数据。

路由模块是我们使用 `passport` 处理用户身份验证的地方。第一项任务是安装所需的模块，如下所示：

```

The `passport` module gives us the authentication algorithms. To support different authentication mechanisms, the passport authors have developed several *strategy* implementations—the authentication mechanisms, or strategies, corresponding to the various third-party services that support authentication, such as using OAuth to authenticate against services such as Facebook, Twitter, or GitHub.

Passport also requires that we install Express Session support. Use the following command to install the modules:

```

Express 会话支持，包括所有各种会话存储实现，都在其 GitHub 项目页面上有文档，网址为 [`github.com/expressjs/session`](https://github.com/expressjs/session)。

`passport-local` 包中实现的策略仅使用存储在应用程序本地的数据进行身份验证，例如我们的用户身份验证信息服务。稍后，我们将添加一个策略模块来验证使用 Twitter 的 OAuth。

让我们从创建路由模块 `routes/users.mjs` 开始，如下所示：

```

This brings in the modules we need for the `/users` router. This includes the two `passport` modules and the REST-based user authentication model. 

In `app.mjs`, we will be adding *session* support so our users can log in and log out. That relies on storing a cookie in the browser, and the cookie name is found in this variable exported from `app.mjs`. We'll be using that cookie in a moment.

Add the following functions to the end of `routes/users.mjs`:

```

`initPassport` 函数将从 `app.mjs` 被调用，并在 Express 配置中安装 Passport 中间件。我们将在后面讨论这个的影响，当我们到达 `app.mjs` 的变化时，但 Passport 使用会话来检测这个 HTTP 请求是否经过身份验证。它查看每个进入应用程序的请求，寻找关于这个浏览器是否已登录的线索，并将数据附加到请求对象作为 `req.user`。

`ensureAuthenticated` 函数将被其他路由模块使用，并插入到任何需要经过身份验证的已登录用户的路由定义中。例如，编辑或删除笔记需要用户已登录，因此 `routes/notes.mjs` 中的相应路由必须使用 `ensureAuthenticated`。如果用户未登录，此函数将重定向他们到 `/users/login`，以便他们可以登录。

在 `routes/users.mjs` 中添加以下路由处理程序：

```

Because this router is mounted on `/users`, all these routes will have `/user` prepended. The `/users/login` route simply shows a form requesting a username and password. When this form is submitted, we land in the second route declaration, with a `POST` on `/users/login`. If `passport` deems this a successful login attempt using `LocalStrategy`, then the browser is redirected to the home page. Otherwise, it is redirected back to the `/users/login` page.

Add the following route for handling logout:

```

当用户请求注销 Notes 时，他们将被发送到 `/users/logout`。我们将在页眉模板中添加一个按钮来实现这个目的。`req.logout` 函数指示 Passport 擦除他们的登录凭据，然后将他们重定向到主页。

这个函数与 Passport 文档中的内容有所偏差。在那里，我们被告知只需调用 `req.logout`，但有时仅调用该函数会导致用户未注销。有必要销毁会话对象，并清除 cookie，以确保用户已注销。cookie 名称在 `app.mjs` 中定义，我们为这个函数导入了 `sessionCookieName`。

添加 `LocalStrategy` 到 Passport，如下所示：

```

Here is where we define our implementation of `LocalStrategy`. In the callback function, we call `usersModel.userPasswordCheck`, which makes a REST call to the user authentication service. Remember that this performs the password check and then returns an object indicating whether the user is logged in.

A successful login is indicated when `check.check` is `true`. In this case, we tell Passport to use an object containing `username` in the session object. Otherwise, we have two ways to tell Passport that the login attempt was unsuccessful. In one case, we use `done(null, false)` to indicate an error logging in, and pass along the error message we were given. In the other case, we'll have captured an exception, and pass along that exception.

You'll notice that Passport uses a callback-style API. Passport provides a `done` function, and we are to call that function when we know what's what. While we use an `async` function to make a clean asynchronous call to the backend service, Passport doesn't know how to grok the Promise that would be returned. Therefore, we have to throw a `try/catch` around the function body to catch any thrown exception.

Add the following functions to manipulate data stored in the session cookie:

```

前面的函数负责对会话的身份验证数据进行编码和解码。我们只需要将`username`附加到会话中，就像我们在`serializeUser`中所做的那样。`deserializeUser`对象在处理传入的 HTTP 请求时被调用，这是我们查找用户配置文件数据的地方。Passport 会将其附加到请求对象上。

### 对 app.mjs 进行登录/注销更改

在`app.mjs`中需要进行一些更改，其中一些我们已经提到过。我们已经将 Passport 模块的依赖项仔细隔离到`routes/users.mjs`中。`app.mjs`中需要的更改支持`routes/users.mjs`中的代码。

添加导入以从用户路由模块中引入函数，如下所示：

```

The User router supports the `/login` and `/logout` URLs, as well as using Passport for authentication. We need to call `initPassport` for a little bit of initialization.

And now, let's import modules for session handling, as follows:

```

因为 Passport 使用会话，我们需要在 Express 中启用会话支持，这些模块也这样做。`session-file-store`模块将我们的会话数据保存到磁盘上，这样我们可以在不丢失会话的情况下终止和重新启动应用程序。还可以使用适当的模块将会话保存到数据库中。文件系统会话存储仅在所有 Notes 实例运行在同一台服务器计算机上时才适用。对于分布式部署情况，您需要使用在整个网络服务上运行的会话存储，例如数据库。

我们在这里定义`sessionCookieName`，以便它可以在多个地方使用。默认情况下，`express-session`使用名为`connect.sid`的 cookie 来存储会话数据。作为一种小的安全措施，当有一个已发布的默认值时，使用不同的非默认值是有用的。每当我们使用默认值时，可能会有攻击者知道安全漏洞，这取决于该默认值。

将以下代码添加到`app.mjs`中：

```

Here, we initialize the session support. The field named `secret` is used to sign the session ID cookie. The session cookie is an encoded string that is encrypted in part using this secret. In the Express Session documentation, they suggest the `keyboard cat` string for the secret. But, in theory, what if Express has a vulnerability, such that knowing this secret can make it easier to break the session logic on your site? Hence, we chose a different string for the secret, just to be a little different and—perhaps—a little more secure.

Similarly, the default cookie name used by `express-session` is `connect.sid`. Here's where we change the cookie name to a non-default name.

`FileStore` will store its session data records in a directory named `sessions`. This directory will be auto-created as needed.

In case you see errors on Windows that are related to the files used by `session-file-store`, there are several alternate session store packages that can be used.  The attraction of the `session-file-store` is that it has no dependency on a service like a database server.  Two other session stores have a similar advantage, `LokiStore`, and `MemoryStore`. Both are configured similarly to the `session-file-store package`. For example, to use `MemoryStore`, first use npm to install the `memorystore` package, then use these  lines of code in `app.mjs`:

```

这是相同的初始化，但是使用`MemoryStore`而不是`FileStore`。

要了解有关会话存储实现的更多信息，请参阅：[`expressjs.com/en/resources/middleware/session.html#compatible-session-stores`](http://expressjs.com/en/resources/middleware/session.html#compatible-session-stores)

挂载用户路由，如下所示：

```

These are the three routers that are used in the Notes application. 

### Login/logout changes in routes/index.mjs

This router module handles the home page. It does not require the user to be logged in, but we want to change the display a little if they are logged in. To do so, run the following code:

```

记住，我们确保`req.user`拥有用户配置文件数据，这是在`deserializeUser`中完成的。我们只需检查这一点，并确保在渲染视图模板时添加该数据。

我们将对大多数其他路由定义进行类似的更改。之后，我们将讨论视图模板的更改，在其中我们使用`req.user`来在每个页面上显示正确的按钮。

### 在`routes/notes.mjs`中需要进行登录/注销更改

这里需要的更改更为重要，但仍然很简单，如下面的代码片段所示：

```

We need to use the `ensureAuthenticated` function to protect certain routes from being used by users who are not logged in. Notice how ES6 modules let us import just the function(s) we require. Since that function is in the User router module, we need to import it from there.

Modify the `/add` route handler, as shown in the following code block:

```

我们将在整个模块中进行类似的更改，添加对`ensureAuthenticated`的调用，并使用`req.user`来检查用户是否已登录。目标是让几个路由确保路由仅对已登录用户可用，并且在这些路由和其他路由中将`user`对象传递给模板。

我们添加的第一件事是在路由定义中调用`usersRouter.ensureAuthenticated`。如果用户未登录，他们将由于该函数而被重定向到`/users/login`。

因为我们已确保用户已经通过身份验证，所以我们知道`req.user`已经有了他们的配置文件信息。然后我们可以简单地将其传递给视图模板。

对于其他路由，我们需要进行类似的更改。

修改`/save`路由处理程序如下：

```

The `/save` route only requires this change to call `ensureAuthenticated` in order to ensure that the user is logged in.

Modify the `/view` route handler, as follows:

```

对于这个路由，我们不需要用户已登录。如果有的话，我们需要用户的配置文件信息发送到视图模板。

修改`/edit`和`/destroy`路由处理程序如下：

```

Remember that throughout this module, we have made the following two changes to router functions:

1.  We protected some routes using `ensureAuthenticated` to ensure that the route is available only to logged-in users.
2.  We passed the `user` object to the template.

For the routes using `ensureAuthenticated`, it is guaranteed that `req.user` will contain the `user` object.  In other cases, such as with the `/view` router function, `req.user` may or may not have a value, and in case it does not, we make sure to pass `undefined`. In all such cases, the templates need to change in order to use the `user` object to detect whether the user is logged in, and whether to show HTML appropriate for a logged-in user.

### Viewing template changes supporting login/logout

So far, we've created a backend user authentication service, a REST module to access that service, a router module to handle routes related to logging in and out of the website, and changes in `app.mjs` to use those modules. We're almost ready, but we've got a number of changes left that need to be made to the templates. We're passing the `req.user` object to every template because each one must be changed to accommodate whether the user is logged in. 

This means that we can test whether the user is logged in simply by testing for the presence of a `user` variable.

In `partials/header.hbs`, make the following additions:

```

我们在这里做的是控制屏幕顶部显示哪些按钮，这取决于用户是否已登录。较早的更改确保了如果用户已注销，则`user`变量将为`undefined`；否则，它将具有用户配置文件对象。因此，只需检查`user`变量即可，如前面的代码块所示，以渲染不同的用户界面元素。

未登录的用户不会看到“添加笔记”按钮，并会看到一个登录按钮。否则，用户会看到“添加笔记”按钮和一个注销按钮。登录按钮将用户带到`/users/login`，而注销按钮将他们带到`/users/logout`。这两个按钮都在`routes/users.js`中处理，并执行预期的功能。

注销按钮具有 Bootstrap 徽章组件显示用户名。这为已登录的用户名提供了一个小的视觉标识。稍后我们将看到，它将作为用户身份的视觉提示。

因为`nav`现在支持登录/注销按钮，我们已经更改了`navbar-toggler`按钮，以便它控制具有`id="navbarLogIn"`的`<div>`。

我们需要创建`views/login.hbs`，如下所示：

```

This is a simple form decorated with Bootstrap goodness to ask for the username and password. When submitted, it creates a `POST` request to `/users/login`, which invokes the desired handler to verify the login request. The handler for that URL will start the Passport process to decide whether the user is authenticated.

In `views/notedestroy.hbs`, we want to display a message if the user is not logged in. Normally, the form to cause the note to be deleted is displayed, but if the user is not logged in, we want to explain the situation, as illustrated in the following code block:

```

这很简单 - 如果用户已登录，则显示表单；否则，在`partials/not-logged-in.hbs`中显示消息。我们根据`user`变量确定要显示其中哪一个。

我们可以在`partials/not-logged-in.hbs`中插入以下代码块中显示的代码：

```

As the text says, this will probably never be shown to users. However, it is useful to put something such as this in place since it may show up during development, depending on the bugs you create.

In `views/noteedit.hbs`, we require a similar change, as follows:

```

也就是说，在底部我们添加了一个段落，对于未登录的用户，引入了`not-logged-in`部分。

**Bootstrap jumbotron**组件可以创建一个漂亮而大的文本显示，非常引人注目。然而，用户不应该看到这一点，因为这些模板只在我们预先验证用户已登录时使用。

这样的消息对于检查代码中的错误非常有用。假设我们疏忽了，并且未能确保这些表单仅显示给已登录用户。假设我们有其他错误，未检查表单提交以确保它仅由已登录用户请求。以这种方式修复模板是另一层防止向未被允许使用该功能的用户显示表单的预防措施。

我们现在已经对用户界面进行了所有更改，并准备测试登录/注销功能。

## 使用用户身份验证运行 Notes 应用程序

我们已经创建了用户信息 REST 服务，创建了一个模块来从 Notes 访问该服务，修改了路由模块以正确访问用户信息服务，并更改了其他支持登录/注销所需的内容。

必要的最后一个任务是修改`package.json`的脚本部分，如下所示：

```

In the previous chapters, we built up quite a few combinations of models and databases for running the Notes application. Since we don't need those, we can strip most of them out from `package.json`. This leaves us with one, configured to use the Sequelize model for Notes, using the SQLite3 database, and to use the new user authentication service that we wrote earlier. All the other Notes data models are still available, just by setting the environment variables appropriately.

`USER_SERVICE_URL` needs to match the port number that we designated for that service.

In one window, start the user authentication service, as follows:

```

然后，在另一个窗口中，按照以下方式启动 Notes 应用程序：

```

You'll be greeted with the following message:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/ceb549b2-cf18-4dd8-9830-b8ef51822b0e.png)

Notice the new button, Log in, and the lack of an ADD Note button. We're not logged in, and so `partials/header.hbs` is rigged to show only the Log in button.

Click on the Log in button, and you will see the login screen, as shown in the following screenshot:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/15c349d7-2754-4ef5-8749-7842178385cc.png)

This is our login form from `views/login.hbs`. You can now log in, create a note or three, and you might end up with the following messages on the home page:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/8dd14aa5-9173-4621-a7fa-9aa53572f658.png)

You now have both Log Out and ADD Note buttons. You'll notice that the Log Out button has the username (me) shown. After some thought and consideration, this seemed the most compact way to show whether the user is logged in, and which user is logged in. This might drive the user experience team nuts, and you won't know whether this user interface design works until it's tested with users, but it's good enough for our purpose at the moment.

In this section, we've learned how to set up a basic login/logout functionality using locally stored user information. This is fairly good, but many web applications find it useful to allow folks to log in using their Twitter or other social media accounts for authentication. In the next section, we'll learn about that by setting up Twitter authentication.

# Providing Twitter login support for the Notes application

If you want your application to hit the big time, it's a great idea to ease the registration process by using third-party authentication. Websites all over the internet allow you to log in using accounts from other services such as Facebook or Twitter. Doing so removes hurdles to prospective users signing up for your service. Passport makes it extremely easy to do this.

Authenticating users with Twitter requires installation of `TwitterStrategy` from the `passport-twitter` package, registering a new application with Twitter, adding a couple of routes to `routes/user.mjs`, and making a small change in `partials/header.hbs`. Integrating other third-party services requires similar steps.

## Registering an application with Twitter

Twitter, as with every other third-party service, uses OAuth to handle authentication. OAuth is a standard protocol through which an application or a person can authenticate with one website by using credentials they have on another website. We use this all the time on the internet. For example, we might use an online graphics application such as [draw.io](http://draw.io) or Canva by logging in with a Google account, and then the service can save files to our Google Drive. 

Any application author must register with any sites you seek to use for authentication. Since we wish to allow Twitter users to log in to Notes using Twitter credentials, we have to register our Notes application with Twitter. Twitter then gives us a pair of authentication keys that will validate the Notes application with Twitter. Any application, whether it is a popular site such as Canva, or a new site such as Joe's Ascendant Horoscopes, must be registered with any desired OAuth authentication providers. The application author must then be diligent about keeping the registration active and properly storing the authentication keys.

The authentication keys are like a username/password pair. Anyone who gets a hold of those keys could use the service as if they were you, and potentially wreak havoc on your reputation or business.

Our task in this section is to register a new application with Twitter, fulfilling whatever requirements Twitter has.

To register a new application with Twitter, go to [`developer.twitter.com/en/apps`](https://developer.twitter.com/en/apps). 

As you go through this process, you may be shown the following message:

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/a2a51eab-1678-4207-b7fb-847230ed20fe.png)

Recall that in recent years, concerns began to arise regarding the misuse of third-party authentication, the potential to steal user information, and the negative results that have occurred thanks to user data being stolen from social networks. As a result, social networks have increased scrutiny over developers using their APIs. It is necessary to sign up for a Twitter developer account, which is an easy process that does not cost anything.

As we go through this, realize that the Notes application needs a minimal amount of data. The ethical approach to this is to request only the level of access required for your application, and nothing more.

Once you're registered, you can log in to `developer.twitter.com/apps` and see a dashboard listing the active applications you've registered. At this point, you probably do not have any registered applications. At the top is a button marked *Create an App*. Click on that button to start the process of submitting a request to register a new application.

Every service offering OAuth authentication has an administrative backend similar to `developer.twitter.com/apps`. The purpose is so that certified application developers can administer the registered applications and authorization tokens. Each such service has its own policies for validating that those requesting authorization tokens have a legitimate purpose and will not abuse the service. The authorization token is one of the mechanisms to verify that API requests come from approved applications. Another mechanism is the URL from which API requests are made. 

In the normal case, an application will be deployed to a regular server, and is accessed through a domain name such as `MyNotes.xyz`. In our case, we are developing a test application on our laptop, and do not have a public IP address, nor is there a domain name associated with our laptop. Not all social networks allow interactions from an application on an untrusted computer—such as a developer's laptop—to make API requests; however, Twitter does.

At the time of writing, there are several pieces of information requested by the Twitter sign-up process, listed as follows:

*   **Name**: This is the application name, and it can be anything you like. It would be a good form to use "`Test`" in the name, in case Twitter's staff decide to do some checking.
*   **Description**: Descriptive phrase—and again, it can be anything you like. The description is shown to users during the login process. It's good form to describe this as a test application.

*   **Website**: This would be your desired domain name. Here, the help text helpfully suggests *If you don't have a URL yet, just put a placeholder here but remember to change it later*.
*   **Allow this application to be used to sign in with Twitter**: Check this, as it is what we want.
*   **Callback URL**: This is the URL to return to following successful authentication. Since we don't have a public URL to supply, this is where we specify a value referring to your laptop. It's been found that `http://localhost:3000` works just fine. macOS users have another option because of the `.local` domain name that is automatically assigned to their laptop. 
*   **Tell us how this app will be used**: This statement will be used by Twitter to evaluate your request. For the purpose of this project, explain that it is a sample app from a book. It is best to be clear and honest about your intention.

The sign-up process is painless. However, at several points, Twitter reiterated the sensitivity of the information provided through the Twitter API. The last step before granting approval warned that Twitter prohibits the use of its API for various unethical purposes.

The last thing to notice is the extremely sensitive nature of the authentication keys. It's bad form to check these into a source code repository or otherwise put them in a place where anybody can access the key. We'll tackle this issue in Chapter 14, *Security in Node.js Applications*.

The Twitter developers' site has documentation describing best practices for storing authentication tokens. Visit [`developer.twitter.com/en/docs/basics/authentication/guides/authentication-best-practices`](https://developer.twitter.com/en/docs/basics/authentication/guides/authentication-best-practices).

### Storing authentication tokens

The Twitter recommendation is to store configuration values in a `.env` file. The contents of this file are to somehow become environment variables, which we can then access using `process.env`, as we've done before. Fortunately, there is a third-party Node.js package to do just this, called `dotenv`.

Learn about the `dotenv` package at [`www.npmjs.com/package/dotenv.`](https://www.npmjs.com/package/dotenv)

First, install the package, as follows:

```

文档表示我们应该加载`dotenv`包，然后在应用程序启动阶段非常早的时候调用`dotenv.config()`，并且我们必须在访问任何环境变量之前这样做。然而，仔细阅读文档后，似乎最好将以下代码添加到`app.mjs`中：

```

With this approach, we do not have to explicitly call the `dotenv.config` function. The primary advantage is avoiding issues with referencing environment variables from multiple modules.

The next step is to create a file, `.env`, in the `notes` directory. The syntax of this file is very simple, as shown in the following code block:

```

这正是我们期望的语法，因为它与 shell 脚本的语法相同。在这个文件中，我们需要定义两个变量，`TWITTER_CONSUMER_KEY`和`TWITTER_CONSUMER_SECRET`。我们将在下一节中编写的代码中使用这些变量。由于我们正在将配置值放在`package.json`的`scripts`部分中，因此可以将这些环境变量添加到`.env`中。

下一步是避免将此文件提交到 Git 等源代码控制系统中。为了确保这不会发生，您应该已经在`notes`目录中有一个`.gitignore`文件，并确保其内容类似于以下内容：

```

These values mostly refer to database files we generated in the previous chapter. In the end, we've added the `.env` file, and because of this, Git will not commit this file to the repository.

This means that when deploying the application to a server, you'll have to arrange to add this file to the deployment without it being committed to a source repository. 

With an approved Twitter application, and with our authentication tokens recorded in a configuration file, we can move on to adding the required code to Notes.

## Implementing TwitterStrategy

As with many web applications, we have decided to allow our users to log in using Twitter credentials. The OAuth protocol is widely used for this purpose and is the basis for authentication on one website using credentials maintained by another website.

The application registration process you just followed at `developer.twitter.com` generated for you a pair of API keys: a consumer key, and a consumer secret. These keys are part of the OAuth protocol and will be supplied by any OAuth service you register with, and the keys should be treated with the utmost care. Think of them as the username and password your service uses to access the OAuth-based service (Twitter et al.). The more people who can see these keys, the more likely it becomes that a miscreant can see them and then cause trouble. Anybody with those secrets can access the service API as if they are you.

Let's install the package required to use `TwitterStrategy`, as follows:

```

在`routes/users.mjs`中，让我们开始做一些更改，如下所示：

```

This imports the package, and then makes its `Strategy` variable available as `TwitterStrategy`.

Let's now install the `TwitterStrategy`, as follows:

```

这注册了一个`TwitterStrategy`实例到`passport`，安排在用户注册 Notes 应用程序时调用用户认证服务。当用户成功使用 Twitter 进行身份验证时，将调用此`callback`函数。

如果包含 Twitter 令牌的环境变量没有设置，那么这段代码就不会执行。显然，没有设置 Twitter 认证的密钥是错误的，所以我们通过不执行代码来避免错误。

为了帮助其他代码知道 Twitter 支持是否已启用，我们导出了一个标志变量-`twitterLogin`。

我们专门定义了`usersModel.findOrCreate`函数来处理来自 Twitter 等第三方服务的用户注册。它的任务是查找在配置文件对象中描述的用户，并且如果该用户不存在，则在 Notes 中创建该用户帐户。

`consumerKey`和`consumerSecret`的值是在注册应用程序后由 Twitter 提供的。这些密钥在 OAuth 协议中用作向 Twitter 证明身份的凭证。

`TwitterStrategy`配置中的`callbackURL`设置是 Twitter 的基于 OAuth1 的 API 实现的遗留物。在 OAuth1 中，回调 URL 是作为 OAuth 请求的一部分传递的。由于`TwitterStrategy`使用了 Twitter 的 OAuth1 服务，我们必须在这里提供 URL。我们马上会看到这个 URL 在 Notes 中是如何实现的。

`callbackURL`、`consumerKey`和`consumerSecret`设置都是使用环境变量注入的。之前，我们讨论了不将`consumerKey`和`consumerSecret`的值提交到源代码库是最佳实践，因此我们设置了`dotenv`包和一个`.env`文件来保存这些配置值。在第十章，*将 Node.js 应用程序部署到 Linux 服务器*中，我们将看到这些密钥可以在 Dockerfile 中声明为环境变量。

添加以下路由声明：

```

To start the user logging in with Twitter, we'll send them to this URL. Remember that this URL is really `/users/auth/twitter` and, in the templates, we'll have to use that URL. When this is called, the passport middleware starts the user authentication and registration process using `TwitterStrategy`.

Once the user's browser visits this URL, the OAuth dance begins. It's called a dance because the OAuth protocol involves carefully designed redirects between several websites. Passport sends the browser over to the correct URL at Twitter, where Twitter asks the user whether they agree to authenticate using Twitter, and then Twitter redirects the user back to your callback URL. Along the way, specific tokens are passed back and forth in a very carefully designed dance between websites.

Once the OAuth dance concludes, the browser lands at the URL designated in the following router declaration:

```

这个路由处理回调 URL，并且它对应于之前配置的`callbackURL`设置。根据它是否指示成功注册，Passport 将重定向浏览器到首页或者回到`/users/login`页面。

因为`router`被挂载在`/user`上，所以这个 URL 实际上是`/user/auth/twitter/callback`。因此，在配置`TwitterStrategy`时要使用完整的 URL，并提供给 Twitter 的是`http://localhost:3000/user/auth/twitter/callback`。

在处理回调 URL 的过程中，Passport 将调用之前显示的回调函数。因为我们的回调使用了`usersModel.findOrCreate`函数，如果需要，用户将自动注册。

我们几乎准备好了，但是我们需要在 Notes 的其他地方做一些小的更改。

在`partials/header.hbs`中，对代码进行以下更改：

```

This adds a new button that, when clicked, takes the user to `/users/auth/twitter`, which—of course—kicks off the Twitter authentication process. The button is enabled only if Twitter support is enabled, as determined by the `twitterLogin` variable. This means that the router functions must be modified to pass in this variable.

This button includes a little image we downloaded from the official Twitter brand assets page at [`about.twitter.com/company/brand-assets`](https://about.twitter.com/company/brand-assets). Twitter recommends using these branding assets for a consistent look across all services using Twitter. Download the whole set, and then pick the one you like.

For the URL shown here, the corresponding project directory is named `public/assets/vendor/twitter`. Notice that we force the size to be small enough for the navigation bar.

In `routes/index.mjs`, make the following change:

```

这导入了变量，然后在传递给`res.render`的数据中，我们添加了这个变量。这将确保该值传递到`partials/header.hbs`。

在`routes/notes.mjs`中，我们需要在几个路由函数中进行类似的更改：

```

This is the same change, importing the variable and passing it to `res.render`.

With these changes, we're ready to try logging in with Twitter.

Start the user information server as shown previously, and then start the Notes application server, as shown in the following code block:

```

然后，使用浏览器访问`http://localhost:3000`，如下所示：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/2eaeb209-1f22-424a-ab86-0563fa7474c1.png)

注意新按钮。它看起来差不多，多亏了使用了官方的 Twitter 品牌形象。按钮有点大，所以也许你想咨询一位设计师。显然，如果你要支持数十种认证服务，就需要不同的设计。

在略去 Twitter 令牌环境变量的情况下运行它，Twitter 登录按钮不应该出现。

单击此按钮将浏览器带到`/users/auth/twitter`，这意味着启动 Passport 运行 OAuth 协议交易以进行身份验证。但是，您可能会收到一个错误消息，指出回调 URL 未经此客户端应用程序批准。批准的回调 URL 可以在您的应用程序设置中进行调整。如果是这种情况，就需要在`developer.twitter.com`上调整应用程序配置。错误消息明确表示 Twitter 看到了一个未经批准的 URL。

在应用程序页面上，在 App Details 选项卡上，点击编辑按钮。然后，向下滚动到 Callback URLs 部分，并添加以下条目：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/cbe8f693-9128-44b9-b8f4-928b960c9770.png)

正如它所解释的，此框列出了允许用于 Twitter OAuth 身份验证的 URL。目前，我们正在使用端口`3000`在笔记本电脑上托管应用程序。如果您从其他基本 URL 访问它，例如`http://MacBook-Pro-4.local`，那么除了该基本 URL 外还应该使用它。

一旦正确配置了回调 URL，单击“使用 Twitter 登录”按钮将带您到正常的 Twitter OAuth 身份验证页面。只需点击批准，您将被重定向回 Notes 应用程序。

然后，一旦您使用 Twitter 登录，您将看到类似以下截图：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/0e324c9a-3128-40c1-9d5c-1d90d2682130.png)

我们现在已经登录，并且会注意到我们的 Notes 用户名与我们的 Twitter 用户名相同。您可以浏览应用程序并创建、编辑或删除笔记。实际上，您可以对任何您喜欢的笔记进行操作，甚至是其他人创建的笔记。这是因为我们没有创建任何访问控制或权限系统，因此每个用户都可以完全访问每个笔记。这是一个需要放入待办事项的功能。

通过使用多个浏览器或计算机，您可以同时以不同用户身份登录，每个浏览器一个用户。

您可以通过执行我们之前所做的操作来运行 Notes 应用程序的多个实例，如下所示：

```

Then, in one command window, run the following command:

```

在另一个命令窗口中，运行以下命令：

```

As previously, this starts two instances of the Notes server, each with a different value in the `PORT` environment variable. In this case, each instance will use the same user authentication service. As shown here, you'll be able to visit the two instances at `http://localhost:3000` and `http://localhost:3002`. As before, you'll be able to start and stop the servers as you wish, see the same notes in each, and see that the notes are retained after restarting the server.

Another thing to try is to fiddle with the **session store**. Our session data is being stored in the `sessions` directory. These are just files in the filesystem, and we can take a look with normal tools such as `ls`, as shown in the following code block:

```

这是使用 Twitter 账户登录后。您可以看到 Twitter 账户名称存储在会话数据中。

如果您想要清除会话怎么办？这只是文件系统中的一个文件。删除会话文件会擦除会话，用户的浏览器将被强制注销。

如果用户长时间不活动，会话将超时。`session-file-store`选项之一，`ttl`，控制超时时间，默认为 3,600 秒（一小时）。会话超时后，应用程序将恢复到已注销状态。

在这一部分，我们已经完成了设置支持使用 Twitter 身份验证服务进行登录的完整流程。我们创建了 Twitter 开发者账户，并在 Twitter 的后端创建了一个应用程序。然后，我们实现了与 Twitter 的 OAuth 支持集成所需的工作流程。为了支持这一点，我们集成了存储用户授权信息的服务。

我们的下一个任务非常重要：保持用户密码加密。

# 保持秘密和密码安全

我们已经多次警告过安全处理用户识别信息的重要性。安全处理这些数据的意图是一回事，但实际上这样做非常重要。尽管我们迄今为止使用了一些良好的做法，但就目前而言，Notes 应用程序无法经受任何安全审计，原因如下：

+   用户密码以明文形式保存在数据库中。

+   Twitter 等的身份验证令牌以明文形式保存。

+   身份验证服务 API 密钥不是加密安全的任何东西；它只是一个明文的**通用唯一标识符**（**UUID**）。

如果您不认识短语*明文*，它只是表示未加密。任何人都可以阅读用户密码或身份验证令牌的文本。最好将两者都加密以避免信息泄漏。

请记住这个问题，因为我们将在第十四章中重新讨论这些以及其他安全问题。

在我们离开这一章之前，让我们解决其中的第一个问题：以明文形式存储密码。我们之前已经提到用户信息安全非常重要。因此，我们应该从一开始就注意到这一点。

`bcrypt` Node.js 包使得安全存储密码变得容易。有了它，我们可以立即加密密码，永远不会存储未加密的密码。

有关`bcrypt`文档，请参阅[`www.npmjs.com/package/bcrypt`](https://www.npmjs.com/package/bcrypt)。

在`notes`和`users`目录中安装`bcrypt`，执行以下命令：

```

The `bcrypt` documentation says that the correct version of this package must be used precisely for the Node.js version in use. Therefore, you should adjust the version number appropriately to the Node.js version you are using.

The strategy of storing an encrypted password dates back to the earliest days of Unix. The creators of the Unix operating system devised a means for storing an encrypted value in `/etc/passwd`, which was thought sufficiently safe that the password file could be left readable to the entire world.

Let's start with the user information service.

## Adding password encryption to the user information service

Because of our command-line tool, we can easily test end-to-end password encryption. After verifying that it works, we can implement encryption in the Notes application.

In `cli.mjs`, add the following code near the top:

```

这引入了`bcrypt`包，然后我们配置了一个常量，该常量控制解密密码所需的 CPU 时间。`bcrypt`文档指向了一篇讨论为什么`bcrypt`算法非常适合存储加密密码的博客文章。论点归结为解密所需的 CPU 时间。针对密码数据库的暴力攻击更加困难，因此如果使用强加密加密密码，测试所有密码组合所需的 CPU 时间更长，因此成功的可能性更小。

我们分配给`saltRounds`的值决定了 CPU 时间的要求。文档进一步解释了这一点。

接下来，添加以下函数：

```

This takes a plain text password and runs it through the encryption algorithm. What's returned is the hash for the password.

Next, in the commands for `add`, `find-or-create`*,* and `update`, we make this same change, as follows:

```

也就是说，在每个地方，我们将回调函数设置为异步函数，以便我们可以使用`await`。然后，我们调用`hashpass`函数来加密密码。

这样，我们立即加密密码，并且用户信息服务器将存储加密密码。

因此，在`user-server.mjs`中，`password-check`处理程序必须重写以适应检查加密密码。

在`user-server.mjs`的顶部，添加以下导入：

```

Of course, we need to bring in the module here to use its decryption function. This module will no longer store a plain text password, but instead, it will now store encrypted passwords. Therefore, it does not need to generate encrypted passwords, but the `bcrypt` package also has a function to compare a plain text password against the encrypted one in the database, which we will use.

Next, scroll down to the `password-check` handler and modify it, like so:

```

`bcrypt.compare`函数比较明文密码，这些密码将作为`req.params.password`到达，与我们存储的加密密码进行比较。为了处理加密，我们需要重构检查，但我们正在测试相同的三个条件。更重要的是，对于这些条件返回相同的对象。

要测试它，像之前一样启动用户信息服务器，如下所示：

```

In another window, we can create a new user, as follows:

```

我们之前已经完成了这两个步骤。不同之处在于我们接下来要做什么。

让我们检查数据库，看看存储了什么，如下所示：

```

Indeed, the password field no longer has a plain text password, but what is—surely—encrypted text.

Next, we should check that the `password-check` command behaves as expected: 

```

我们之前进行了相同的测试，但这次是针对加密密码。

我们已经验证了对密码进行 REST 调用将起作用。我们的下一步是在 Notes 应用程序中实现相同的更改。

## 在 Notes 应用程序中实现加密密码支持

由于我们已经证明了如何实现加密密码检查，我们所需要做的就是在 Notes 服务器中复制一些代码。

在`users-superagent.mjs`中，添加以下代码到顶部：

```

As before, this imports the `bcrypt` package and configures the complexity that will be used, and we have the same encryption function because we will use it from multiple places.

Next, we must change the functions that interface with the backend server, as follows:

```

在适当的地方，我们必须加密密码。不需要其他更改。

因为`password-check`后端执行相同的检查，返回相同的对象，所以前端代码不需要更改。

为了测试，启动用户信息服务器和 Notes 服务器。然后，使用应用程序检查使用基于 Twitter 的用户和本地用户的登录和退出。

我们已经学会了如何使用加密来安全存储用户密码。如果有人窃取了我们的用户数据库，由于这里的选择，破解密码将需要更长的时间。

我们几乎完成了本章。剩下的任务只是简单地回顾我们创建的应用程序架构。

# 运行 Notes 应用程序堆栈

您是否注意到之前我们说要运行 Notes 应用程序堆栈？现在是时候向营销团队解释这个短语的含义了。他们可能希望在营销宣传册或网站上放置架构图。对于像我们这样的开发人员来说，退一步并绘制我们已经创建或计划创建的图片也是有用的。

以下是工程师可能绘制的图表，以展示给营销团队系统设计（当然，营销团队将聘请图形艺术家对其进行整理）：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/56c15d1d-4fe7-45a8-8e6d-5410f048234e.png)

在上图中标有“Notes 应用程序”的方框是由模板和路由器模块实现的面向公众的代码。按照当前配置，它可以在我们的笔记本电脑上的端口`3000`上可见。它可以使用多个数据存储服务之一。它通过端口`5858`（或前图所示的端口`3333`）与“用户身份验证服务”后端通信。

在第十章中，*将 Node.js 应用程序部署到 Linux 服务器*，当我们学习如何在真实服务器上部署时，我们将扩展这个图片。

# 总结

在本章中，您涵盖了很多内容，不仅涉及 Express 应用程序中的用户身份验证，还涉及微服务开发。

具体来说，您涵盖了 Express 中的会话管理，使用 Passport 进行用户身份验证（包括 Twitter/OAuth），使用路由器中间件限制访问，使用 Restify 创建 REST 服务，以及何时创建微服务。我们甚至使用了加密算法来确保我们只存储加密密码。

了解如何处理登录/注销，特别是来自第三方服务的 OAuth 登录，对于 Web 应用程序开发人员来说是一项必不可少的技能。现在您已经学会了这一点，您将能够为自己的应用程序做同样的事情。

在下一章中，我们将通过半实时通信将 Notes 应用程序提升到一个新水平。为此，我们将编写一些浏览器端 JavaScript，并探索 Socket.io 包如何让我们在用户之间发送消息。


使用 Socket.IO 进行动态客户端/服务器交互

Web 的原始设计模型类似于 20 世纪 70 年代主机的工作方式。旧式的哑终端，如 IBM 3270，和 Web 浏览器都遵循请求-响应范式。用户发送请求，远程计算机发送响应。这种请求-响应范式在 Node.js HTTP 服务器 API 中是明显的，如下面的代码所示：

```

The paradigm couldn't be more explicit than this. The `request` and the `response` are right there.

It wasn't until JavaScript improved that we had a quite different paradigm. The new paradigm is interactive communication driven by browser-side JavaScript. This change in the web application model is called, by some, the real-time web. In some cases, websites keep an open connection to the web browser, send notifications, or update the page as it changes.

For some deep background on this, read about the Comet application architecture introduced by Alex Russell in his blog in 2006 ([`infrequently.org/2006/03/comet-low-latency-data-for-the-browser/`](http://infrequently.org/2006/03/comet-low-latency-data-for-the-browser/)). That blog post called for a platform very similar to Node.js, years before Node.js existed.

In this chapter, we'll explore interactive dynamically updated content, as well as inter-user messaging, in the Notes application. To do this, we'll lean on the Socket.IO library ([`socket.io/`](http://socket.io/)). This library simplifies two-way communication between the browser and server and can support a variety of protocols with fallback to old-school web browsers. It keeps a connection open continuously between browser and server, and it follows the `EventEmitter` model, allowing us to send events back and forth.

We'll be covering the following topics:

*   An introduction to the Socket.IO library
*   Integrating Socket.IO with an Express application, and with Passport
*   Real-time communications in modern web browsers
*   Using Socket.IO events:
    *   To update application content as it changes
    *   To send messages between users
*   User experience for real-time communication
*   Using Modal windows to support a user experience that eliminates page reloads

These sorts of techniques are widely used in many kinds of websites. This includes online chat with support personnel, dynamically updated pricing on auction sites, and dynamically updated social network sites.

To get started, let's talk about what Socket.IO is and what it does.

# 第十二章：Introducing Socket.IO

The aim of Socket.IO is to make real-time apps possible in every browser and mobile device*. *It supports several transport protocols, choosing the best one for the specific browser.

Look up the technical definition for the phrase *real-time* and you'll see the real-time web is not truly real-time. The actual meaning of *real-time* involves software with strict time boundaries that must respond to events within a specified time constraint. It is typically used in embedded systems to respond to button presses, for applications as diverse as junk food dispensers and medical devices in intensive care units. Eat too much junk food and you could end up in intensive care, and you'll be served by real-time software in both cases. Try and remember the distinction between different meanings for this phrase.

The proponents of the so-called real-time web should be calling it the pseudo-real-time-web, but that's not as catchy a phrase.

What does it mean that Socket.IO uses the best protocol for the specific browser? If you were to implement your application with WebSockets, it would be limited to the modern browsers supporting that protocol. Because Socket.IO falls back on so many alternative protocols (WebSockets, Flash, XHR, and JSONP), it supports a wider range of web browsers.

As the application author, you don't have to worry about the specific protocol Socket.IO uses with a given browser. Instead, you can implement the business logic and the library takes care of the details for you.

The Socket.IO package includes both a server-side package and a client library. After an easy configuration, the two will communicate back and forth over a socket. The API between the server side and client side is very similar. Because a Socket.IO application runs code in both browser and server, in this chapter we will be writing code for both.

The model that Socket.IO provides is similar to the `EventEmitter` object. The programmer uses the `.on` method to listen for events and the `.emit` method to send them. But with Socket.IO, an event is sent not just using its event name, but is targeted to a combination of two spaces maintained by Socket.IO – the *namespace* and the *room*. Further, the events are sent between the browser and the server rather than being limited to the Node.js process.

Information about Socket.IO is available at [`socket.io/`](https://socket.io/).

On the server side, we wrap the HTTP Server object using the Socket.IO library, giving us the Socket.IO Server object. The Server object lets us create two kinds of communication spaces, *namespaces,* and *rooms*. With it we can send messages, using the `emit` method, either globally or into one of those spaces. We can also listen for messages, using the `on` method, either globally or from a namespace or room.

On the client side, we load the library from the Socket.IO server. Then, client code running in the browser opens one or more communication channels to the server, and the client can connect to namespaces or rooms.

This high-level overview should help to understand the following work. Our next step is to integrate Socket.IO into the initialization of the Notes application.

# Initializing Socket.IO with Express

Socket.IO works by wrapping itself around an HTTP Server object. Think back to Chapter 4, *HTTP Servers and Clients*, where we wrote a module that hooked into HTTP Server methods so that we could spy on HTTP transactions. The HTTP Sniffer attaches a listener to every HTTP event to print out the events. But what if you used that idea to do real work? Socket.IO uses a similar concept, listening to HTTP requests and responding to specific ones by using the Socket.IO protocol to communicate with client code in the browser.

To get started, let's first make a duplicate of the code from the previous chapter. If you created a directory named `chap08` for that code, create a new directory named `chap09` and copy the source tree there.

We won't make changes to the user authentication microservice, but we will use it for user authentication, of course.

In the Notes source directory, install these new modules:

```

我们将在一些实时交互中结合使用`passport`模块进行用户身份验证，该模块在第八章 *使用微服务对用户进行身份验证*中使用。

在`app.mjs`的开头，将此添加到`import`语句中：

```

This code brings in the required modules. The `socket.io` package supplies the core event-passing service. The `passport.socketio` module integrates Socket.IO with PassportJS-based user authentication. We will be reorganizing `app.mjs` so that session management will be shared between Socket.IO, Express, and Passport. 

The first change is to move the declaration of some session-related values to the top of the module, as we've done here:

```

这样做的是创建一对全局范围的变量来保存与会话配置相关的对象。在设置 Express 会话支持时，我们一直在使用这些值作为常量。现在我们需要将这些值与 Socket.IO 和 Express 会话管理器共享。当我们初始化 Express 和 Socket.IO 会话处理程序时，有一个初始化对象接受初始化参数。在每个对象中，我们将传入相同的值作为`secret`和`sessionStore`字段，以确保它们保持一致。

下一个更改是将与设置服务器对象相关的一些代码从`app.mjs`的底部移到靠近顶部，如下所示：

```

In addition to moving some code from the bottom of `app.mjs`, we've added the initialization for Socket.IO. This is where the Socket.IO library wraps itself around the HTTP server object. Additionally, we're integrating it with the Passport library so that Socket.IO knows which sessions are authenticated.

The creation of the `app` and `server` objects is the same as before. All that's changed is the location in `app.mjs` where that occurred. What's new is the `io` object, which is our entry point into the Socket.IO API, and it is used for all Socket.IO operations. This precise object must be made available to other modules wishing to use Socket.IO operations since this object was created by wrapping the HTTP server object. Hence, the `io` object is exported so that other modules can import it.

By invoking `socketio(server)`, we have given Socket.IO access to the HTTP server. It listens for incoming requests on the URLs through which Socket.IO does its work. That's invisible to us, and we don't have to think about what's happening under the covers.

According to the Socket.IO internals, it looks like Socket.IO uses the `/socket.io` URL. That means our applications must avoid using this URL. See [`socket.io/docs/internals/`](https://socket.io/docs/internals/).

The `io.use` function installs functions in Socket.IO that are similar to Express middleware, which the Socket.IO documentation even calls middleware. In this case, the middleware function is returned by calling `passportSocketIO.authorize`, and is how we integrate Passport authentication into Socket.IO.

Because we are sharing session management between Express and Socket.IO, we must make the following change:

```

这与我们在第八章 *使用微服务对用户进行身份验证*中添加的 Express 会话支持的配置相同，但修改为使用我们之前设置的配置变量。这样做，Express 和 Socket.IO 会话处理都是从相同的信息集中管理的。

我们已经完成了在 Express 应用程序中设置 Socket.IO 的基本设置。首先，我们将 Socket.IO 库连接到 HTTP 服务器，以便它可以处理 Socket.IO 服务的请求。然后我们将其与 Passport 会话管理集成。

现在让我们学习如何使用 Socket.IO 在 Notes 中添加实时更新。

# Notes 主页的实时更新

我们正在努力实现的目标是，当笔记被编辑、删除或创建时，Notes 主页会自动更新笔记列表。到目前为止，我们已经重构了应用程序启动，以便在 Notes 应用程序中初始化 Socket.IO。但是行为还没有改变。

我们将在创建、更新或删除笔记时发送事件。Notes 应用程序的任何感兴趣的部分都可以监听这些事件并做出适当的反应。例如，Notes 主页路由模块可以监听事件，然后向浏览器发送更新。Web 浏览器中的代码将监听来自服务器的事件，并在响应时重新编写主页。同样，当笔记被修改时，监听器可以向 Web 浏览器发送包含新笔记内容的消息，或者如果笔记被删除，监听器可以发送消息，以便 Web 浏览器重定向到主页。

这些更改是必需的：

+   重构 Notes Store 实现以发送创建、更新和删除事件

+   重构模板以支持每个页面上的 Bootstrap 和自定义 Socket.IO 客户端

+   重构主页和笔记查看路由模块，以侦听 Socket.IO 事件并向浏览器发送更新

我们将在接下来的几节中处理这个问题，所以让我们开始吧。

## 重构 NotesStore 类以发出事件

为了在笔记更改、删除或创建时自动更新用户界面，`NotesStore`必须发送事件以通知感兴趣的各方这些更改。我们将使用我们的老朋友`EventEmitter`类来管理必须发送的事件的监听器。

请记住，我们创建了一个名为`AbstractNotesStore`的类，每个存储模块都包含`AbstractNotesStore`的子类。因此，我们可以在`AbstractNotesStore`中添加监听器支持，使其自动可用于实现。

在`models/Notes.mjs`中，进行以下更改：

```

We imported the `EventEmitter` class, made `AbstractNotesStore` a subclass of `EventEmitter`, and then added some methods to emit events. As a result, every `NotesStore` implementation now has an `on` and `emit` method, plus these three helper methods.

This is only the first step since nothing is emitting any events. We have to rewrite the create, update, and destroy methods in `NotesStore` implementations to call these methods so the events are emitted. 

In the interest of space, we'll show the modifications to one of the `NotesStore` implementations, and leave the rest as an exercise for you.

Modify these functions in `models/notes-sequelize.mjs` as shown in the following code:

```

这些更改并未改变这些方法的原始合同，因为它们仍然创建、更新和销毁笔记。其他`NotesStore`实现需要类似的更改。新的是现在这些方法会为可能感兴趣的任何代码发出适当的事件。

还有一个需要处理的任务是初始化，这必须发生在`NotesStore`初始化之后。请记住，设置`NotesStore`是异步的。因此，在`NotesStore`初始化之后调用`.on`函数注册事件监听器必须发生在`NotesStore`初始化之后。

在`routes/index.mjs`和`routes/notes.mjs`中，添加以下函数：

```

This function is meant to be in place of such initialization.

Then, in `app.mjs`, make this change:

```

这导入了两个`init`函数，为它们提供了唯一的名称，然后在`NotesStore`设置完成后调用它们。目前，这两个函数什么也不做，但很快会改变。重要的是这两个`init`函数将在`NotesStore`完全初始化后被调用。

我们的`NotesStore`在创建、更新或销毁笔记时发送事件。现在让我们使用这些事件适当地更新用户界面。

## Notes 主页的实时更改

Notes 模型现在在创建、更新或销毁笔记时发送事件。为了让这些事件有用，它们必须显示给我们的用户。使事件对我们的用户可见意味着应用程序的控制器和视图部分必须消耗这些事件。

在`routes/index.mjs`的顶部，将其添加到导入列表中：

```

Remember that this is the initialized Socket.IO object we use to send messages to and from connected browsers. We will use it to send messages to the Notes home page.

Then refactor the `router` function:

```

这将原本是`router`函数主体的内容提取到一个单独的函数中。我们不仅需要在主页的`router`函数中使用这个函数，还需要在为主页发出 Socket.IO 消息时使用它。

我们确实改变了返回值。最初，它包含一个 Note 对象数组，现在它包含一个包含`key`和`title`数据的匿名对象数组。我们之所以这样做，是因为将 Note 对象数组提供给 Socket.IO 会导致发送到浏览器的是一组空对象，而发送匿名对象则可以正常工作。

然后，在底部添加这个：

```

The primary purpose of this section is to listen to the create/update/destroy events, so we can update the browser. For each, the current list of Notes is gathered, then sent to the browser.

As we said, the Socket.IO package uses a model similar to the `EventEmitter` class. The `emit` method sends an event, and the policy of event names and event data is the same as with `EventEmitter`.

Calling `io.of('/namespace')` creates a `Namespace` object for the named namespace. Namespaces are named in a pattern that looks like a pathname in Unix-like filesystems.

Calling `io.of('/namespace').on('connect'...)` has the effect of letting server-side code know when a browser connects to the named namespace. In this case, we are using the `/home` namespace for the Notes home page. This has the side-effect of keeping the namespace active after it is created. Remember that `init` is called during the initialization of the server. Therefore, we will have created the `/home` namespace long before any web browser tries to access that namespace by visiting the Notes application home page.

Calling `io.emit(...)` sends a broadcast message. Broadcast messages are sent to every browser connected to the application server. That can be useful in some situations, but in most situations, we want to avoid sending too many messages. To limit network data consumption, it's best to target each event to the browsers that need the event.

Calling `io.of('/namespace').emit(...)` targets the event to browsers connected to the named namespace. When the client-side code connects to the server, it connects with one or more namespaces. Hence, in this case, we target the `notetitles` event to browsers attached to the `/home` namespace, which we'll see later is the Notes home page.

Calling `io.of('/namespace').to('room')` accesses what Socket.IO calls a `room`. Before a browser receives events in a room, it must *join* the room. Rooms and namespaces are similar, but different, things. We'll use rooms later.

The next task accomplished in the `init` function is to create the event listeners for the `notecreated`, `noteupdate`, and `notedestroy` events. The handler function for each emits a Socket.IO event, `notetitles`, containing the list of note keys and titles.

As Notes are created, updated, and destroyed, we are now sending an event to the home page that is intended to refresh the page to match the change. The home page template, `views/index.hbs`, must be refactored to receive that event and rewrite the page to match.

### Changing the home page and layout templates

Socket.IO runs on both the client and the server, with the two communicating back and forth over the HTTP connection. So far, we've seen the server side of using Socket.IO to send events. The next step is to install a Socket.IO client on the Notes home page.

Generally speaking, every application page is likely to need a different Socket.IO client, since each page has different requirements. This means we must change how JavaScript code is loaded in Notes pages. 

Initially, we simply put JavaScript code required by Bootstrap and FeatherJS at the bottom of `layout.hbs`. That worked because every page required the same set of JavaScript modules, but now we've identified the need for different JavaScript code on each page. Because the custom Socket.IO clients for each page use jQuery for DOM manipulation, they must be loaded after jQuery is loaded. Therefore, we need to change `layout.hbs` to not load the JavaScript. Instead, every template will now be required to load the JavaScript code it needs. We'll supply a shared code snippet for loading the Bootstrap, Popper, jQuery, and FeatherJS libraries but beyond that, each template is responsible for loading any additional required JavaScript.

Create a file, `partials/footerjs.hbs`, containing the following code:

```

这段代码原本位于`views/layout.hbs`的底部，这是我们刚提到的共享代码片段。这意味着它将用于每个页面模板，并在自定义 JavaScript 之后使用。

现在我们需要修改`views/layout.hbs`如下：

```

That is, we'll leave `layout.hbs` pretty much as it was, except for removing the JavaScript tags from the bottom. Those tags are now in `footerjs.hbs`. 

We'll now need to modify every template (`error.hbs`, `index.hbs`, `login.hbs`, `notedestroy.hbs`, `noteedit.hbs`, and `noteview.hbs`) to, at the minimum, load the `footerjs` partial.

```

有了这个，每个模板都明确地在页面底部加载了 Bootstrap 和 FeatherJS 的 JavaScript 代码。它们以前是在`layout.hbs`的页面底部加载的。这给我们带来的好处是可以在加载 Bootstrap 和 jQuery 之后加载 Socket.IO 客户端代码。

我们已经更改了每个模板以使用新的加载 JavaScript 的策略。现在让我们来处理主页上的 Socket.IO 客户端。

### 向 Notes 主页添加 Socket.IO 客户端

请记住我们的任务是在主页添加一个 Socket.IO 客户端，以便主页接收有关创建、更新或删除笔记的通知。

在`views/index.hbs`中，在`footerjs`部分之后添加以下内容：

```

This is what we meant when we said that each page will have its own Socket.IO client implementation. This is the client for the home page, but the client for the Notes view page will be different. This Socket.IO client connects to the `/home` namespace, then for `notetitles` events, it redraws the list of Notes on the home page.

The first `<script>` tag is where we load the Socket.IO client library, from `/socket.io/socket.io.js`. You'll notice that we never set up any Express route to handle the `/socket.io` URL. Instead, the Socket.IO library did that for us. Remember that the Socket.IO library handles every request starting with `/socket.io`, and this is one of such request it handles. The second `<script>` tag is where the page-specific client code lives.

Having client code within a `$(document).ready(function() { .. })` block is typical when using jQuery. This, as the code implies, waits until the web page is fully loaded, and then calls the supplied function. That way, our client code is not only held within a private namespace; it executes only when the page is fully set up.

On the client side, calling `io()` or `io('/namespace')` creates a `socket` object. This object is what's used to send messages to the server or to receive messages from the server.

In this case, the client connects a `socket` object to the `/home` namespace, which is the only namespace defined so far. We then listen for the `notetitles` events, which is what's being sent from the server. Upon receiving that event, some jQuery DOM manipulation erases the current list of Notes and renders a new list on the screen. The same markup is used in both places.

Additionally, for this script to function, this change is required elsewhere in the template:

```

您会注意到脚本中引用了`$("#notetitles")`来清除现有的笔记标题列表，然后添加一个新列表。显然，这需要在这个`<div>`上有一个`id="notetitles"`属性。

我们在`routes/index.mjs`中的代码监听了来自 Notes 模型的各种事件，并相应地向浏览器发送了一个`notetitles`事件。浏览器代码获取笔记信息列表并重新绘制屏幕。

您可能会注意到我们的浏览器端 JavaScript 没有使用 ES-2015/2016/2017 功能。当然，如果我们这样做，代码会更清晰。我们如何知道我们的访问者是否使用足够现代的浏览器来支持这些语言特性呢？我们可以使用 Babel 将 ES-2015/2016/2017 代码转译为能够在任何浏览器上运行的 ES5 代码。然而，在浏览器中仍然编写 ES5 代码是一种务实的折衷。

### 使用实时主页更新运行 Notes

我们现在已经实现了足够的功能来运行应用程序并看到一些实时操作。

像之前一样，在一个窗口中启动用户信息微服务：

```

Then, in another window, start the Notes application:

```

然后，在浏览器窗口中，转到`http://localhost:3000`并登录 Notes 应用程序。要查看实时效果，请打开多个浏览器窗口。如果您可以从多台计算机上使用 Notes，则也可以这样做。

在一个浏览器窗口中，创建和删除便签，同时保留其他浏览器窗口查看主页。创建一个便签，它应该立即显示在其他浏览器窗口的主页上。删除一个便签，它也应该立即消失。

您可能要尝试的一个场景需要三个浏览器窗口。在一个窗口中，创建一个新的便签，然后保留显示新创建的便签的浏览器窗口。在另一个窗口中，显示 Notes 主页。在第三个窗口中，显示新创建的便签。现在，删除这个新创建的便签。其中两个窗口被正确更新，现在显示主页。第三个窗口，我们只是在查看便签，仍然显示该便签，即使它已经不存在。

我们很快就会解决这个问题，但首先，我们需要讨论如何调试您的 Socket.IO 客户端代码。

## 关于在 Socket.IO 代码中启用调试跟踪的说明

检查 Socket.IO 正在做什么是有用的，如果您遇到问题。幸运的是，Socket.IO 包使用与 Express 相同的 Debug 包，我们可以通过设置`DEBUG`环境变量来打开调试跟踪。它甚至在客户端使用相同的语法`localStorage.debug`变量，我们也可以在浏览器中启用调试跟踪。

在服务器端，这是一个有用的`DEBUG`环境变量设置：

```

This enables debug tracing for the Notes application and the Socket.IO package.

Enabling this in a browser is a little different since there are no environment variables. Simply open up the JavaScript console in your browser and enter this command:

```

立即，您将开始看到来自 Socket.IO 的不断交谈的消息。您将了解到的一件事是，即使应用程序处于空闲状态，Socket.IO 也在来回通信。

还有其他几个要使用的`DEBUG`字符串。例如，Socket.IO 依赖于 Engine.IO 包来进行传输。如果您想要对该包进行调试跟踪，将`engine*`添加到`DEBUG`字符串中。在测试本章节时，所示的字符串最有帮助。

现在我们已经了解了调试跟踪，我们可以处理将`/notes/view`页面更改为对正在查看的便签做出反应的问题。

## 查看便签时的实时操作

现在我们可以看到 Notes 应用程序的一部分实时更改，这很酷。让我们转到`/notes/view`页面看看我们能做些什么。我想到的是这个功能：

+   如果其他人编辑便签，则更新便签。

+   如果其他人删除了便签，将查看者重定向到主页。

+   允许用户在便签上留下评论。

对于前两个功能，我们可以依赖于来自 Notes 模型的现有事件。因此，我们可以在本节中实现这两个功能。第三个功能将需要一个消息传递子系统，因此我们将在本章的后面进行讨论。

为了实现这一点，我们可以为每个便签创建一个 Socket.IO 命名空间，例如`/notes/${notekey}`。然后，当浏览器查看便签时，添加到`noteview.hbs`模板的客户端代码将连接到该命名空间。然而，这引发了如何创建这些命名空间的问题。相反，所选的实现是有一个命名空间`/notes`，并为每个便签创建一个房间。

在`routes/notes.mjs`中，确保像这样导入`io`对象：

```

This, of course, makes the `io` object available to code in this module. We're also importing a function from `index.mjs` that is not currently exported. We will need to cause the home page to be updated, and therefore in `index.mjs`, make this change:

```

这只是添加了`export`关键字，以便我们可以从其他地方访问该函数。

然后，将`init`函数更改为以下内容：

```

First, we handle `connect` events on the `/notes` namespace. In the handler, we're looking for a `query` object containing the `key` for a Note. Therefore, in the client code, when calling `io('/notes')` to connect with the server, we'll have to arrange to send that `key` value. It's easy to do, and we'll learn how in a little while.

Calling `socket.join(roomName)` does what is suggested—it causes this connection to join the named room. Therefore, this connection will be addressed as being in the `/notes` namespace, and in a room whose name is the `key` for a given Note.

The next thing is to add listeners for the `noteupdated` and `notedestroyed` messages. In both, we are using this pattern:

```

这就是我们如何使用 Socket.IO 向连接到给定命名空间和房间的任何浏览器发送消息。

对于`noteupdated`，我们只需发送新的笔记数据。我们再次不得不将笔记对象转换为匿名 JavaScript 对象，因为否则浏览器中会收到一个空对象。客户端代码将不得不使用 jQuery 操作来更新页面，我们很快就会看到。

对于`notedestroyed`，我们只需发送`key`。由于客户端代码将通过将浏览器重定向到主页来做出响应，我们根本不需要发送任何内容。

在这两者中，我们还调用`emitNoteTitles`来确保主页在被查看时得到更新。

### 为实时操作更改笔记视图模板

就像我们在主页模板中所做的那样，这些事件中包含的数据必须对用户可见。我们不仅需要向模板`views/noteview.hbs`中添加客户端代码；我们还需要对模板进行一些小的更改：

```

In this section of the template, we add a pair of IDs to two elements. This enables the JavaScript code to target the correct elements.

Add this client code to `noteview.hbs`:

```

在此脚本中，我们首先连接到`/notes`命名空间，然后为`noteupdated`和`notedestroyed`事件创建监听器。

连接到`/notes`命名空间时，我们传递了一个额外的参数。这个函数的可选第二个参数是一个选项对象，在这种情况下，我们传递了`query`选项。`query`对象在形式上与`URL`类的`query`对象相同。这意味着命名空间就像是一个 URL，比如`/notes?key=${notekey}`。根据 Socket.IO 文档，我们可以传递一个完整的 URL，如果连接是这样创建的，它也可以工作：

```

While we could set up the URL query string this way, it's cleaner to do it the other way.

We need to call out a technique being used. These code snippets are written in a Handlebars template, and therefore the syntax `{{ expression }}` is executed on the server, with the result of that expression to be substituted into the template. Therefore, the `{{ expression }}` construct accesses server-side data. Specifically, `query: { key: '{{ notekey }}' }` is a data structure on the client side, but the `{{ notekey }}` portion is evaluated on the server. The client side does not see `{{ notekey }}`, it sees the value `notekey` had on the server.

For the `noteupdated` event, we take the new note content and display it on the screen. For this to work, we had to add `id=` attributes to certain HTML elements so we could use jQuery selectors to manipulate the correct elements.

Additionally in `partials/header.hbs`, we needed to make this change as well:

```

我们还需要在页面顶部更新标题，这个`id`属性有助于定位正确的元素。

对于`notedestroyed`事件，我们只需将浏览器窗口重定向回主页。正在查看的笔记已被删除，用户继续查看不再存在的笔记是没有意义的。

### 在查看笔记时运行带有伪实时更新的笔记

此时，您现在可以重新运行笔记应用程序并尝试新的实时更新功能。

到目前为止，您已经多次测试了笔记，并知道该怎么做。首先启动用户认证服务器和笔记应用程序。确保数据库中至少有一条笔记；如果需要，添加一条。然后，打开多个浏览器窗口，一个查看主页，两个查看同一条笔记。在查看笔记的窗口中，编辑笔记进行更改，确保更改标题。文本更改应该在主页和查看笔记的页面上都有变化。

然后删除笔记并观察它从主页消失，而且查看笔记的浏览器窗口现在位于主页上。

在本节中，我们处理了很多事情，现在笔记应用程序具有动态更新功能。为此，我们创建了一个基于事件的通知系统，然后在浏览器和服务器中使用 Socket.IO 来往返通信数据。

我们已经实现了我们设定的大部分目标。通过重构笔记存储实现以发送事件，我们能够向浏览器中的 Socket.IO 客户端发送事件。这反过来又用于自动更新笔记主页和`/notes/view`页面。

剩下的功能是让用户能够在笔记上写评论。在下一节中，我们将通过添加一个全新的数据库表来处理消息。

# 笔记的用户间聊天和评论

这很酷！现在我们在编辑、删除或创建笔记时可以实时更新笔记。现在让我们把它提升到下一个级别，并实现类似于用户之间聊天的功能。

早些时候，我们列举了在`/notes/view`页面上可以使用 Socket.IO 做的三件事。我们已经实现了当笔记更改时的实时更新和当笔记被删除时重定向到主页；剩下的任务是允许用户对笔记进行评论。

我们可以将我们的笔记应用程序概念转变，并将其发展成一个社交网络。在大多数这样的网络中，用户发布东西（笔记、图片、视频等），其他用户对这些东西进行评论。如果做得好，这些基本元素可以发展成一个庞大的人群共享笔记的社区。虽然笔记应用程序有点像一个玩具，但它离一个基本的社交网络并不太远。我们现在将要做的评论是朝着这个方向迈出的一小步。

在每个笔记页面上，我们将有一个区域来显示来自笔记用户的消息。每条消息将显示用户名、时间戳和他们的消息。我们还需要一种方法让用户发布消息，并允许用户删除消息。

所有这些操作都将在不刷新屏幕的情况下执行。相反，网页内运行的代码将发送命令到/从服务器，并动态采取行动。通过这样做，我们将学习关于 Bootstrap 模态对话框，以及更多关于发送和接收 Socket.IO 消息的知识。让我们开始吧。

## 存储消息的数据模型

我们需要首先实现一个用于存储消息的数据模型。所需的基本字段是唯一 ID、发送消息的人的用户名、与消息相关的命名空间和房间、消息，最后是消息发送的时间戳。当接收或删除消息时，必须从数据模型中发出事件，以便我们可以在网页上做正确的事情。我们将消息与房间和命名空间组合关联起来，因为在 Socket.IO 中，该组合已被证明是一种很好的方式来定位笔记应用程序中的特定页面。

这个数据模型实现将被写入 Sequelize。如果您喜欢其他存储解决方案，您可以尽管在其他数据存储系统上重新实现相同的 API。

创建一个新文件`models/messages-sequelize.mjs`，其中包含以下内容：

```

This sets up the modules being used and also initializes the `EventEmitter` interface. We're also exporting the `EventEmitter` as `emitter` so other modules can be notified about messages as they're created or deleted.

Now add this code for handling the database connection:

```

`connectDB`的结构与我们在`notes-sequelize.mjs`中所做的类似。我们使用相同的`connectSequlz`函数与相同的数据库连接，并且如果数据库已经连接，我们会立即返回。

通过`SQMessage.init`，我们在数据库中定义了我们的消息模式。我们有一个相当简单且相当自解释的数据库模式。为了发出关于消息的事件，我们使用了`Sequelize`的一个特性，在特定时间调用。

`id`字段不会由调用者提供；相反，它将自动生成。因为它是一个`autoIncrement`字段，每添加一条消息，数据库将为其分配一个新的`id`编号。在 MySQL 中的等效操作是在列定义上的`AUTO_INCREMENT`属性。

`namespace`和`room`字段一起定义了每条消息属于笔记中的哪个页面。请记住，在使用 Socket.IO 发出事件时，我们可以将事件定位到这两个空间中的一个或两个，因此我们将使用这些值将每条消息定位到特定页面。

到目前为止，我们为笔记主页定义了一个命名空间`/home`，为查看单个笔记定义了另一个命名空间`/notes`。理论上，笔记应用程序可以扩展到在其他区域显示消息。例如，`/private-message`命名空间可以用于私人消息。因此，模式被定义为具有`namespace`和`room`字段，以便在将来的笔记应用程序的任何部分中使用消息。

对于我们当前的目的，消息将被存储在`namespace`等于`/home`，`room`等于给定笔记的`key`的情况下。

我们将使用`timestamp`按发送顺序呈现消息。`from`字段是发送者的用户名。

为了发送有关已创建和已销毁消息的通知，让我们尝试一些不同的方法。如果我们遵循之前使用的模式，我们即将创建的函数将具有带有相应消息的`emitter.emit`调用。但 Sequelize 提供了一种不同的方法。

使用`Sequelize`，我们可以创建所谓的钩子方法。钩子也可以被称为**生命周期事件**，它们是我们可以声明的一系列函数。当 Sequelize 管理的对象存在某些触发状态时，将调用钩子方法。在这种情况下，我们的代码需要知道何时创建消息，以及何时删除消息。

钩子声明如选项对象所示。`schema`选项对象中的名为`hooks`的字段定义了钩子函数。对于我们想要使用的每个钩子，添加一个包含钩子函数的适当命名字段。对于我们的需求，我们需要声明`hooks.afterCreate`和`hooks.afterDestroy`。对于每个钩子，我们声明一个函数，该函数接受刚刚创建或销毁的`SQMessage`对象的实例。然后，使用该对象，我们调用`emitter.emit`，使用`newmessage`或`destroymessage`事件名称。

继续添加这个函数：

```

The `sanitizedMessage` function performs the same function as `sanitizedUser`. In both cases, we are receiving a Sequelize object from the database, and we want to return a simple object to the caller. These functions produce that simplified object.

Next, we have several functions to store new messages, retrieve messages, and delete messages. 

The first is this function:

```

当用户发布新评论/消息时将调用此函数。我们将其存储在数据库中，并且钩子发出一个事件，表示消息已创建。

请记住，`id`字段是在存储新消息时自动创建的。因此，在调用`SQMessage.create`时不提供它。

这个函数和下一个函数本来可以包含`emitter.emit`调用来发送`newmessage`或`destroymessage`事件。相反，这些事件是在我们之前创建的钩子函数中发送的。问题是是否将`emitter.emit`放在钩子函数中，还是放在这里。

这里使用的原理是，通过使用钩子，我们可以确保始终发出消息。

然后，添加这个函数：

```

This is to be called when a user requests that a message should be deleted. With Sequelize, we must first find the message and then delete it by calling its `destroy` method.

Add this function:

```

这个函数检索最近的消息，立即使用情况是在渲染`/notes/view`页面时使用。

虽然我们当前的实现是用于查看笔记，但它是通用的，适用于任何 Socket.IO 命名空间和房间。这是为了可能的未来扩展，正如我们之前解释的那样。它找到与给定命名空间和房间组合关联的最近的 20 条消息，然后将一个经过清理的列表返回给调用者。

在`findAll`中，我们指定一个`order`属性。这类似于 SQL 中的`ORDER BY`短语。`order`属性接受一个或多个描述符的数组，声明 Sequelize 应该如何对结果进行排序。在这种情况下，有一个描述符，表示按照时间戳字段降序排序。这将导致最近的消息首先显示。

我们创建了一个简单的模块来存储消息。我们没有实现完整的**创建、读取、更新和删除**（**CRUD**）操作，因为对于这个任务并不需要。我们即将创建的用户界面只允许用户添加新消息、删除现有消息和查看当前消息。

让我们继续创建用户界面。

## 为 Notes 路由器添加消息支持

现在我们可以将消息存储到数据库中，让我们将其集成到 Notes 路由器模块中。

将消息集成到`/notes/view`页面将需要在`notesview.hbs`模板中添加一些新的 HTML 和 JavaScript，并在`routes/notes.mjs`中的`init`函数中添加一些新的 Socket.IO 通信端点。在本节中，让我们处理这些通信端点，然后在下一节中让我们讨论如何在用户界面中设置它。

在`routes/notes.mjs`中，将这个添加到`import`语句中：

```

This imports the functions we just created so we can use them. And we also set up `debug` and `error` functions for tracing.

Add these event handlers to the `init` function in `routes/notes.mjs`:

```

这些接收来自`models/messages-sequelize.mjs`的新消息或已销毁消息的通知，然后将通知转发到浏览器。请记住，消息对象包含命名空间和房间，因此这让我们能够将此通知发送到任何 Socket.IO 通信通道。

为什么我们不直接在`models/messages-sequelize.mjs`中进行 Socket.IO 调用呢？显然，将 Socket.IO 调用放在`messages-sequelize.mjs`中会更有效率，需要更少的代码行，因此减少了错误的机会。但是我们正在保持模型、视图和控制器之间的分离，这是我们在第五章中讨论过的。此外，我们能够自信地预测将来不会有其他用途的消息吗？这种架构允许我们将多个监听器方法连接到这些消息事件，以实现多种目的。

在用户界面中，我们将不得不实现相应的监听器来接收这些消息，然后采取适当的用户界面操作。

在`init`函数中的`connect`监听器中，添加这两个新的事件监听器：

```

This is the existing function to listen for connections from `/notes/view` pages, but with two new Socket.IO event handler functions. Remember that in the existing client code in `notesview.hbs`, it connects to the `/notes` namespace and supplies the note `key` as the room to join. In this section, we build on that by also setting up listeners for `create-message` and `delete-message` events when a note `key` has been supplied.

As the event names imply, the `create-message` event is sent by the client side when there is a new message, and the `delete-message` event is sent to delete a given message. The corresponding data model functions are called to perform those functions.

For the `create-message` event, there is an additional feature being used. This uses what Socket.IO calls an acknowledgment function.

So far, we've used the Socket.IO `emit` method with an event name and a data object. We can also include a `callback` function as an optional third parameter. The receiver of the message will receive the function and can call the function, and any data passed to the function is sent to the `callback` function. The interesting thing is this works across the browser-server boundary.

This means our client code will do this:

```

第三个参数中的函数成为`create-message`事件处理程序函数中的`fn`参数。然后，提供给`fn`调用的任何内容都将作为`result`参数传递到此函数中。不管是浏览器通过连接到服务器提供该函数，还是在服务器上调用该函数，Socket.IO 都会负责将响应数据传输回浏览器代码并在那里调用确认函数。最后要注意的是，我们在错误报告方面有些懒惰。因此，将一个任务放在待办事项中，以改进向用户报告错误。

下一个任务是在浏览器中实现代码，使所有这些对用户可见。

## 更改消息的注释视图模板

我们需要再次深入`views/noteview.hbs`进行更多的更改，以便我们可以查看、创建和删除消息。这一次，我们将添加大量的代码，包括使用 Bootstrap 模态弹出窗口来获取消息，我们刚刚讨论的 Socket.IO 消息，以及 jQuery 操作，使所有内容显示在屏幕上。

我们希望`/notes/view`页面不会导致不必要的页面重新加载。相反，我们希望用户通过弹出窗口收集消息文本来添加评论，然后新消息将被添加到页面上，而不会导致页面重新加载。同样，如果另一个用户向 Note 添加消息，我们希望消息能够在不重新加载页面的情况下显示出来。同样，我们希望删除消息而不会导致页面重新加载，并且希望消息被删除后，其他查看 Note 的用户也不会导致页面重新加载。

当然，这将涉及浏览器和服务器之间来回传递多个 Socket.IO 消息，以及一些 jQuery DOM 操作。我们可以在不重新加载页面的情况下完成这两个操作，这通常会提高用户体验。

让我们首先实现用户界面来创建新消息。

### 在 Note 视图页面上撰写消息

`/notes/view`页面的下一个任务是让用户添加消息。他们将点击一个按钮，弹出窗口让他们输入文本，然后他们将在弹出窗口中点击一个按钮，弹出窗口将被关闭，消息将显示出来。此外，消息将显示给 Note 的其他查看者。

Bootstrap 框架包括对模态窗口的支持。它们与桌面应用程序中的模态对话框具有类似的作用。模态窗口出现在应用程序现有窗口的上方，同时阻止与网页或应用程序其他部分的交互。它们用于向用户提问等目的。典型的交互是点击按钮，然后应用程序弹出一个包含一些 UI 元素的模态窗口，用户与模态交互，然后关闭它。在使用计算机时，您肯定已经与成千上万个模态窗口进行了交互。

让我们首先添加一个按钮，用户将请求添加评论。在当前设计中，笔记文本下方有一排两个按钮。在`views/noteview.hbs`中，让我们添加第三个按钮：

```

This is directly out of the documentation for the Bootstrap Modal component. The `btn-outline-dark` style matches the other buttons in this row, and between the `data-toggle` and the `data-target` attributes, Bootstrap knows which Modal window to pop up.

Let's insert the definition for the matching Modal window in `views/noteview.hbs`:

```

这是直接来自 Bootstrap 模态组件的文档，以及一个简单的表单来收集消息。

请注意，这里有`<div class="modal-dialog">`，在其中有`<div class="model-content">`。这两者一起形成了对话框窗口内显示的内容。内容分为`<div class="modal-header">`用于对话框的顶部行，以及`<div class="modal-body">`用于主要内容。

最外层元素的`id`值，`id="notes-comment-modal"`，与按钮中声明的目标匹配，`data-target="#notes-comment-modal"`。另一个连接是`aria-labelledby`，它与`<h5 class="modal-title">`元素的`id`匹配。

`<form id="submit-comment">`很简单，因为我们不会使用它通过 HTTP 连接提交任何内容到常规 URL。因此，它没有`action`和`method`属性。否则，这是一个正常的日常 Bootstrap`form`，带有`fieldset`和各种表单元素。

下一步是添加客户端 JavaScript 代码使其功能正常。单击按钮时，我们希望运行一些客户端代码，该代码将发送与我们添加到`routes/notes.mjs`匹配的`create-message`事件。

在`views/noteview.hbs`中，我们有一个包含客户端代码的`$(document).ready`部分。在该函数中，添加一个仅在`user`对象存在时存在的部分，如下所示：

```

That is, we want a section of jQuery code that's active only when there is a `user` object, meaning that this Note is being shown to a logged-in user.

Within that section, add this event handler:

```

这与我们刚刚创建的表单中的按钮相匹配。通常在`type="submit"`按钮的事件处理程序中，我们会使用`event.preventDefault`来防止正常结果，即重新加载页面。但在这种情况下不需要。

该函数从表单元素中收集各种值，并发送`create-message`事件。如果我们回顾服务器端代码，`create-message`调用`postMessage`，将消息保存到数据库，然后发送`newmessage`事件，该事件传递到浏览器。

因此，我们将需要一个`newmessage`事件处理程序，我们将在下一节中介绍。与此同时，您应该能够运行 Notes 应用程序，添加一些消息，并查看它们是否已添加到数据库中。

请注意，这有一个第三个参数，一个函数，当调用时会导致模态被关闭，并清除输入的任何消息。这是我们之前提到的确认函数，在服务器上调用，并且 Socket.IO 安排在客户端调用它。

### 在 Note 视图页面上显示任何现有消息

现在我们可以添加消息了，让我们学习如何显示消息。请记住，我们已经定义了 SQMessage 模式，并且我们已经定义了一个函数`recentMessages`来检索最近的消息。

在呈现 Note 页面时，我们有两种可能的方法来显示现有消息。一种选择是当页面最初显示时，发送一个事件请求最近的消息，并在接收到消息后在客户端呈现这些消息。另一种选择是在服务器上呈现消息。我们选择了第二种选择，即服务器端呈现。

在`routes/notes.mjs`中，修改`/view`路由器函数如下：

```

That's simple enough: we retrieve the recent messages, then supply them to the `noteview.hbs` template. When we retrieve the messages, we supply the `/notes` namespace and a room name of the note `key`. It is now up to the template to render the messages.

In the `noteview.hbs` template, just below the *delete*, edit, and *comment* buttons, add this code:

```

如果有一个`messages`对象，这些步骤会遍历数组，并为每个条目设置一个 Bootstrap `card`组件来显示消息。消息显示在`<div id="noteMessages">`中，我们稍后会在 DOM 操作中进行定位。每条消息的标记直接来自 Bootstrap 文档，稍作修改。

在每种情况下，`card`组件都有一个`id`属性，我们可以用它来与数据库中的特定消息关联。`button`组件将用于删除消息，并携带数据属性来标识将要删除的消息。

通过这样，我们可以查看一个笔记，并查看已附加的任何消息。我们没有选择消息的排序，但请记住，在`models/messages-sequelize.mjs`中，数据库查询按照时间顺序相反的顺序排列消息。

无论如何，我们的目标是使消息能够自动添加，而无需重新加载页面。为此，我们需要一个`newmessage`事件的处理程序，这是上一节遗留下来的任务。

在`submitNewComment`按钮的处理程序下面，添加以下内容：

```

This is a handler for the Socket.IO `newmessage` event. What we have done is taken the same markup as is in the template, substituted values into it, and used jQuery to prepend the text to the top of the `noteMessages` area.

Remember that we decided against using any ES6 goodness because a template string would sure be handy in this case. Therefore, we have fallen back on an older technique, the JavaScript `String.replace` method.

There is a common question, how do we replace multiple occurrences of a target string in JavaScript? You'll notice that the target `%id%` appears twice. The best answer is to use `replace(/pattern/g, newText)`; in other words, you pass a regular expression and specify the `g` modifier to make it a global action. To those of us who grew up using `/bin/ed` and for whom `/usr/bin/vi` was a major advance, we're nodding in recognition that this is the JavaScript equivalent to `s/pattern/newText/g`.

With this event handler, the message will now appear automatically when it is added by the user. Further, for another window simply viewing the Note the new message will appear automatically.

Because we use the jQuery `prepend` method, the message appears at the top. If you want it to appear at the bottom, then use `append`. And in `models/messages-sequelize.mjs`, you can remove the `DESC` attribute in `recentMessages` to change the ordering.

The last thing to notice is the markup includes a button with the `id="message-del-button"`. This button is meant to be used to delete a message, and in the next section, we'll implement that feature.

### Deleting messages on the Notes view page

To make the `message-del-button` button active, we need to listen to click events on the button. 

Below the `newmessage` event handler, add this button click handler:

```

`socket`对象已经存在，并且是与此笔记的 Socket.IO 连接。我们向房间发送一个`delete-message`事件，其中包含按钮上存储的数据属性的值。

正如我们已经看到的，在服务器上，`delete-message`事件调用`destroyMessage`函数。该函数从数据库中删除消息，并发出一个`destroymessage`事件。`routes/notes.mjs`中接收到该事件，并将消息转发到浏览器。因此，我们需要在浏览器中添加一个事件监听器来接收`destroymessage`事件：

```

回头看看，每条消息显示`card`都有一个符合这里显示模式的`id`参数。因此，jQuery 的`remove`函数负责从显示中删除消息。

### 运行笔记并传递消息

这是很多代码，但现在我们有能力撰写消息，在屏幕上显示它们，并删除它们，而无需重新加载页面。

您可以像我们之前那样运行应用程序，首先在一个命令行窗口中启动用户认证服务器，然后在另一个命令行窗口中启动笔记应用程序：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/8600d6c4-884c-4758-bf91-e57db6f92371.png)

它显示了笔记上的任何现有消息。

输入消息时，模态框看起来像这样：

![](https://github.com/OpenDocCN/freelearn-node-zh/raw/master/docs/node-webdev-5e/img/332a268c-23b4-440f-aa4c-b3084db30df7.png)

尝试在多个浏览器窗口中查看相同的笔记或不同的笔记。这样，您可以验证笔记只显示在相应的笔记窗口上。

# 总结

在本章中，我们走了很长的路，但也许 Facebook 不必担心我们将笔记应用程序转换为社交网络的初步尝试。尽管如此，我们为应用程序添加了一些有趣的新功能，这使我们有机会探索一些真正酷的伪实时通信技术，用于浏览器会话之间的交流。

我们了解了如何使用 Socket.IO 进行伪实时的网络体验。正如我们所学到的，它是一个用于服务器端代码和在浏览器中运行的客户端代码之间动态交互的框架。它遵循一个事件驱动模型，用于在两者之间发送事件。我们的代码使用这个框架，既用于向浏览器发送服务器上发生的事件的通知，也用于希望编写评论的用户。

我们了解了从服务器端代码的一个部分发送到另一个部分的事件的价值。这使我们能够根据服务器上发生的更改进行客户端更新。这使用了`EventEmitter`类和监听器方法，将事件和数据传递到浏览器。

在浏览器中，我们使用 jQuery DOM 操作来响应这些动态发送的消息来改变用户界面。通过使用 Socket.IO 和正常的 DOM 操作，我们能够刷新页面内容，同时避免重新加载页面。

我们还学习了关于模态窗口，利用这种技术来创建评论。当然，还有很多其他事情可以做，比如不同的体验来创建、删除或编辑笔记。

为了支持所有这些，我们添加了另一种数据，*消息*，以及一个由新的 Sequelize 模式管理的相应数据库表。它用于表示我们的用户可以在笔记上发表的评论，但也足够通用，可以用于其他用途。

正如我们所看到的，Socket.IO 为我们提供了丰富的事件基础，可以在服务器和客户端之间传递事件，为用户构建多用户、多通道的通信体验。

在下一章中，我们将探讨 Node.js 应用程序在真实服务器上的部署。在我们的笔记本上运行代码很酷，但要取得成功，应用程序需要得到适当的部署。
