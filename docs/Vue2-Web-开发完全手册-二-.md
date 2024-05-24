# Vue2 Web 开发完全手册（二）

> 原文：[`zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070`](https://zh.annas-archive.org/md5/E8B4B21F7ACD89D5DD2A27CD73B2E070)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Dropbox API 获取文件列表

在接下来的几章中，我们将构建一个基于 Vue 的 Dropbox 浏览器。这个应用程序将使用你的 Dropbox API 密钥，允许你浏览文件夹并下载文件。你将学习如何在 Vue 应用程序中与 API 进行交互，了解 Vue 的生命周期钩子，包括`created()`方法，最后我们将介绍一个名为`Vuex`的库来处理应用程序的缓存和状态。该应用程序将具有可共享的 URL，并通过`#`URL 参数检索文件夹的内容。

如果你想让用户访问你的 Dropbox 内容而不提供用户名和密码，这种应用程序将非常有用。但要注意，一个精通技术的用户可能会在代码中找到你的 API 密钥并滥用它，所以不要将这段代码发布到互联网上。

本章将涵盖以下内容：

+   加载和查询 Dropbox API

+   列出你的 Dropbox 账户中的目录和文件

+   为你的应用程序添加加载状态

+   使用 Vue 动画

在接下来的几章中，你将需要一个 Dropbox 账户。如果你没有账户，请注册并添加一些虚拟文件和文件夹。Dropbox 的内容并不重要，但有文件夹可以帮助你理解代码。

# 开始加载库

为你的应用程序创建一个新的 HTML 页面运行。创建一个网页所需的 HTML 结构，并包含你的应用程序视图包装器：

```js
      <!DOCTYPE html>
      <html>
      <head>
        <title>Dropbox App</title>
      </head>
      <body>  
 <div id="app">
 </div>  
      </body>
      </html>
```

这里称之为`#app`，但你可以随意命名 - 只需记得更新 JavaScript。

由于我们的应用程序代码将变得相当庞大，所以创建一个单独的 JavaScript 文件，并将其包含在文档底部。你还需要包含 Vue 和 Dropbox API SDK。

与之前一样，你可以引用远程文件或下载库文件的本地副本。出于速度和兼容性的原因，下载一个本地副本。在 HTML 文件的底部包含你的三个 JavaScript 文件：

```js
      <script src="js/vue.js"></script>
      <script src="js/dropbox.js"></script>
      <script src="js/app.js"></script>
```

创建你的`app.js`并初始化一个新的 Vue 实例，使用`el`标签将实例挂载到视图中的 ID 上。

```js
      new Vue({
          el: '#app'
      });
```

# 创建一个 Dropbox 应用程序并初始化 SDK

在与 Vue 实例交互之前，我们需要通过 SDK 连接到 Dropbox API。这是通过 Dropbox 自动生成的 API 密钥来完成的，用于跟踪连接到你的账户的内容和位置，Dropbox 要求你创建一个自定义的 Dropbox 应用程序。

前往 Dropbox 开发者区域并选择创建你的应用。选择 Dropbox API 并选择一个受限文件夹或完全访问权限。这取决于你的需求，但是为了测试，选择完全访问权限。给你的应用取一个名字并点击创建应用按钮。

为你的应用生成一个访问令牌。要这样做，在查看应用详情页面时，点击“生成访问令牌”下的“生成”按钮。这将给你一个由数字和字母组成的长字符串 - 将其复制并粘贴到你的编辑器中，并将其作为一个变量存储在你的 JavaScript 的顶部。在本书中，API 密钥将被称为`XXXX`：

```js
      /**
       * API Access Token
       */
      let accessToken = 'XXXX';
```

现在我们有了 API 密钥，我们可以访问我们 Dropbox 中的文件和文件夹。初始化 API 并将你的`accessToken`变量传递给 Dropbox API 的`accessToken`属性：

```js
      /**
      * Dropbox Client
      * @type {Dropbox}
      */
      const dbx = new Dropbox({
        accessToken: accessToken
      });
```

现在我们可以通过`dbx`变量访问 Dropbox。我们可以通过连接并输出根路径的内容来验证我们与 Dropbox 的连接是否正常：

```js
      dbx.filesListFolder({path: ''})
          .then(response => {
            console.log(response.entries);
          })
          .catch(error => {
            console.log(error);
          });
```

这段代码使用了 JavaScript 的 Promise，它是一种在代码中添加操作而不需要回调函数的方法。如果你对 Promise 不熟悉，可以查看 Google 的这篇博文（[`developers.google.com/web/fundamentals/primers/promises`](https://developers.google.com/web/fundamentals/primers/promises)）。

注意第一行，特别是`path`变量。这使我们可以传递一个文件夹路径来列出该目录中的文件和文件夹。例如，如果你的 Dropbox 中有一个名为`images`的文件夹，你可以将参数值更改为`/images`，返回的文件列表将是该目录中的文件和文件夹。

打开你的 JavaScript 控制台并检查输出；你应该得到一个包含多个对象的数组 - 每个对象对应你 Dropbox 根目录中的一个文件或文件夹。

# 显示你的数据并使用 Vue 获取它

现在我们可以使用 Dropbox API 检索我们的数据了，是时候在我们的 Vue 实例中检索它并在我们的视图中显示了。这个应用将完全使用组件构建，这样我们就可以利用分隔的数据和方法。这也意味着代码是模块化和可共享的，如果你想将其集成到其他应用中。

我们还将利用 Vue 的原生`created()`函数 - 我们将在稍后讨论它被触发的时候。

# 创建组件

首先，在你的视图中创建自定义的 HTML 元素`<dropbox-viewer>`。在页面底部创建一个`<script>`模板块，用于我们的 HTML 布局：

```js
      <div id="app">
        <dropbox-viewer></dropbox-viewer>
      </div> 
      <script type="text/x-template" id="dropbox-viewer-          
       template">
        <h1>Dropbox</h1>
      </script>
```

在`app.js`文件中初始化你的组件，将其指向模板 ID：

```js
      Vue.component('dropbox-viewer', {
        template: '#dropbox-viewer-template'
      });
```

在浏览器中查看应用程序应该显示模板中的标题。下一步是将 Dropbox API 集成到组件中。

# 检索 Dropbox 数据

创建一个名为`dropbox`的新方法。在其中，将调用 Dropbox 类并返回实例的代码移动到这里。现在通过调用`this.dropbox()`可以通过组件访问 Dropbox API：

```js
      Vue.component('dropbox-viewer', {
        template: '#dropbox-viewer-template',  
        methods: {
 dropbox() {
 return new Dropbox({
 accessToken: this.accessToken
 });
 }
 }
      });
```

我们还要将 API 密钥集成到组件中。创建一个返回包含你的访问令牌的对象的数据函数。更新 Dropbox 方法，使用本地版本的密钥：

```js
      Vue.component('dropbox-viewer', {
        template: '#dropbox-viewer-template',  
        data() {
 return {
 accessToken: 'XXXX'
 }
 },
        methods: {
          dropbox() {
            return new Dropbox({
              accessToken: this.accessToken
            });
          }
        }
      });
```

现在我们需要为组件添加获取目录列表的功能。为此，我们将创建另一个方法，它接受一个参数-路径。这将使我们以后能够根据需要请求不同路径或文件夹的结构。

使用之前提供的代码-将`dbx`变量更改为`this.dropbox()`：

```js
      getFolderStructure(path) {
        this.dropbox().filesListFolder({path: path})
        .then(response => {
          console.log(response.entries);
        })
        .catch(error => {
          console.log(error);
        });
      }
```

更新 Dropbox 的`filesListFolder`函数，接受传入的路径参数，而不是固定值。在浏览器中运行此应用程序将显示 Dropbox 标题，但不会检索任何文件夹，因为尚未调用这些方法。

# Vue 生命周期钩子

这就是`created()`函数的作用。`created()`函数在 Vue 实例初始化数据和方法后调用，但尚未将实例挂载到 HTML 组件上。在生命周期的不同阶段还有其他几个可用的函数；关于这些函数的更多信息可以在 Alligator.io 上阅读。生命周期如下：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/02ada895-fdcb-4485-af9c-4c0b4d76c68d.png)

使用`created()`函数使我们能够在 Vue 挂载应用程序时访问方法和数据，并能够启动我们的检索过程。这些不同阶段之间的时间是分秒必争的，但在性能和创建快速应用程序方面，每一刻都很重要。如果我们可以提前开始任务，就没有必要等待应用程序完全挂载。

在你的组件上创建`created()`函数，并调用`getFolderStructure`方法，传入一个空字符串作为获取 Dropbox 根目录的路径：

```js
      Vue.component('dropbox-viewer', {
        template: '#dropbox-viewer-template',  
        data() {
          return {
            accessToken: 'XXXX'
          }
        }, 
        methods: {
         ...
        }, 
        created() {
 this.getFolderStructure('');
 }
      });
```

现在在浏览器中运行应用程序，将文件夹列表输出到控制台，结果应与之前相同。

现在我们需要在视图中显示文件列表。为此，我们将在组件中创建一个空数组，并用我们的 Dropbox 查询结果填充它。这样做的好处是，即使在没有任何内容之前，Vue 也可以在视图中循环遍历一个变量。

# 显示 Dropbox 数据

在数据对象中创建一个名为`structure`的新属性，并将其赋值为空数组。在文件夹检索的响应函数中，将`response.entries`赋值给`this.structure`。保留`console.log`，因为我们需要检查条目以确定在模板中输出什么：

```js
      Vue.component('dropbox-viewer', {
        template: '#dropbox-viewer-template', 
        data() {
          return {
            accessToken: 'XXXX',
            structure: []
          }
        },
        methods: {
          dropbox() {
            return new Dropbox({
              accessToken: this.accessToken
            });
          },
          getFolderStructure(path) {
            this.dropbox().filesListFolder({path: path})
            .then(response => {
              console.log(response.entries);
              this.structure = response.entries;
            })
            .catch(error => {
              console.log(error);
            });
          }
        },  
        created() {
          this.getFolderStructure('');
        }
      });
```

现在我们可以更新视图以显示来自 Dropbox 的文件夹和文件。由于结构数组在视图中可用，因此创建一个可重复的`<li>`循环遍历结构的`<ul>`。

由于我们现在添加了第二个元素，Vue 要求模板必须包含一个包含元素的容器，所以将标题和列表包装在一个`<div>`中：

```js
      <script type="text/x-template" id="dropbox-viewer-         
        template">
        <div>
          <h1>Dropbox</h1>
          <ul>
 <li v-for="entry in structure">
 </li>
 </ul>
 </div>
      </script>
```

在浏览器中查看应用程序时，当数组出现在 JavaScript 控制台中时，将显示一些空的项目符号。为了确定可以显示哪些字段和属性，请展开 JavaScript 控制台中的数组，然后进一步展开每个对象。您应该注意到每个对象都有一组相似的属性和一些在文件夹和文件之间有所不同的属性。

第一个属性`.tag`帮助我们确定该项是文件还是文件夹。然后，这两种类型都具有以下共同属性：

+   `id`: Dropbox 的唯一标识符。

+   `name`: 文件或文件夹的名称，与该项所在位置无关。

+   `path_display`: 项目的完整路径，与文件和文件夹的大小写匹配。

+   `path_lower`: 与`path_display`相同，但全部小写。

`.tag`为文件的项还包含了一些更多的字段供我们显示：

+   `client_modified`: 文件添加到 Dropbox 的日期。

+   `content_hash`: 文件的哈希值，用于判断它是否与本地或远程副本不同。关于此内容可以在 Dropbox 网站上阅读更多信息。

+   `rev`: 文件版本的唯一标识符。

+   `server_modified`: 文件在 Dropbox 上最后修改的时间。

+   `size`: 文件的大小（以字节为单位）。

首先，我们将显示项目的名称和大小（如果有）。更新列表项以显示这些属性：

```js
      <li v-for="entry in structure">
        <strong>{{ entry.name }}</strong>
        <span v-if="entry.size"> - {{ entry.size }}</span>
      </li>
```

# 更多文件元信息

为了使我们的文件和文件夹视图更有用，我们可以为图像等文件添加更多丰富的内容和元数据。通过在 Dropbox API 中启用`include_media_info`选项，可以获得这些详细信息。

返回到您的`getFolderStructure`方法，并在`path`之后添加该参数。以下是一些新的可读性行：

```js
      getFolderStructure(path) {
        this.dropbox().filesListFolder({
          path: path, 
          include_media_info: true
        })
        .then(response => {
          console.log(response.entries);
          this.structure = response.entries;
        })
        .catch(error => {
          console.log(error);
        });
      }
```

检查这个新 API 调用的结果将显示视频和图像的`media_info`键。展开它将显示有关文件的更多信息，例如尺寸。如果您想添加这些信息，您需要在显示信息之前检查`media_info`对象是否存在：

```js
      <li>
        <strong>{{ f.name }}</strong>
        <span v-if="f.size"> - {{ bytesToSize(f.size) }}          
        </span> - 
        <span v-if="f.media_info">
 [
 {{ f.media_info.metadata.dimensions.width }}px x 
 {{ f.media_info.metadata.dimensions.height }}px
 ]
 </span>
      </li>
```

尝试在从 Dropbox 检索数据时更新路径。例如，如果您有一个名为`images`的文件夹，将`this.getFolderStructure`参数更改为`/images`。如果您不确定路径是什么，请在 JavaScript 控制台中分析数据，并复制文件夹的`path_lower`属性的值，例如：

```js
      created() {
        this.getFolderStructure('/images');
      }
```

# 格式化文件大小

由于文件大小以纯字节输出，对于用户来说可能很难理解。为了解决这个问题，我们可以添加一个格式化方法来输出一个更用户友好的文件大小，例如显示`<q>1kb</q>`而不是`<q>1024</q>`。

首先，在数据对象上创建一个包含单位数组的新键`byteSizes`：

```js
      data() {
        return {
          accessToken: 'XXXX',
          structure: [],
          byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB']
        }
      }
```

这是将附加到图形的内容，所以可以将这些属性设置为小写或全词，例如*megabyte*。

接下来，在您的组件中添加一个新的方法`bytesToSize`。它将接受一个`bytes`参数，并输出一个带有单位的格式化字符串：

```js
      bytesToSize(bytes) {
        // Set a default
        let output = '0 Byte'; 
        // If the bytes are bigger than 0
        if (bytes > 0) {
          // Divide by 1024 and make an int
          let i = parseInt(Math.floor(Math.log(bytes) /              
           Math.log(1024)));
          // Round to 2 decimal places and select the                 
             appropriate unit from the array
            output = Math.round(bytes / Math.pow(1024, i), 
              2) + ' ' + this.byteSizes[i];
            }
            return output
          }
```

现在我们可以在视图中利用这个方法：

```js
      <li v-for="entry in structure">
        <strong>{{ entry.name }}</strong>
        <span v-if="entry.size"> - {{ 
        bytesToSize(entry.size) }}</span>
      </li>
```

# 添加一个加载屏幕

本章的最后一步是为我们的应用程序创建一个加载屏幕。这将告诉用户应用程序正在加载，如果 Dropbox API 运行缓慢（或者您有很多数据要显示！）。

这个加载屏幕背后的理论相当基本。我们将默认将加载变量设置为`true`，一旦数据加载完成，它将被设置为`false`。根据这个变量的结果，我们将利用视图属性来显示和隐藏带有加载文本或动画的元素，并显示加载的数据列表。

在数据对象中创建一个名为`isLoading`的新键。将这个变量默认设置为`true`：

```js
      data() {
        return {
          accessToken: 'XXXX',
          structure: [],
          byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB'],
          isLoading: true
        }
      }
```

在组件的`getFolderStructure`方法中，将`isLoading`变量设置为`false`。这应该在您设置结构之后的 promise 中发生：

```js
      getFolderStructure(path) {
        this.dropbox().filesListFolder({
          path: path, 
          include_media_info: true
        })
        .then(response => {
          console.log(response.entries);
          this.structure = response.entries;
          this.isLoading = false;
        })
        .catch(error => {
          console.log(error);
        });
      }
```

现在我们可以在视图中利用这个变量来显示和隐藏加载容器。

在无序列表之前创建一个新的`<div>`，其中包含一些加载文本。随意添加 CSS 动画或动画 gif-任何东西都可以让用户知道应用程序正在检索数据：

```js
      <h1>Dropbox</h1>
 <div>Loading...</div>
      <ul>
      ...
```

现在，我们只需要在应用程序加载时显示加载 div，数据加载后显示列表。由于这只是对 DOM 的一个更改，我们可以使用`v-if`指令。为了让您可以自由地重新排列 HTML，将属性添加到两者而不是使用`v-else`。

要显示或隐藏，我们只需要检查`isLoading`变量的状态。我们可以在列表前面添加一个感叹号，只有在应用程序没有加载时才显示：

```js
      <div>
        <h1>Dropbox</h1>
        <div v-if="isLoading">Loading...</div>
         <ul v-if="!isLoading">
          <li v-for="entry in structure">
            <strong>{{ entry.name }}</strong>
            <span v-if="entry.size">- {{ 
             bytesToSize(entry.size) }}</span>
          </li>
        </ul>
      </div>
```

我们的应用程序现在应该在挂载后显示加载容器，然后在收集到应用程序数据后显示列表。总结一下，我们完整的组件代码现在看起来像这样：

```js
      Vue.component('dropbox-viewer', {
        template: '#dropbox-viewer-template',
        data() {
          return {
            accessToken: 'XXXX',
            structure: [],
            byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB'],
            isLoading: true
          }
        },
        methods: {
          dropbox() {
            return new Dropbox({
              accessToken: this.accessToken
            });
          },
          getFolderStructure(path) {
            this.dropbox().filesListFolder({
              path: path, 
              include_media_info: true
            })
            .then(response => {
              console.log(response.entries);
              this.structure = response.entries;
              this.isLoading = false;
            })
            .catch(error => {
              console.log(error);
            });
          },

          bytesToSize(bytes) {
            // Set a default
            let output = '0 Byte';

            // If the bytes are bigger than 0
            if (bytes > 0) {
              // Divide by 1024 and make an int
              let i = parseInt(Math.floor(Math.log(bytes)               
              / Math.log(1024)));
              // Round to 2 decimal places and select the                 
                appropriate unit from the array
                output = Math.round(bytes / Math.pow(1024, 
                i), 2) + ' ' + this.byteSizes[i];
            }
           return output
          }
        },
        created() {
          this.getFolderStructure('');
        }
      });
```

# 在状态之间进行动画切换

作为对用户的一个很好的增强，我们可以在组件和状态之间添加一些过渡效果。幸运的是，Vue 包含了一些内置的过渡效果。通过使用 CSS，这些过渡效果允许您在插入 DOM 元素时轻松地添加淡入淡出、滑动和其他 CSS 动画。有关过渡的更多信息可以在 Vue 文档中找到。

第一步是添加 Vue 自定义 HTML `<transition>`元素。用单独的过渡元素包裹您的加载和列表，并给它一个`name`属性和一个`fade`值：

```js
      <script type="text/x-template" id="dropbox-viewer-      
       template">
        <div>
          <h1>Dropbox</h1>
          <transition name="fade">
            <div v-if="isLoading">Loading...</div>
          </transition>
          <transition name="fade">
            <ul v-if="!isLoading">
              <li v-for="entry in structure">
                <strong>{{ entry.name }}</strong>
                <span v-if="entry.size">- {{         
                bytesToSize(entry.size) }}</span>
              </li>
            </ul>
          </transition>
        </div>
</script>
```

现在将以下 CSS 添加到您的文档头部或一个单独的样式表中（如果您已经有一个）：

```js
      .fade-enter-active,
      .fade-leave-active {
        transition: opacity .5s
      }
      .fade-enter, 
      .fade-leave-to {
        opacity: 0
      }
```

使用过渡元素，Vue 根据过渡的状态和时间添加和删除各种 CSS 类。所有这些类都以通过属性传递的名称开头，并附加有关过渡当前阶段的信息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/e49dfffb-4158-44a3-abcb-0a1955bb862e.png)

在浏览器中尝试该应用程序，您应该注意到加载容器的淡出和文件列表的淡入。尽管在这个基本示例中，列表在淡出完成后会跳动一次，但这是一个示例，可以帮助您了解在 Vue 中使用过渡效果。

# 总结

在本章中，我们学习了如何制作一个 Dropbox 查看器，它是一个单页面应用程序，可以列出我们 Dropbox 账户中的文件和文件夹，并允许我们通过更新代码来显示不同的文件夹内容。我们学习了如何为我们的应用程序添加基本的加载状态，并使用 Vue 动画进行导航。

在第五章中，*通过文件树导航和从 URL 加载文件夹*，我们将浏览我们的应用程序文件夹，并为我们的文件添加下载链接。


# 第五章：通过文件树导航和从 URL 加载文件夹

在第四章中，*使用 Dropbox API 获取文件列表*，我们创建了一个应用程序，列出了指定 Dropbox 文件夹的文件和文件夹内容。现在我们需要使我们的应用程序易于导航。这意味着用户将能够点击文件夹名称以进入并列出其内容，并且还能够下载文件。

在继续之前，请确保在 HTML 中包含了 Vue 和 Dropbox 的 JavaScript 文件。

在本章中，我们将会：

+   为文件和文件夹创建一个组件

+   为文件夹组件添加链接以更新目录列表

+   为文件组件添加下载按钮

+   创建一个面包屑组件，以便用户可以轻松地返回到上一级目录

+   动态更新浏览器的 URL，这样如果一个文件夹被收藏夹或链接分享，正确的文件夹将被加载

# 分离文件和文件夹

在创建组件之前，我们需要将文件和文件夹分开放置在我们的结构中，这样我们就可以轻松地识别和显示不同类型的文件和文件夹。由于每个项目上都有`.tag`属性，我们可以将文件夹和文件分开。

首先，我们需要更新我们的`structure`数据属性，使其成为一个包含`files`和`folders`数组的对象。

```js
      data() {
        return {
          accessToken: 'XXXX',
          structure: {
 files: [],
 folders: []
 },
          byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB'],
          isLoading: true
        }
      }
```

这使我们能够将文件和文件夹追加到不同的数组中，从而可以在视图中以不同的方式显示它们。

下一步是用当前文件夹的数据填充这些数组。所有以下代码都在`getFolderStructure`方法的第一个`then()`函数中执行。

创建一个 JavaScript 循环来遍历条目并检查项目的`.tag`属性。如果它等于`folder`，则将其追加到`structure.folder`数组中，否则将其添加到`structure.files`数组中：

```js
      getFolderStructure(path) {
        this.dropbox().filesListFolder({
          path: path, 
          include_media_info: true
        })
        .then(response => {
          for (let entry of response.entries) {
 // Check ".tag" prop for type
 if(entry['.tag'] === 'folder') {
 this.structure.folders.push(entry);
 } else {
 this.structure.files.push(entry);
 }
 }
          this.isLoading = false;
        })
        .catch(error => {
          console.log(error);
        });
      },
```

这段代码通过循环遍历条目，并检查`.tag`属性。由于属性本身以`.`开头，我们无法像访问`entry.name`属性那样使用对象样式的表示法来访问该属性。然后，根据类型，我们使用 JavaScript 的 push 方法将条目追加到`files`或`folders`数组中。

为了显示这些新数据，我们需要更新视图以循环遍历这两种类型的数组。这是使用`<template>`标签的一个完美用例，因为我们想要将这两个数组都追加到同一个无序列表中。

更新视图以单独列出这两个数组。我们可以从文件夹显示部分中删除`size`选项，因为它永远不会有`size`属性：

```js
      <ul v-if="!isLoading">
        <template v-for="entry in structure.folders">
 <li>
 <strong>{{entry.name }}</strong>
 </li>
 </template>
 <template v-for="entry in structure.files">
 <li>
 <strong>{{ entry.name }}</strong>
 <span v-if="entry.size">- {{ bytesToSize(entry.size)       }}</span>
 </li>
 </template>
      </ul>
```

现在我们有机会为两种类型创建组件。

# 创建文件和文件夹组件

通过将数据类型分离出来，我们可以创建单独的组件来分隔数据和方法。创建一个`folder`组件，它接受一个属性，允许通过`folder`对象变量传递。由于模板非常小，所以不需要基于视图或`<script>`块的模板；相反，我们可以将其作为字符串传递给组件：

```js
      Vue.component('folder', {
        template: '<li><strong>{{ f.name }}</strong>      
        </li>',
        props: {
          f: Object
        },
      });
```

为了使我们的代码更小、更少重复，属性被称为`f`。这样可以整理视图，并让组件名称确定显示类型，而不需要多次重复使用单词`folder`。

更新视图以使用文件夹组件，并将`entry`变量传递给`f`属性：

```js
      <template v-for="entry in structure.folders">
        <folder :f="entry"></folder>
      </template>
```

通过创建一个`file`组件来重复这个过程。创建`file`组件时，我们可以将`bytesToSize`方法和`byteSizes`数据属性从父`dropbox-viewer`组件中移动，因为它只会在显示文件时使用：

```js
      Vue.component('file', {
        template: '<li><strong>{{ f.name }}</strong><span       v-if="f.size"> - {{ bytesToSize(f.size) }}</span>         </li>',
        props: {
          f: Object
        },
        data() {
          return {
            byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB']
          }
        }, 
        methods: {
          bytesToSize(bytes) {
            // Set a default
            let output = '0 Byte';      
            // If the bytes are bigger than 0
            if (bytes > 0) {
              // Divide by 1024 and make an int
              let i = parseInt(Math.floor(Math.log(bytes) 
              / Math.log(1024)));
             // Round to 2 decimal places and select the 
            appropriate unit from the array
            output = Math.round(bytes / Math.pow(1024, i), 
             2) + ' ' + this.byteSizes[i];
            }   
            return output
          }
        }
      });
```

再次，我们可以使用`f`作为属性名称来减少重复（和应用程序的文件大小）。再次更新视图以使用这个新组件：

```js
      <template v-for="entry in structure.files">
        <file :f="entry"></file>
      </template>
```

# 链接文件夹并更新结构

现在我们已经将文件夹和文件分开了，我们可以将文件夹名称转换为链接。这些链接将更新结构以显示所选文件夹的内容。为此，我们将使用每个文件夹的`path_lower`属性来构建链接目标。

为每个文件夹的`name`创建一个动态链接，链接到文件夹的`path_lower`。由于我们对 Vue 越来越熟悉，`v-bind`属性已经缩短为冒号表示法：

```js
      Vue.component('folder', {
        template: '<li><strong><a :href="f.path_lower">{{ 
        f.name }}</a></strong></li>',
        props: {
          f: Object
        },
      });
```

现在我们需要为此链接添加一个`click`监听器。当点击时，我们需要在`dropbox-viewer`组件上触发`getFolderStructure`方法。虽然点击方法将使用每个实例上的`f`变量来获取数据，但最好将`href`属性设置为文件夹的 URL。

使用本书早期章节中学到的知识，在`folder`组件上创建一个方法，当触发时将文件夹路径发送到父组件。当触发时，`dropbox-viewer`组件还需要一个新的方法来使用给定的参数更新结构。

在`folder`组件上创建新方法，并将`click`事件添加到文件夹链接上。与`v-bind`指令一样，我们现在使用`v-on`的简写符号`@`表示：

```js
      Vue.component('folder', {
        template: '<li><strong><a          
 @click.prevent="navigate()" :href="f.path_lower">{{ 
       f.name }}</a></strong></li>',
        props: {
          f: Object
        },
        methods: {
          navigate() {
 this.$emit('path', this.f.path_lower);
 }
        }
      });
```

除了定义`click`事件之外，还添加了一个事件修饰符。在点击事件之后使用`.prevent`将`preventDefault`添加到链接操作中，这样可以阻止链接实际上转到指定的 URL，而是让`click`方法处理所有事情。有关更多事件修饰符及其详细信息，请参阅 Vue 文档。

当点击时，将触发`navigate`方法，该方法使用`path`变量发出文件夹的较低路径。

现在我们有了`click`处理程序和被发出的变量，我们需要更新视图以触发父`dropbox-viewer`组件上的方法：

```js
      <template v-for="entry in structure.folders">
        <folder :f="entry" @path="updateStructure">      
        </folder>
      </template>
```

在 Dropbox 组件上创建一个与`v-on`属性的值相同的新方法，本例中为`updateStructure`。此方法将有一个参数，即我们之前发出的路径。从这里，我们可以使用路径变量触发我们原始的`getFolderStructure`方法：

```js
      updateStructure(path) {
        this.getFolderStructure(path);
      }
```

在浏览器中查看我们的应用程序现在应该列出文件夹和链接，并在点击时显示新文件夹的内容。

但是，在这样做时，会引发一些问题。首先，文件和文件夹被附加到现有列表而不是替换它。其次，用户没有任何反馈，表明应用程序正在加载下一个文件夹。

可以通过在附加新结构之前清除文件夹和文件数组来解决第一个问题。可以通过使用应用程序开始时使用的加载屏幕来解决第二个问题-这将为用户提供一些反馈。

为了解决第一个问题，在`getFolderStructure`方法的成功 promise 函数中创建一个新的`structure`对象。该对象应该复制`data`对象中的`structure`对象。这将为文件和文件夹设置空数组。更新`for`循环以使用本地结构数组而不是组件数组。最后，使用更新后的文件和文件夹更新组件的`structure`对象：

```js
      getFolderStructure(path) {
        this.dropbox().filesListFolder({
          path: path, 
          include_media_info: true
        })
        .then(response => {  
          const structure = {
 folders: [],
 files: []
 }
          for (let entry of response.entries) {
            // Check ".tag" prop for type
            if(entry['.tag'] == 'folder') {
              structure.folders.push(entry);
            } else {
              structure.files.push(entry);
            }
          } 
          this.structure = structure;
          this.isLoading = false;
        })
        .catch(error => {
          console.log(error);
        });
      }
```

当应用程序挂载并创建自己的结构对象时，会调用此方法，因此不需要在`data`函数中声明数组。将数据对象更新为仅将`structure`属性初始化为对象：

```js
      data() {
        return {
          accessToken: 'XXXX',
          structure: {},
          isLoading: true
        }
      }
```

现在运行应用程序将渲染文件列表，当点击进入新文件夹时，文件列表将被清除并更新。为了给用户一些反馈并让他们知道应用程序正在工作，让我们在每次点击后切换加载屏幕。

然而，在此之前，让我们充分了解延迟来自何处以及何时最好触发加载屏幕。

点击链接是瞬间的，这会触发文件夹组件上的导航方法，进而触发 Dropbox 组件上的`updateStructure`方法。当应用程序到达 Dropbox 实例上的`filesListFolder`函数时，延迟发生在`getFolderStructure`方法内部。由于我们可能希望在以后的某个日期触发`getFolderStucture`方法而不触发加载屏幕，所以在`updateStructure`方法中将`isLoading`变量设置为`true`：

```js
      updateStructure(path) {
        this.isLoading = true;
        this.getFolderStructure(path);
      }
```

通过动画，应用程序在导航文件夹时在加载屏幕和文件夹结构之间淡入淡出。

# 从当前路径创建面包屑

在浏览文件夹或任何嵌套结构时，始终有一个可用的面包屑非常好，这样用户就知道他们在哪里，他们走了多远，也可以轻松返回到以前的文件夹。我们将为面包屑制作一个组件，因为它将包含各种属性、计算函数和方法。

面包屑组件将以链接的形式列出每个文件夹的深度，链接指向文件夹图标。点击链接将直接将用户导航到该文件夹 - 即使它在多个层级上。为了实现这一点，我们需要一个链接列表，我们可以循环遍历，每个链接都有两个属性 - 一个是文件夹的完整路径，另一个只是文件夹的名称。

例如，如果我们有文件夹结构为`/images/holiday/summer/iphone`，我们希望能够点击`Holiday`并且应用程序导航到`/images/holiday`。

创建面包屑组件 - 现在，在模板属性中添加一个空的`<div>`：

```js
      Vue.component('breadcrumb', {
        template: '<div></div>'
      });
```

将组件添加到视图中。我们希望面包屑与结构列表一起淡入淡出，因此我们需要调整 HTML，将列表和面包屑组件都包裹在具有`v-if`声明的容器中：

```js
      <transition name="fade">
        <div v-if="!isLoading">
          <breadcrumb></breadcrumb>
          <ul>
            <template v-for="entry in structure.folders">
              <folder :f="entry" @path="updateStructure">              </folder>
            </template>  
            <template v-for="entry in structure.files">
              <file :f="entry"></file>
            </template>
          </ul>
        </div>
      </transition>
```

现在我们需要一个变量来存储当前文件夹路径。然后我们可以在面包屑组件中操作这个变量。这个变量将被存储并在 Dropbox 组件上更新，并传递给面包屑组件。

在`dropbox-viewer`组件上创建一个名为`path`的新属性：

```js
      data() {
        return {
          accessToken: 'XXXXX',
          structure: {},
          isLoading: true,
          path: ''
        }
      }
```

现在我们需要确保当从 Dropbox API 检索到结构时，该路径会得到更新。在`getFolderStructure`方法中，在禁用`isLoading`变量之前执行此操作。这样可以确保它只在结构加载完成之后，但在文件和文件夹显示之前更新：

```js
      getFolderStructure(path) {
        this.dropbox().filesListFolder({
          path: path, 
          include_media_info: true
        })
        .then(response => {    
          const structure = {
            folders: [],
            files: []
          }  
          for (let entry of response.entries) {
            // Check ".tag" prop for type
            if(entry['.tag'] == 'folder') {
              structure.folders.push(entry);
            } else {
              structure.files.push(entry);
            }
          } 
          this.path = path;
          this.structure = structure;
          this.isLoading = false;
        })
        .catch(error => {
          console.log(error);
        });
      },
```

现在我们有了一个填充了当前路径的变量，我们可以将其作为属性传递给面包屑组件。在面包屑上添加一个新的属性，将路径变量作为值：

```js
      <breadcrumb :p="path"></breadcrumb>
```

更新组件以接受字符串作为属性：

```js
      Vue.component('breadcrumb', {
        template: '<div></div>',
        props: {
 p: String
 }
      });
```

`p`属性现在包含了我们所在位置的完整路径（例如`/images/holiday/summer`）。我们想要将这个字符串分解，以便我们可以识别文件夹名称并构建面包屑以供组件渲染。

在组件上创建一个`computed`对象，并创建一个名为`folders()`的新函数。这将为我们创建面包屑数组，供我们在模板中循环遍历：

```js
      computed: {
       folders() {   
        }
      }
```

现在我们需要设置一些变量供我们使用。创建一个新的空数组`output`。这是我们要构建面包屑的地方。我们还需要一个空字符串变量`slug`。`slug`变量是指 URL 的一部分，它的使用在 WordPress 中很流行。最后一个变量是作为数组创建的路径。我们知道，每个文件夹都是由`/`分隔的，我们可以使用这个来将字符串分解成各个部分：

```js
      computed: {
        folders() {
 let output = [],
 slug = '',
 parts = this.p.split('/');
        }
      }
```

如果我们查看`Summer`文件夹的`parts`变量，它会像下面这样：

```js
      ['images', 'holiday', 'summer']
```

现在我们可以循环遍历数组来创建面包屑。每个面包屑项都将是一个对象，包含个别文件夹的`name`，例如`holiday`或`summer`，以及`slug`，前者为`/images/holiday`，后者为`/images/holiday/summer`。

每个对象都将被构建并添加到`output`数组中。然后我们可以返回这个输出供我们的模板使用：

```js
      folders() {
        let output = [],
          slug = '',
          parts = this.p.split('/'); 
 for (let item of parts) {
 slug += item;
 output.push({'name': item, 'path': slug});
 slug += '/';
 }  
        return output;
      }
```

这个循环通过以下步骤创建我们的面包屑。以这个例子为例，我们假设我们在`/images/holiday`文件夹中：

1.  `parts`现在将是一个包含三个项的数组，`['', 'images', holiday']`。如果你要拆分的字符串以你正在拆分的项开头，那么将创建一个空项作为第一项。

1.  在循环开始时，第一个 slug 变量将等于`''`，因为它是第一个项。

1.  `output`数组将附加一个新项，其对象为`{'name': '', 'path': ''}`。

1.  然后，`slug`变量在末尾添加了一个斜杠。

1.  循环遍历下一个项时，`slug`变量会将该项的名称（`images`）添加到其中。

1.  `output`现在添加了一个新对象，其值为`{'name': 'images', 'path': '/images'}`。

1.  对于最后一项，除了下一个名称`holiday`之外，还添加了一个`/`。

1.  `output`获取最后添加的对象，其值为`{'name': 'holiday', 'path': '/images/holiday'}` - 注意路径正在构建，而名称仍然是单数文件夹名称。

现在我们有了可以在视图中循环遍历的面包屑输出数组。

我们在将项附加到输出数组之后添加斜杠的原因是 API 规定，要获取 Dropbox 的根目录，我们传入一个空字符串，而所有其他路径必须以`/`开头。

下一步是将面包屑输出到我们的视图中。由于这个模板很小，我们将使用多行 JavaScript 表示法。循环遍历`folders`计算变量中的项，为每个项输出一个链接。不要忘记在所有链接周围保留一个包含元素：

```js
      template: '<div>' +
 '<span v-for="f in folders">' +
 '<a :href="f.path">{{ f.name }}</a>' +
 '</span>' + 
      '</div>'
```

在浏览器中渲染此应用程序应该显示一个面包屑 - 尽管有点挤在一起，缺少一个主页链接（因为第一个项没有名称）。返回到`folders`函数并添加一个`if`语句 - 检查该项是否有名称，如果没有，则添加一个硬编码的值：

```js
      folders() {
        let output = [],
          slug = '',
          parts = this.p.split('/');
        console.log(parts);
        for (let item of parts) {
          slug += item;
          output.push({'name': item || 'home', 'path':      
            slug});
          slug += '/';
        }  
        return output;
      }
```

另一种选择是在模板本身中添加`if`语句：

```js
      template: '<div>' +
        '<span v-for="f in folders">' +
          '<a :href="f.path">{{ f.name || 'Home' }}</a>' +
        '</span>' + 
      '</div>'
```

如果我们想在文件夹名称之间显示分隔符，比如斜杠或箭头，这可以很容易地添加。然而，当我们想在链接之间显示分隔符，但不在开头或结尾时，会出现一个小障碍。为了解决这个问题，我们将利用循环时可用的`index`关键字。然后，我们将将其与数组的长度进行比较，并在元素上操作`v-if`声明。

在循环遍历数组时，Vue 允许您利用另一个变量。默认情况下，这是索引（数组中项的位置）；然而，如果您的数组是以键/值方式构建的，则索引可以设置为一个值。如果是这种情况，您仍然可以通过添加第三个变量来访问索引。由于我们的数组是一个简单的列表，我们可以轻松地使用这个变量：

```js
      template: '<div>' +
        '<span v-for="(f, i) in folders">' +
          '<a :href="f.path">{{ f.name || 'Home' }}</a>' +
          '<span v-if="i !== (folders.length - 1)"> » 
            </span>' +
        '</span>' + 
      '</div>',
```

更新`f`变量为包含一个`f`和一个`i`的括号，用逗号分隔。`f`变量是循环中的当前文件夹，而已创建的`i`变量是该项的索引。请记住，数组索引从`0`开始，而不是从`1`开始。

我们添加的分隔符包含在一个带有`v-if`属性的 span 标签中，其内容可能看起来令人困惑。这是将当前索引与`folders`数组的长度（它有多少项）减 1 混淆了。`- 1`是因为索引从 0 开始，而不是从 1 开始，正如您所期望的那样。如果数字不匹配，则显示`span`元素。

我们需要做的最后一件事是使我们的面包屑导航到所选文件夹。我们可以通过修改我们为`folder`组件编写的导航函数来实现这一点。然而，由于我们的整个组件是面包屑，而不是每个单独的链接，所以我们需要修改它以接受一个参数。

首先，在链接上添加`click`事件，传入`folder`对象：

```js
      template: '<div>' +
        '<span v-for="(f, i) in folders">' +
          '<a @click.prevent="navigate(f)"          
            :href="f.path"> 
            {{ f.name || 'Home' }}</a>' +
          '<i v-if="i !== (folders.length - 1)"> &raquo; 
           </i>' +
        '</span>' + 
      '</div>',
```

接下来，在面包屑组件上创建`navigate`方法，确保接受`folder`参数并发出路径：

```js
      methods: {
        navigate(folder) {
          this.$emit('path', folder.path);
        }
      }
```

最后一步是在路径被发出时触发父方法。为此，我们可以在`dropbox-viewer`组件上利用相同的`updateStructure`方法：

```js
      <breadcrumb :p="path" @path="updateStructure">      
      </breadcrumb>
```

现在我们有了一个完全可操作的面包屑，允许用户通过文件夹链接向下导航文件夹结构，并通过面包屑链接向上导航。

我们完整的面包屑组件如下所示：

```js
      Vue.component('breadcrumb', {
        template: '<div>' +
          '<span v-for="(f, i) in folders">' +
            '<a @click.prevent="navigate(f)" 
             :href="f.path">{{ 
              f.name || 'Home' }}</a>' +
              '<i v-if="i !== (folders.length - 1)"> » 
              </i>' + '</span>' + 
             '</div>',

        props: {
    p: String
  },

  computed: {
    folders() {
      let output = [],
        slug = '',
        parts = this.p.split('/');
      console.log(parts);
      for (let item of parts) {
        slug += item;
        output.push({'name': item || 'home', 'path':   
        slug});
        slug += '/';
      }

      return output;
    }
  },

   methods: {
    navigate(folder) {
      this.$emit('path', folder.path);
    }
  }
});
```

# 添加下载文件的功能

现在，我们的用户可以通过文件夹结构导航，我们需要添加下载文件的功能。不幸的是，这并不像访问文件上的链接属性那样简单。为了获取下载链接，我们必须查询 Dropbox API 以获取每个文件。

在创建文件组件时，我们将查询 API，这将异步获取下载链接并在可用时显示。在此之前，我们需要将 Dropbox 实例提供给文件组件。

在视图中为文件组件添加一个新属性，并将 Dropbox 方法作为值传递：

```js
      <file :d="dropbox()" :f="entry"></file>
```

将`d`变量添加到接受对象的组件的`props`对象中：

```js
    props: {
      f: Object,
      d: Object
    },
```

现在，我们将添加一个名为`link`的数据属性。默认情况下，它应该设置为`false`，以便我们可以隐藏链接，并在 API 返回值后填充它的下载链接。

将`created()`函数添加到文件组件中，并在其中添加 API 调用：

```js
     created() {
      this.d.filesGetTemporaryLink({path:    
       this.f.path_lower}).then(data => {
        this.link = data.link;
     });
    }
```

此 API 方法接受一个对象，类似于`filesListFolder`函数。我们正在传递当前文件的路径。一旦数据返回，我们可以将组件的`link`属性设置为下载链接。

现在我们可以在组件的模板中添加一个下载链接。只有在检索到下载链接后才添加`v-if`以显示`<a>`：

```js
   template: '<li><strong>{{ f.name }}</strong><span v-  
    if="f.size"> - {{ bytesToSize(f.size) }}</span><span    
    v-if="link"> - <a :href="link">Download</a></span>  
   </li>'
```

浏览文件时，我们现在可以看到每个文件旁边出现一个下载链接，其速度取决于您的互联网连接和 API 速度。

现在添加了下载链接的完整文件组件如下所示：

```js
    Vue.component('file', {
     template: '<li><strong>{{ f.name }}</strong><span v-   
     if="f.size"> - {{ bytesToSize(f.size) }}</span><span 
     v-if="link"> - <a :href="link">Download</a></span>
     </li>',
    props: {
      f: Object,
      d: Object
      },

   data() {
     return {
       byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB'],
      link: false
      }
   },

    methods: {
     bytesToSize(bytes) {
      // Set a default
      let output = '0 Byte';

      // If the bytes are bigger than 0
      if (bytes > 0) {
        // Divide by 1024 and make an int
        let i = parseInt(Math.floor(Math.log(bytes) / 
          Math.log(1024)));
        // Round to 2 decimal places and select the 
         appropriate unit from the array
        output = Math.round(bytes / Math.pow(1024, i), 2) 
         + ' ' + this.byteSizes[i];
      }

      return output
      }
     },

     created() {
    this.d.filesGetTemporaryLink({path:    
     this.f.path_lower}).then(data => {
      this.link = data.link;
      });
    },
  });
```

# 更新 URL 哈希并使用它来浏览文件夹：

通过结构列表和面包屑，我们现在可以完全浏览我们的 Dropbox Web 应用程序，并且可以添加和更新浏览器 URL 以便快速访问和共享文件夹。我们可以通过两种方式实现：我们可以更新哈希，例如`www.domain.com/#/images/holiday/summer`，或者我们可以将所有路径重定向到单个页面，并处理 URL 中的路由而不使用哈希。

对于这个应用程序，我们将在 URL 中使用`#`方法。当我们介绍`vue-router`时，我们将在本书的第三部分介绍 URL 路由技术。

在让应用程序显示 URL 对应的文件夹之前，我们首先需要在导航到新文件夹时更新 URL。我们可以使用原生的`window.location.hash` JavaScript 对象来实现这一点。我们希望在用户点击链接时立即更新 URL，而不是等待数据加载后再更新。

由于每当我们更新结构时都会触发`getFolderStructure`方法，因此将代码添加到此函数的顶部。这意味着 URL 会被更新，然后调用 Dropbox API 来更新结构：

```js
    getFolderStructure(path) {
      window.location.hash = path;

      this.dropbox().filesListFolder({
       path: path, 
        include_media_info: true
      })
     .then(response => {

       const structure = {
        folders: [],
        files: []
       }

      for (let entry of response.entries) {
        // Check ".tag" prop for type
         if(entry['.tag'] == 'folder') {
          structure.folders.push(entry);
         } else {
          structure.files.push(entry);
         }
       }

      this.path = path;
      this.structure = structure;
      this.isLoading = false;
   })
     .catch(error => {
      console.log(error);
   });
 }
```

当您浏览应用程序时，应该更新 URL 以包括当前文件夹路径。

然而，当你按下刷新按钮时，你会发现一个问题，那就是 URL 会重置，只有一个哈希，后面没有文件夹，因为它是通过`created()`函数中传递的空路径重置的。

我们可以通过在`created`函数中将当前哈希传递给`getFolderStructure`来解决这个问题，但是如果这样做，我们需要进行一些检查和错误捕获。

首先，在调用`window.location.hash`时，你也会得到哈希作为字符串的一部分返回，所以我们需要将其删除。其次，我们需要处理 URL 不正确的情况，如果用户输入了不正确的路径或者文件夹被移动了。最后，我们需要让用户在浏览器中使用后退和前进按钮（或键盘快捷键）。

# 根据 URL 显示文件夹

当我们的应用程序挂载时，它已经调用了一个函数来请求基本文件夹的结构。我们编写了这个函数以允许路径被传递，并且在`created()`函数中，我们已经将值固定为根文件夹`''`。这使我们能够灵活地调整这个函数，以传递 URL 中的哈希值，而不是固定字符串。

更新函数以接受 URL 的哈希值，并且如果没有哈希值，则使用原始的固定字符串：

```js
  created() {
    let hash = window.location.hash.substring(1);
    this.getFolderStructure(hash || '');
  }
```

创建一个名为`hash`的新变量，并将`window.location.hash`赋值给它。因为变量以`#`开头，对于我们的应用程序来说是不需要的，所以使用`substring`函数从字符串中删除第一个字符。然后我们可以使用逻辑运算符来使用 hash 变量，或者如果它等于空，使用原始的固定字符串。

现在你应该能够通过更新 URL 来浏览你的应用程序。如果你随时按下刷新按钮或将 URL 复制粘贴到不同的浏览器窗口中，你所在的文件夹应该会加载。

# 显示错误消息

由于我们的应用程序接受 URL，我们需要处理一种情况，即用户输入 URL 时出现错误，或者共享的文件夹已经被移动。

由于这个错误是一个边缘情况，如果加载数据时出现错误，我们将劫持`isLoading`参数。在`getFolderStructure`函数中，我们返回一个作为 promise 的`catch`函数，如果 API 调用出错，就会触发这个函数。在这个函数中，将`isLoading`变量设置为`'error'`：

```js
   getFolderStructure(path) {
     window.location.hash = path;

     this.dropbox().filesListFolder({
      path: path, 
      include_media_info: true
    })
    .then(response => {

      const structure = {
        folders: [],
        files: []
      }

      for (let entry of response.entries) {
        // Check ".tag" prop for type
        if(entry['.tag'] == 'folder') {
         structure.folders.push(entry);
       } else {
         structure.files.push(entry);
       }
     }

     this.path = path;
     this.structure = structure;
     this.isLoading = false;
   })
    .catch(error => {
      this.isLoading = 'error';
      console.log(error);
    });
  }
```

如果需要诊断除了错误文件路径之外的问题，可以保留`console.log`。尽管 API 可能会抛出多种不同的错误，但在这个应用程序中，我们假设错误是由于错误的路径。如果您想在应用程序中处理其他错误，可以通过其`status_code`属性来识别错误类型。有关此更多详细信息，请参阅 Dropbox API 文档。

更新视图以处理这个新的`isLoading`变量属性。当设置为错误时，`isLoading`变量仍然为"true"，因此在加载元素中，添加一个新的`v-if`来检查加载变量是否设置为`error`：

```js
   <transition name="fade">
    <div v-if="isLoading">
      <div v-if="isLoading === 'error'">
 <p>There seems to be an issue with the URL entered.  
       </p>
 <p><a href="">Go home</a></p>
 </div>
 <div v-else>
 Loading...
 </div>
    </div>
  </transition>
```

如果`isLoading`变量的第一个元素设置为`error`，则显示该元素；否则，显示加载文本。在错误文本中，包含一个链接，将用户发送回当前 URL，不带任何 URL 哈希。这将将他们“重置”回文档树的顶部，以便他们可以向下导航。一个改进可以是将当前 URL 拆分，并建议删除最后一个文件夹后相同的 URL。

验证错误代码是否加载，方法是在 URL 的末尾添加一个不存在的路径，并确保显示错误消息。请注意，用户可能会在某种意义上对此错误消息产生误报，即如果 Dropbox API 抛出任何类型的错误，将显示此消息。

# 在浏览器中使用返回和前进按钮

为了在浏览器中使用返回和前进按钮，我们需要大幅更新我们的代码。目前，当用户从结构或面包屑中的任何一个文件夹中单击时，我们通过在`click`处理程序上使用`.prevent`来阻止浏览器的默认行为。然后，在处理文件夹之前，我们立即更新 URL。

然而，如果我们允许应用程序使用本机行为更新 URL，我们可以监听哈希 URL 的更新，并使用它来检索我们的新结构。使用这种方法，返回和前进按钮将无需任何进一步的干预即可工作，因为它们将更新 URL 哈希。

这也将提高我们应用程序的可读性，并减少代码量，因为我们将能够删除链接上的`navigate`方法和`click`处理程序。

# 删除不需要的代码

在添加更多代码之前，第一步是从组件中删除不必要的代码。从面包屑开始，从组件中删除`navigate`方法，并从模板中的链接中删除`@click.prevent`属性。

我们还需要更新每个项目的`slug`，在其前面添加`#` - 这样可以确保应用程序在点击时不会尝试导航到全新的页面。由于我们在文件夹的`computed`函数中循环遍历面包屑项，所以在将对象推送到`output`数组时，为每个`slug`添加一个哈希：

```js
 Vue.component('breadcrumb', {
   template: '<div>' +
     '<span v-for="(f, i) in folders">' +
       '<a :href="f.path">{{ f.name || 'Home' }}</a>' +
       '<i v-if="i !== (folders.length - 1)"> &raquo;   
       </i>' + '</span>' + 
       '</div>',
    props: {
      p: String
     },
    computed: {
      folders() {
        let output = [],
          slug = '',
          parts = this.p.split('/');

         for (let item of parts) {
          slug += item;
            output.push({'name': item || 'home', 'path': '#' + slug});
            slug += '/';
         }

         return output;
       }
     }
   });
```

我们还可以在`dropbox-viewer-template`中的面包屑组件上删除`v-on`声明。它只应该有传递的路径作为属性：

```js
    <breadcrumb :p="path"></breadcrumb>
```

现在我们可以为文件夹组件重复相同的模式。从链接中删除`@click.prevent`声明并删除`navigate`方法。

由于我们在显示之前不会循环遍历或编辑文件夹对象，所以我们可以在模板中添加`#`。由于我们告诉 Vue `href` 绑定到一个 JavaScript 对象（使用冒号），我们需要用引号将哈希封装起来，并使用 JavaScript 的`+`符号将其与文件夹路径连接起来。

我们已经在单引号和双引号之间，所以我们需要告诉 JavaScript 我们*确实*是一个单引号，这可以通过在单引号字符前面使用反斜杠来实现：

```js
   Vue.component('folder', {
    template: '<li><strong><a :href="\'#\' +   
    f.path_lower">{{ f.name }}</a></strong></li>',
     props: {
      f: Object
     }
   });
```

我们还可以从视图中的`<folder>`组件中删除`@path`属性。

```js
   <template v-for="entry in structure.folders">
     <folder :f="entry"></folder>
   </template>
```

现在我们的代码看起来更加清晰、简洁，并且文件大小更小。在浏览器中查看应用程序将呈现所在文件夹的结构；但是，点击链接将更新 URL 但不会更改显示内容。

# 通过更改 URL 并在实例外设置 Vue 数据来更新结构

现在我们的 URL 已经正确更新，我们可以在哈希更改时获取新的结构。这可以使用 JavaScript 的`onhashchange`函数来实现。

我们将创建一个函数，每当 URL 的哈希更新时触发，这将更新父 Vue 实例上的路径变量。这个变量将作为属性传递给子`dropbox-viewer`组件。该组件将监视变量的变化，并在更新时检索新的结构。

首先，更新父 Vue 实例，使其具有一个带有路径键的数据对象 - 设置为空字符串属性。我们还将将 Vue 实例分配给一个名为`app`的常量变量 - 这允许我们在实例外设置数据和调用方法：

```js
 const app = new Vue({
    el: '#app',
 data: {
 path: ''
 }
 });
```

下一步是在每次 URL 更新时更新这个数据属性。这是通过使用`window.onhashchange`来实现的，它是一个原生的 JavaScript 函数，每当 URL 中的哈希值发生变化时就会触发。

从 Dropbox 组件的`created`函数中复制并粘贴哈希修改器，并使用它来修改哈希并将值存储在 Vue 实例上。如果哈希不存在，我们将传递一个空字符串给路径变量：

```js
   window.onhashchange = () => {
    let hash = window.location.hash.substring(1);
    app.path = (hash || '');
   }
```

现在，我们需要将这个路径变量传递给 Dropbox 组件。在视图中添加一个名为`p`的 prop，将`path`变量作为值：

```js
   <div id="app">
    <dropbox-viewer :p="path"></dropbox-viewer>
   </div>
```

在 Dropbox 组件中添加`props`对象，以接受一个字符串：

```js
   props: {
     p: String
    },
```

现在，我们将在`dropbox-viewer`组件中添加一个`watch`函数。这个函数将监视`p` prop，并在更新时使用修改后的路径调用`updateStructure()`方法：

```js
   watch: {
     p() {
      this.updateStructure(this.p);
     }
   }
```

回到浏览器，我们现在应该能够像以前一样通过 Dropbox 结构进行导航，使用文件夹链接和面包屑作为导航。我们现在应该能够使用浏览器的后退和前进按钮，以及任何键盘快捷键，来通过文件夹进行导航。

在我们进入第六章之前，使用`vuex`为我们的应用程序引入文件夹缓存，*使用 Vuex 缓存当前文件夹结构*，我们可以对 Dropbox 组件进行一些优化。

首先，在`getFolderStructure`函数中，我们可以删除设置 URL 哈希为路径的第一行代码。这是因为当链接被使用时，URL 已经被更新了。从你的代码中删除这一行：

```js
   window.location.hash = path;
```

其次，在 Dropbox 组件中，现在存在`this.path`变量和`p` prop 的重复。消除这个重复需要进行一些微小的改动，因为你不能像处理路径那样直接修改 prop；然而，它需要保持同步，以便正确渲染面包屑。

从 Dropbox 组件的数据对象中删除`path`属性，并且还要从`getFolderStructure`函数中删除`this.path = path`这一行。

接下来，将`prop`更新为等于`path`，而不是`p`。这还需要更新`watch`函数，以监视`path`变量而不是`p()`。

将`created`方法更新为只使用`this.path`作为函数的参数。现在，Dropbox 组件应该如下所示：

```js
   Vue.component('dropbox-viewer', {
     template: '#dropbox-viewer-template',

     props: {
      path: String
     },

     data() {
       return {
         accessToken: 'XXXX',
        structure: {},
         isLoading: true
       }
      },

     methods: {
       dropbox() {
         return new Dropbox({
            accessToken: this.accessToken
         });
       },

       getFolderStructure(path) { 
         this.dropbox().filesListFolder({
           path: path, 
          include_media_info: true
         })
          .then(response => {

           const structure = {
            folders: [],
            files: []
           }

          for (let entry of response.entries) {
            // Check ".tag" prop for type
            if(entry['.tag'] == 'folder') {
             structure.folders.push(entry);
             } else {
           }
          }

         this.structure = structure;
         this.isLoading = false;
       })
        .catch(error => {
         this.isLoading = 'error';
         console.log(error);
        });
      },

       updateStructure(path) {
        this.isLoading = true;
        this.getFolderStructure(path);
       }
    },

     created() {
       this.getFolderStructure(this.path);
     },

      watch: {
      path() {
        this.updateStructure(this.path);
      }
     },
   });
```

更新视图以接受`prop`作为`path`：

```js
   <dropbox-viewer :path="path"></dropbox-viewer>
```

现在，我们需要确保父级`Vue`实例在页面加载和哈希值变化时具有正确的路径。为了避免重复，我们将扩展我们的`Vue`实例，添加一个方法和一个`created`函数。

将路径变量设置为空字符串。创建一个名为`updateHash()`的新方法，它会从窗口哈希中删除第一个字符，然后将`path`变量设置为哈希值或空字符串。接下来，创建一个名为`created()`的函数，它会运行`updateHash`方法。

`Vue`实例现在看起来是这样的：

```js
  const app = new Vue({
    el: '#app',

    data: {
      path: ''
    }, 
    methods: {
 updateHash() {
 let hash = window.location.hash.substring(1);
 this.path = (hash || '');
 }
 },
 created() {
 this.updateHash()
 }
  });
```

最后，为了避免重复，当地址栏中的哈希值发生变化时，我们可以触发`updateHash`方法：

```js
   window.onhashchange = () => {
     app.updateHash();
   }
```

# 最终代码

我们的代码现在已经完成，你的视图和 JavaScript 文件应该如下所示。首先，视图应该是这样的：

```js
   <div id="app">
      <dropbox-viewer :path="path"></dropbox-viewer>
    </div>

   <script type="text/x-template" id="dropbox-viewer- 
     template">
    <div>
      <h1>Dropbox</h1>

      <transition name="fade">
        <div v-if="isLoading">
          <div v-if="isLoading == 'error'">
            <p>There seems to be an issue with the URL 
            entered.</p>
            <p><a href="">Go home</a></p>
          </div>
          <div v-else>
            Loading...
          </div>
        </div>
      </transition>

      <transition name="fade">
        <div v-if="!isLoading">
          <breadcrumb :p="path"></breadcrumb>
          <ul>
            <template v-for="entry in structure.folders">
             <folder :f="entry"></folder>
            </template>

           <template v-for="entry in structure.files">
             <file :d="dropbox()" :f="entry"></file>
           </template>
         </ul>
       </div>
      </transition>

     </div>
    </script>
```

附带的 JavaScript 应用应该是这样的：

```js
   Vue.component('breadcrumb', {
        template: '<div>' +
        '<span v-for="(f, i) in folders">' +
         '<a :href="f.path">{{ f.name || 'Home' }}</a>' +
          '<i v-if="i !== (folders.length - 1)"> &raquo; 
           </i>' + '</span>' + 
        '</div>',
      props: {
      p: String
     },
     computed: {
        folders() {
          let output = [],
           slug = '',
           parts = this.p.split('/');

        for (let item of parts) {
          slug += item;
            output.push({'name': item || 'home', 'path': 
            '#' + slug});
          slug += '/';
         }

         return output;
        }
      }
    });

    Vue.component('folder', {
       template: '<li><strong><a :href="\'#\' + 
       f.path_lower">{{ f.name }}</a></strong></li>',
      props: {
       f: Object
      }
   });

   Vue.component('file', {
         template: '<li><strong>{{ f.name }}</strong><span 
         v-if="f.size"> - {{ bytesToSize(f.size) }}</span>
         <span v-if="link"> - <a :href="link">Download</a>
         </span></li>',
        props: {
        f: Object,
         d: Object
       },

     data() {
      return {
        byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB'],
        link: false
       }
      },

    methods: {
       bytesToSize(bytes) {
        // Set a default
        let output = '0 Byte';

        // If the bytes are bigger than 0
         if (bytes > 0) {
          // Divide by 1024 and make an int
          let i = parseInt(Math.floor(Math.log(bytes) / 
           Math.log(1024)));
        // Round to 2 decimal places and select the 
           appropriate unit from the array
         output = Math.round(bytes / Math.pow(1024, i), 2)   
         + ' ' + this.byteSizes[i];
       }

       return output
      }
    },

     created() {
       this.d.filesGetTemporaryLink({path:   
       this.f.path_lower}).then(data => {
         this.link = data.link;
       });
      },
    });

     Vue.component('dropbox-viewer', {
       template: '#dropbox-viewer-template',

     props: {
       path: String
      },

     data() {
       return {
       accessToken: 'XXXX',
       structure: {},
       isLoading: true
     }
    },

     methods: {
      dropbox() {
        return new Dropbox({
          accessToken: this.accessToken
        });
      },

     getFolderStructure(path) { 
      this.dropbox().filesListFolder({
        path: path, 
        include_media_info: true
      })
      .then(response => {

        const structure = {
          folders: [],
          files: []
        }

        for (let entry of response.entries) {
          // Check ".tag" prop for type
          if(entry['.tag'] == 'folder') {
            structure.folders.push(entry);
          } else {
            structure.files.push(entry);
          }
        }

          this.structure = structure;
          this.isLoading = false;
        })
        .catch(error => {
         this.isLoading = 'error';
         console.log(error);
        });
     },

     updateStructure(path) {
       this.isLoading = true;
       this.getFolderStructure(path);
      }
    },

    created() {
     this.getFolderStructure(this.path);
    },

   watch: {
     path() {
       this.updateStructure(this.path);
       }
     },
  });

     const app = new Vue({
      el: '#app',

       data: {
       path: ''
      }, 
    methods: {
     updateHash() {
        let hash = window.location.hash.substring(1);
        this.path = (hash || '');
      }
    },
     created() {
      this.updateHash()
     }
  });

   window.onhashchange = () => {
   app.updateHash();
 }
```

# 总结

我们现在有一个完全功能的 Dropbox 查看器应用程序，具有文件夹导航和文件下载链接。我们可以使用文件夹链接或面包屑进行导航，并使用后退和/或前进按钮。我们还可以共享或书签一个链接，并加载该文件夹的内容。

在第六章《使用 Vuex 缓存当前文件夹结构》中，我们将通过使用 Vuex 缓存当前文件夹的内容来加快导航过程。


# 第六章：使用 Vuex 缓存当前文件夹结构

在本章中，我们将介绍一个名为 Vuex 的官方 Vue 插件。Vuex 是一种状态管理模式和库，允许您为所有 Vue 组件创建一个集中的存储，无论它们是子组件还是 Vue 实例。它为我们提供了一种集中、简单的方式来保持整个应用程序中的数据同步。

本章将涵盖以下内容：

+   开始使用 Vuex

+   从 Vuex 存储中存储和检索数据

+   将 Vuex 与我们的 Dropbox 应用程序集成

+   缓存当前 Dropbox 文件夹内容，并在需要时从存储中加载数据

不再需要在每个组件上使用自定义事件和`$emit`函数，并尝试保持组件和子组件的更新，您的 Vue 应用程序的每个部分都可以更新中央存储，并且其他部分可以根据该信息来更新其数据和状态。它还为我们提供了一个共同的存储数据的地方，因此，我们不再需要决定将数据对象放在组件、父组件还是 Vue 实例上更具语义性，我们可以使用 Vuex 存储。

Vuex 还集成到 Vue 开发工具中，这将在第十二章“使用 Vue 开发工具和测试您的 SPA”中介绍。通过集成该库，可以轻松调试和查看存储的当前状态和过去状态。开发工具反映状态变化或数据更新，并允许您检查存储的每个部分。

如前所述，Vuex 是一种状态管理模式，是 Vue 应用程序的真相来源。例如，跟踪购物篮或已登录用户对于某些应用程序至关重要，如果这些数据在组件之间不同步，可能会造成严重问题。而且，如果没有使用父组件来处理数据交换，就无法在子组件之间传递数据。Vuex 通过处理数据的存储、变化和操作来解决这个问题。

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/cpl-vue2-web-dev/img/02e6fa58-a9f3-4654-88d4-7747265331a2.png)

当初次使用 Vuex 时，它可能看起来相当冗长，似乎超出了所需的范围；然而，这是一个很好的例子，可以帮助我们熟悉该库。有关 Vuex 的更多信息可以在其文档中找到。

对于我们的 Dropbox 应用程序，Vuex store 可以用来存储文件夹结构、文件列表和下载链接。这意味着如果用户多次访问同一个文件夹，API 将不需要再次查询，因为所有的信息已经存储好了。这将加快文件夹的导航速度。

# 包含和初始化 Vuex

Vuex 库的包含方式与 Vue 本身相同。您可以使用之前提到的 unpkg 服务（[`unpkg.com/vuex`](https://unpkg.com/vuex)）使用托管版本，或者您可以从他们的[`github.com/vuejs/vuex`](https://github.com/vuejs/vuex)下载 JavaScript 库。

在 HTML 文件的底部添加一个新的`<script>`块。确保在应用程序 JavaScript 之前，Vuex 库被包含在`vue.js`库之后：

```js
<script type="text/javascript" src="js/vue.js"></script>
<script type="text/javascript" src="js/vuex.js"></script>
<script type="text/javascript" src="js/dropbox.js"></script>
<script type="text/javascript" src="js/app.js"></script>
```

如果您正在部署一个包含多个 JavaScript 文件的应用程序，值得研究一下是将它们合并压缩成一个文件更高效，还是配置服务器使用 HTTP/2 推送。

在包含了库之后，我们可以初始化并在我们的应用程序中包含 store。创建一个名为`store`的新变量，并初始化`Vuex.Store`类，并将其赋值给该变量：

```js
const store = new Vuex.Store({

});
```

初始化了 Vuex store 之后，我们现在可以使用`store`变量来利用其功能。使用`store`，我们可以访问其中的数据，并通过 mutations 来修改这些数据。通过一个独立的`store`，许多 Vue 实例可以更新同一个`store`；这在某些情况下可能是需要的，但在其他情况下可能是一个不希望的副作用。

为了绕过这个问题，我们可以将一个 store 与特定的 Vue 实例关联起来。通过将`store`变量传递给我们的 Vue 类来实现这一点。这样做也会将`store`实例注入到所有的子组件中。虽然对于我们的应用程序来说并不是必需的，但将 store 与应用程序关联起来是一个好的实践习惯：

```js
const app = new Vue({
  el: '#app',

  store,
  data: {
    path: ''
  }, 
  methods: {
    updateHash() {
      let hash = window.location.hash.substring(1);
      this.path = (hash || '');
    }
  },
  created() {
    this.updateHash()
  }
});
```

添加了`store`变量后，我们现在可以使用`this.$store`变量在我们的组件中访问`store`了。

# 利用 store

为了帮助我们掌握如何使用 store，让我们将当前存储在父 Vue 实例上的`path`变量移动起来。在我们开始编写和移动代码之前，有一些在使用 Vuex store 时不同的短语和词汇，我们应该熟悉一下：

+   `state`：这是 store 中数据对象的等效部分；原始数据存储在这个对象中。

+   `getters`：这些是 Vuex 中与计算值相当的函数；`store`的函数可以在返回组件中使用之前处理原始状态值。

+   `mutations`：Vuex 不允许直接在`store`之外修改状态对象，必须通过变异处理程序来完成；这些是`store`上的函数，然后允许更新状态。它们始终将`state`作为第一个参数。

这些对象直接属于`store`。但是，更新`store`并不像调用`store.mutationName()`那样简单。相反，我们必须使用一个新的`commit()`函数来调用该方法。此函数接受两个参数：变异的名称和传递给它的数据。

虽然最初很难理解，但 Vuex 存储的冗长性允许强大的功能。以下是一个使用存储的示例，将第一章“开始使用 Vue.js”的原始示例进行了调整：

```js
const store = new Vuex.Store({
  state: {
    message: 'HelLO Vue!'
  },

  getters: {
    message: state => {
      return state.message.toLowerCase();
    }
  },

  mutations: {
    updateMessage(state, msg) {
      state.message = msg;
    }
  }
});
```

前面的`store`示例包括`state`对象，这是我们的原始数据存储；`getters`对象，其中包括我们对状态的处理；最后，`mutations`对象，允许我们更新消息。请注意，`message` getter 和`updateMessage`变异都将存储的状态作为第一个参数。

要使用此`store`，您可以执行以下操作：

```js
new Vue({
  el: '#app',

  store,
  computed: {
    message() {
      return this.$store.state.message
    },
    formatted() {
      return this.$store.getters.message
    }
  }
});
```

# 检索消息

在`{{ message }}`计算函数中，我们从状态对象中检索了原始的、未经处理的消息，并使用了以下路径：

```js
this.$store.state.message
```

这实际上是访问`store`，然后是状态对象，然后是消息对象键。

类似地，`{{ formatted }}`计算值使用`store`中的 getter，将字符串转换为小写。这是通过访问`getters`对象来检索的：

```js
this.$store.getters.message
```

# 更新消息

要更新消息，您需要调用`commit`函数。这将接受方法名称作为第一个参数，负载或数据作为第二个参数。负载可以是简单变量、数组或对象，如果需要传递多个变量，则可以使用对象。

`store`中的`updateMessage`变异接受一个参数，并将消息设置为相等，因此要更新我们的消息，代码应该是：

```js
store.commit('updateMessage', 'VUEX Store');
```

这可以在应用程序的任何地方运行，并且将自动更新之前使用的值，因为它们都依赖于相同的`store`。

现在返回我们的消息 getter 将返回 VUEX Store，因为我们已经更新了状态。考虑到这一点，让我们更新我们的应用程序，使用`store`中的路径变量，而不是 Vue 实例。

# 使用 Vuex store 来获取文件夹路径

在使用 Vue store 作为全局 Dropbox 路径变量的第一步是将数据对象从 Vue 实例移动到`Store`，并将其重命名为`state`：

```js
const store = new Vuex.Store({
  state: {
 path: ''
 }
});
```

我们还需要创建一个 mutation，以允许从 URL 的哈希值更新路径。在 store 中添加一个`mutations`对象，并将`updateHash`函数从 Vue 实例中移动-不要忘记更新函数以接受 store 作为第一个参数。还要更改方法，使其更新`state.path`而不是`this.path`：

```js
const store = new Vuex.Store({
  state: {
    path: ''
  },
  mutations: {
 updateHash(state) {
 let hash = window.location.hash.substring(1);
 state.path = (hash || '');
 }
 }
});
```

通过将路径变量和 mutation 移动到 store 中，可以使 Vue 实例变得更小，同时删除`methods`和`data`对象：

```js
const app = new Vue({
  el: '#app',

  store,
  created() {
    this.updateHash()
  }
});
```

我们现在需要更新我们的应用程序，使用`store`中的路径变量，而不是在 Vue 实例上。我们还需要确保调用`store`的`mutation`函数来更新路径变量，而不是在 Vue 实例上的方法。

# 更新路径方法以使用 store commits

从 Vue 实例开始，将`this.Updatehash`更改为`store.commit('updateHash')`。不要忘记还要更新`onhashchange`函数中的方法。第二个函数应该引用我们 Vue 实例上的`store`对象，而不是直接引用`store`。这可以通过访问 Vue 实例变量`app`，然后在此实例中引用 Vuex store 来完成。

在 Vue 实例上引用 Vuex store 时，它保存在变量`$store`下，无论最初对该变量进行了什么样的声明：

```js
const app = new Vue({
  el: '#app',

  store,
  created() {
    store.commit('updateHash');
  }
});

window.onhashchange = () => {
  app.$store.commit('updateHash');
}
```

# 使用路径变量

我们现在需要更新组件，使用`store`中的路径，而不是通过组件传递的路径。`breadcrumb`和`dropbox-viewer`都需要更新以接受这个新变量。我们还可以从组件中删除不必要的 props。

# 更新面包屑组件

从 HTML 中删除`:p` prop，只留下一个简单的面包屑 HTML 标签：

```js
<breadcrumb></breadcrumb>
```

接下来，从 JavaScript 文件中删除组件的`props`对象。`parts`变量也需要更新为使用`this.$store.state.path`，而不是`this.p`：

```js
Vue.component('breadcrumb', {
  template: '<div>' +
    '<span v-for="(f, i) in folders">' +
      '<a :href="f.path">[F] {{ f.name }}</a>' +
      '<i v-if="i !== (folders.length - 1)"> &raquo; </i>' +
    '</span>' + 
  '</div>',

  computed: {
    folders() {
      let output = [],
        slug = '',
        parts = this.$store.state.path.split('/');

      for (let item of parts) {
        slug += item;
        output.push({'name': item || 'home', 'path': '#' + slug});
        slug += '/';
      }

      return output;
    }
  }
});
```

# 更新 dropbox-viewer 组件以与 Vuex 一起使用

与`breadcrumb`组件一样，第一步是从视图中删除 HTML 属性。这将进一步简化您的应用程序视图，您将只剩下一些 HTML 标签：

```js
<div id="app">
  <dropbox-viewer></dropbox-viewer>
</div>
```

下一步是清理 JavaScript 代码，删除任何不必要的函数参数。从`dropbox-viewer`组件中删除`props`对象。接下来，更新`getFolderStructure`中的`filesListFolder` Dropbox 方法，以使用存储路径，而不是使用路径变量：

```js
this.dropbox().filesListFolder({
  path: this.$store.state.path, 
  include_media_info: true
})
```

由于该方法现在使用`store`而不是函数参数，我们可以从方法声明本身中删除变量，以及从`updateStructure`方法和调用这两个函数的任何地方删除它。例如：

```js
updateStructure(path) {
  this.isLoading = true;
  this.getFolderStructure(path);
}
```

这将变成以下内容：

```js
updateStructure() {
  this.isLoading = true;
  this.getFolderStructure();
}
```

然而，我们仍然需要将路径存储为此组件上的变量。这是由于我们的`watch`方法调用了`updateStructure`函数。为此，我们需要将路径存储为计算值，而不是固定变量。这样，当`store`更新时，它可以动态更新，而不是在组件初始化时固定值。

在`dropbox-viewer`组件上创建一个计算对象，其中包含一个名为`path`的方法，该方法只返回`store`的路径：

```js
computed: {
  path() {
    return this.$store.state.path
  }
}
```

现在我们将其作为局部变量，因此 Dropbox 的`filesListFolder`方法可以更新为再次使用`this.path`。

新更新的`dropbox-viewer`组件应如下所示。在浏览器中查看应用程序时，它应该看起来好像没有任何变化-然而，应用程序的内部工作现在依赖于新的 Vuex 存储，而不是存储在 Vue 实例上的变量。

```js
Vue.component('dropbox-viewer', {
  template: '#dropbox-viewer-template',

  data() {
    return {
      accessToken: 'XXXX',
      structure: {},
      isLoading: true
    }
  },

  computed: {
 path() {
 return this.$store.state.path
 }
 },

  methods: {
    dropbox() {
      return new Dropbox({
        accessToken: this.accessToken
      });
    },

    getFolderStructure() { 
      this.dropbox().filesListFolder({
        path: this.path, 
        include_media_info: true
      })
      .then(response => {

        const structure = {
          folders: [],
          files: []
        }

        for (let entry of response.entries) {
          // Check ".tag" prop for type
          if(entry['.tag'] == 'folder') {
            structure.folders.push(entry);
          } else {
            structure.files.push(entry);
          }
        }

        this.structure = structure;
        this.isLoading = false;
      })
      .catch(error => {
        this.isLoading = 'error';
        console.log(error);
      });
    },

    updateStructure() {
      this.isLoading = true;
      this.getFolderStructure();
    }
  },

  created() {
    this.getFolderStructure();
  },

  watch: {
    path() {
      this.updateStructure();
    }
  },
});
```

# 缓存文件夹内容

现在我们在应用程序中使用 Vuex 并利用它来获取路径，我们可以开始考虑存储当前显示文件夹的内容，以便如果用户返回到相同的位置，API 不需要查询以检索结果。我们将通过将 API 返回的对象存储在 Vuex 存储中来实现这一点。

当请求文件夹时，应用程序将检查存储中是否存在数据。如果存在，则省略 API 调用，并从存储中加载数据。如果不存在，则查询 API 并将结果保存在 Vuex 存储中。

第一步是将数据处理分离到自己的方法中。这是因为文件和文件夹需要被拆分，无论数据是来自存储还是 API。

在`dropbox-viewer`组件中创建一个名为`createFolderStructure()`的新方法，并将代码从 Dropbox 的`filesListFolder`方法的`then()`函数内移动到其中。在这个函数内调用新方法。

现在你的两个方法应该如下所示，并且你的应用程序应该像之前一样工作：

```js
createFolderStructure(response) {
  const structure = {
    folders: [],
    files: []
  }

  for (let entry of response.entries) {
    // Check ".tag" prop for type
    if(entry['.tag'] == 'folder') {
      structure.folders.push(entry);
    } else {
      structure.files.push(entry);
    }
  }

  this.structure = structure;
  this.isLoading = false;
},

getFolderStructure() { 
  this.dropbox().filesListFolder({
    path: this.path, 
    include_media_info: true
  })
  .then(this.createFolderStructure)
  .catch(error => {
    this.isLoading = 'error';
    console.log(error);
  });
}
```

使用 promises，我们可以将`createFolderStructure`作为 API 调用的操作。

下一步是存储我们正在处理的数据。为此，我们将利用将对象传递给`store`的`commit`函数的能力，并使用路径作为存储对象中的键。我们将不再嵌套文件结构，而是将信息存储在一个扁平的结构中。例如，在我们浏览了几个文件夹之后，我们的存储将如下所示：

```js
structure: {
  'images': [{...}],
  'images-holiday': [{...}],
  'images-holiday-summer': [{...}]
}
```

路径将进行几个转换，以使其适合作为对象键。它将被转换为小写，并删除任何标点符号。我们还将用连字符替换所有空格和斜杠。

首先，在 Vuex 存储状态对象中创建一个名为`structure`的空对象；这是我们将存储数据的地方：

```js
state: {
  path: '',
  structure: {}
}
```

现在，我们需要创建一个新的`mutation`，以便在加载数据时存储它。在`mutations`对象中创建一个名为`structure`的新函数。它需要接受`state`作为参数，以及一个作为对象传递的`payload`变量：

```js
structure(state, payload) {
}
```

路径对象将包括一个`path`变量和从 API 返回的`data`。例如：

```js
{
  path: 'images-holiday',
  data: [{...}]
}
```

通过传入这个对象，我们可以使用路径作为键，数据作为值。将数据存储在突变中的路径键内：

```js
structure(state, payload) {
  state.structure[payload.path] = payload.data;
}
```

我们现在可以在组件的`createFolderStructure`方法的末尾提交这些数据：

```js
createFolderStructure(response) {
  const structure = {
    folders: [],
    files: []
  }

  for (let entry of response.entries) {
    // Check ".tag" prop for type
    if(entry['.tag'] == 'folder') {
      structure.folders.push(entry);
    } else {
      structure.files.push(entry);
    }
  }

  this.structure = structure;
  this.isLoading = false;

 this.$store.commit('structure', {
 path: this.path,
 data: response
 });
}
```

现在，当浏览应用程序时，它将存储每个文件夹的数据。可以通过在结构突变中添加`console.log(state.structure)`来验证这一点。

虽然目前的代码可以工作，但最好在将路径用作对象键时对其进行清理。为此，我们将删除任何标点符号，将任何空格和斜杠替换为连字符，并将路径转换为小写。

在`dropbox-viewer`组件上创建一个名为`slug`的新计算函数。术语 slug 通常用于清理过的 URL，并源自报纸和编辑如何引用故事的方式。此函数将运行多个 JavaScript `replace`方法来创建一个安全的对象键：

```js
slug() {
  return this.path.toLowerCase()
    .replace(/^\/|\/$/g, '')
    .replace(/ /g,'-')
    .replace(/\//g,'-')
    .replace(/[-]+/g, '-')
    .replace(/[^\w-]+/g,'');
}
```

slug 函数执行以下操作。例如路径`/images/iPhone/mom's Birthday - 40th`将受到以下影响：

+   将字符串转换为小写：`/images/iphone/mom's birthday - 40th`

+   删除路径开头和结尾的任何斜杠：`images/iphone/mom birthday - 40th`

+   将任何空格替换为连字符：`images/iphone/mom-birthday---40th`

+   将任何斜杠替换为连字符：`images-iphone-mom-birthday---40th`

+   将任何多个连字符替换为单个连字符：`images-iphone-mom-birthday-40th`

+   最后，删除任何标点符号：`images-iphone-moms-birthday-40th`

现在创建了 slug，我们可以将其用作存储数据时的键：

```js
this.$store.commit('structure', {
  path: this.slug,
  data: response
});
```

现在，我们的文件夹内容已经被缓存在 Vuex 存储中，我们可以添加一个检查，看看数据是否存在于存储中，如果存在，则从存储中加载数据。

# 如果存在，则从存储中加载数据

从存储中加载数据需要对我们的代码进行一些更改。第一步是检查`store`中是否存在结构，如果存在，则加载它。第二步是仅在数据是新数据时将数据提交到存储中-调用现有的`createFolderStructure`方法将更新结构，但也会重新提交数据到存储中。尽管当前情况下对用户没有害处，但不必要地将数据写入`store`可能会在应用程序增长时引发问题。这也将在我们进行预缓存文件夹和文件时对我们有所帮助。

# 从存储中加载数据

由于`store`是一个 JavaScript 对象，而我们的`slug`变量是组件上的一个计算值，我们可以使用`if`语句来检查对象键是否存在：

```js
if(this.$store.state.structure[this.slug]) {
  // The data exists
}
```

这使我们可以根据需要从`store`加载数据，使用`createFolderStructure`方法，如果不存在，则触发 Dropbox API 调用。

更新`getFolderStructure`方法以包含`if`语句，并在数据存在时添加方法调用：

```js
getFolderStructure() {
  if(this.$store.state.structure[this.slug]) {
 this.createFolderStructure(this.$store.state.structure[this.slug]);
 } else {
    this.dropbox().filesListFolder({
      path: this.path, 
      include_media_info: true
    })
    .then(this.createFolderStructure)
    .catch(error => {
      this.isLoading = 'error';
      console.log(error);
    });
  }
}
```

数据的路径非常长，可能会导致我们的代码难以阅读。为了更容易理解，将数据赋值给一个变量，这样我们可以检查它是否存在，并使用更清晰、更简洁、更少重复的代码返回数据。这也意味着如果数据路径发生变化，我们只需要更新一行代码：

```js
getFolderStructure() {
  let data = this.$store.state.structure[this.slug]; 
  if(data) {
    this.createFolderStructure(data);
  } else {
    this.dropbox().filesListFolder({
      path: this.path, 
      include_media_info: true
    })
    .then(this.createFolderStructure)
    .catch(error => {
      this.isLoading = 'error';
      console.log(error);
    });
  }
}
```

# 仅存储新数据

如前所述，当前的`createFolderStructure`方法既显示结构，又将响应缓存到`store`中，因此即使从缓存中加载数据，也会重新保存结构。

创建一个新的方法，当数据加载完成后，Dropbox API 将调用该方法。将其命名为`createStructureAndSave`。该方法应该只接受一个参数，即`response`变量：

```js
createStructureAndSave(response) {

}
```

现在，我们可以将`store`的`commit`函数从`createFolderStructure`方法中移动到这个新方法中，同时调用现有方法并传递数据：

```js
createStructureAndSave(response) {

  this.createFolderStructure(response)

 this.$store.commit('structure', {
 path: this.slug,
 data: response
 });
}
```

最后，更新 Dropbox API 函数以调用此方法：

```js
getFolderStructure() {
  let data = this.$store.state.structure[this.slug]; 
  if(data) {
    this.createFolderStructure(data);
  } else {
    this.dropbox().filesListFolder({
      path: this.path, 
      include_media_info: true
    })
    .then(this.createStructureAndSave)
    .catch(error => {
      this.isLoading = 'error';
      console.log(error);
    });
  }

},
```

在浏览器中打开应用程序并浏览文件夹。当您使用面包屑导航返回上一级时，响应速度应该更快，因为它现在是从您创建的缓存中加载，而不是每次查询 API。

在第七章《预缓存其他文件夹和文件以加快导航速度》中，我们将研究预缓存文件夹，以尝试预测用户接下来的操作。我们还将研究缓存文件的下载链接。

我们的完整应用程序 JavaScript 现在应该如下所示：

```js
Vue.component('breadcrumb', {
  template: '<div>' +
    '<span v-for="(f, i) in folders">' +
      '<a :href="f.path">[F] {{ f.name }}</a>' +
      '<i v-if="i !== (folders.length - 1)"> &raquo; </i>' +
    '</span>' + 
  '</div>',
  computed: {
    folders() {
      let output = [],
        slug = '',
        parts = this.$store.state.path.split('/');

      for (let item of parts) {
        slug += item;
        output.push({'name': item || 'home', 'path': '#' + slug});
        slug += '/';
      }

      return output;
    }
  }
});

Vue.component('folder', {
  template: '<li><strong><a :href="\'#\' + f.path_lower">{{ f.name }}</a></strong></li>',
  props: {
    f: Object
  }
});

Vue.component('file', {
  template: '<li><strong>{{ f.name }}</strong><span v-if="f.size"> - {{ bytesToSize(f.size) }}</span> - <a v-if="link" :href="link">Download</a></li>',
  props: {
    f: Object,
    d: Object
  },

  data() {
    return {
      byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB'],
      link: false
    }
  },

  methods: {
    bytesToSize(bytes) {
      // Set a default
      let output = '0 Byte';

      // If the bytes are bigger than 0
      if (bytes > 0) {
        // Divide by 1024 and make an int
        let i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
        // Round to 2 decimal places and select the appropriate unit from the array
        output = Math.round(bytes / Math.pow(1024, i), 2) + ' ' + this.byteSizes[i];
      }

      return output
    }
  },

  created() {
    this.d.filesGetTemporaryLink({path: this.f.path_lower}).then(data => {
      this.link = data.link;
    });
  },
});

Vue.component('dropbox-viewer', {
  template: '#dropbox-viewer-template',

  data() {
    return {
      accessToken: 'XXXX',
      structure: {},
      isLoading: true
    }
  },

  computed: {
    path() {
      return this.$store.state.path
    },
    slug() {
      return this.path.toLowerCase()
        .replace(/^\/|\/$/g, '')
        .replace(/ /g,'-')
        .replace(/\//g,'-')
        .replace(/[-]+/g, '-')
        .replace(/[^\w-]+/g,'');
    }
  },

  methods: {
    dropbox() {
      return new Dropbox({
        accessToken: this.accessToken
      });
    },

    createFolderStructure(response) {

      const structure = {
        folders: [],
        files: []
      }

      for (let entry of response.entries) {
        // Check ".tag" prop for type
        if(entry['.tag'] == 'folder') {
          structure.folders.push(entry);
        } else {
          structure.files.push(entry);
        }
      }

      this.structure = structure;
      this.isLoading = false;

    },

    createStructureAndSave(response) {

      this.createFolderStructure(response)

      this.$store.commit('structure', {
        path: this.slug,
        data: response
      });
    },

    getFolderStructure() {
      let data = this.$store.state.structure[this.slug]; 
      if(data) {
        this.createFolderStructure(data);
      } else {
        this.dropbox().filesListFolder({
          path: this.path, 
          include_media_info: true
        })
        .then(this.createStructureAndSave)
        .catch(error => {
          this.isLoading = 'error';
          console.log(error);
        });
      }

    },

    updateStructure() {
      this.isLoading = true;
      this.getFolderStructure();
    }
  },

  created() {
    this.getFolderStructure();
  },

  watch: {
    path() {
      this.updateStructure();
    }
  },
});

const store = new Vuex.Store({
  state: {
    path: '',
    structure: {}
  },
  mutations: {
    updateHash(state) {
      let hash = window.location.hash.substring(1);
      state.path = (hash || '');
    },
    structure(state, payload) {
      state.structure[payload.path] = payload.data;
    }
  }
});

const app = new Vue({
  el: '#app',

  store,
  created() {
    store.commit('updateHash');
  }
});

window.onhashchange = () => {
  app.$store.commit('updateHash');
}
```

# 摘要

在本章之后，您的应用程序现在应该与 Vuex 集成，并缓存 Dropbox 文件夹的内容。Dropbox 文件夹路径也应该利用`store`来使应用程序更高效。我们只在需要时查询 API。

在[第七章](https://cdp.packtpub.com/vue_js_by_example/wp-admin/post.php?post=71&action=edit#post_82)中，《预缓存其他文件夹和文件以加快导航速度》，我们将研究预缓存文件夹-预先查询 API 以加快应用程序的导航和可用性。
