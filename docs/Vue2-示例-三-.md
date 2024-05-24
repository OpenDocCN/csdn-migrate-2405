# Vue2 示例（三）

> 原文：[`zh.annas-archive.org/md5/e39af983af3c7de00776f3c773ad8d42`](https://zh.annas-archive.org/md5/e39af983af3c7de00776f3c773ad8d42)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：预缓存其他文件夹和文件以实现更快的导航

在本章中，本节的最后一部分，我们将通过引入更多的缓存来进一步加快我们的 Dropbox 文件浏览器的速度。到目前为止，我们已经构建了一个可以查询 Dropbox API 并返回文件和文件夹的应用程序。从那里开始，我们添加了文件夹导航，包括更新用于链接共享的 URL 以及能够使用后退和前进按钮。有了这个功能，在第六章中，我们引入了 Vuex 来存储当前文件夹路径和我们访问过的文件夹的内容。

本章将讨论以下内容：

+   预缓存不仅用户当前所在的文件夹，还包括子文件夹。这将通过循环遍历当前显示的文件夹并检查它们是否已经被缓存来完成。如果没有，我们可以从 API 中获取数据。

+   如果用户通过直接 URL 进入，存储父文件夹的内容。这将通过利用面包屑路径向上遍历树来完成。

+   缓存文件的下载链接。目前，无论文件夹是否已被我们的代码缓存，都需要为每个遇到的文件调用 API。

通过这些改进，我们可以确保应用程序每个项目只与 API 联系一次，而不是像最初那样无数次。

# 缓存子文件夹

通过子文件夹和父文件夹缓存，我们不一定需要编写新代码，而是将现有代码重新组织和重新用途化为一个更模块化的系统，以便可以单独调用每个部分。

以下流程图应该帮助您可视化缓存当前文件夹和子文件夹所需的步骤：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00012.jpeg)

在查看流程图时，您可以立即看到应用程序所需的事件中存在一些重复。在两个点上，应用程序需要决定缓存中是否存在一个文件夹，如果不存在，则查询 API 以获取数据并存储结果。尽管在流程图上只出现两次，但这个功能需要多次，每次都需要针对当前位置的每个文件夹。

我们还需要将显示逻辑与查询和存储逻辑分开，因为我们可能需要从 API 加载并存储，而不更新视图。

# 计划应用程序方法

考虑到前一节的内容，我们可以借此机会修订和重构我们的`dropbox-viewer`应用程序上的方法，确保每个操作都有自己的方法。这样我们就可以在需要时调用每个操作。在进入代码之前，让我们根据前面的流程图规划出需要创建的方法。

首先要注意的是，每次查询 API 时，我们都需要将结果存储在缓存中。由于我们不需要在缓存中存储任何内容，除非调用 API，我们可以将这两个操作合并在同一个方法中。我们还经常需要检查特定路径的缓存中是否有内容，并根据需要加载或从 API 中检索它。我们可以将此添加到自己的方法中返回数据。

让我们绘制出我们需要创建的方法：

+   `getFolderStructure`：此方法将接受路径的单个参数，并返回文件夹条目的对象。它将负责检查数据是否在缓存中，如果不在，则查询 Dropbox API。

+   `displayFolderStructure`：此方法将触发前面的函数，并使用数据更新组件上的`structure`对象，以显示视图中的文件和文件夹。

+   `cacheFolderStructure`：此方法将包含`getFolderStructure`方法以缓存每个子文件夹-我们将探讨几种触发此方法的方式。

我们可能需要创建更多的方法，但这三个方法将是组件的主干。我们将保留路径和 slug-computed 属性以及`dropbox()`方法。删除其余的对象、方法和函数，使您的`dropbox-viewer`回到基本状态：

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
  }
});
```

# 创建`getFolderStructure`方法

在组件上创建一个名为`getFolderStructure`的新方法。如前所述，此方法需要接受一个路径参数。这样我们就可以同时使用当前路径和子路径：

```js
getFolderStructure(path) {

}
```

此方法需要检查缓存并返回数据。在方法内部创建一个名为`output`的新变量，并返回它：

```js
getFolderStructure(path) {
 let output;

 return output;
}
```

在[第六章](https://cdp.packtpub.com/vue_js_by_example/wp-admin/post.php?post=82&action=edit#post_71)中缓存数据时，我们使用`slug`作为存储中的键。`slug`是通过使用当前路径生成的；然而，我们不能在新方法中使用它，因为它固定在其当前位置。

创建一个名为`generateSlug`的新方法。它将接受一个参数，即路径，并返回使用 slug-computed 函数中的替换后的字符串：

```js
generateSlug(path) {
  return path.toLowerCase()
    .replace(/^\/|\/$/g, '')
    .replace(/ /g,'-')
    .replace(/\//g,'-')
    .replace(/[-]+/g, '-')
    .replace(/[^\w-]+/g,'');
}
```

现在我们可以删除计算的`slug`函数，这样我们就不会有重复的代码了。

回到我们的`getFolderStructure`方法，创建一个新变量，使用新方法存储路径的 slug 版本。为此，我们将使用`const`创建一个不可更改的变量。

```js
getFolderStructure(path) {
  let output;

  const slug = this.generateSlug(path);

  return output;
}
```

我们将创建的最后一个变量是数据路径，就像我们在第八章中所做的那样，*介绍 Vue-Router 和加载基于 URL 的组件*。这将使用我们刚刚创建的新`slug`变量：

```js
getFolderStructure(path) {
  let output;

  const slug = this.generateSlug(path),
      data = this.$store.state.structure[slug];

  return output;
}
```

现在我们可以在这里使用先前代码中的`data` `if`语句，其中包含 Dropbox 函数调用的空间。如果存储中存在`data`，我们可以立即将其分配给`output`：

```js
getFolderStructure(path) {
  let output;

  const slug = this.generateSlug(path),
      data = this.$store.state.structure[slug];

 if(data) {
 output = data;
 } else {

 }

  return output;
}
```

然而，通过 Dropbox API 调用，我们可以对其进行调整以适应这段新代码。之前，它是从 API 中检索数据，然后触发一个方法来保存和显示结构。由于我们需要将检索到的数据存储在`output`变量中，我们将改变数据的流动方式。我们将不再触发一个方法，而是利用这个机会首先将响应存储在缓存中，然后将数据返回给`output`变量。

由于我们只使用 API 调用的条目，我们还将更新存储以仅缓存响应的这部分。这将减少应用程序的代码和复杂性：

```js
getFolderStructure(path) {
  let output;

  const slug = this.generateSlug(path),
      data = this.$store.state.structure[slug];

  if(data) {
    output = data;
  } else {

    output = this.dropbox().filesListFolder({
 path: path, 
 include_media_info: true
 })
 .then(response => {
 let entries = response.entries;
 this.$store.commit('structure', {
 path: slug,
 data: entries
 });

 return entries;
 })
 .catch(error => {
 this.isLoading = 'error';
 console.log(error);
 });

  }

  return output;
}
```

Dropbox 的`filesListFolder`方法使用传入的`path`变量，而不是之前使用的全局变量。然后，将响应中的条目存储在一个变量中，然后使用相同的 mutation 将其缓存到 Vuex 存储中。然后，`entries`变量从 promise 中返回，将结果存储在`output`中。`catch()`函数与之前相同。

当数据从缓存或 API 返回时，我们可以在组件创建时和路径更新时触发和处理这些数据。然而，在这之前，我们需要处理各种数据类型的混合。

当从 API 返回数据时，数据仍然是一个需要解析的 promise；将其赋值给一个变量只是将 promise 传递给稍后解析。然而，来自存储的数据是一个处理方式完全不同的普通数组。为了给我们一个统一的数据类型来处理，我们将把存储的数组作为 promise 来`resolve`，这意味着`getFolderStructure`无论数据从何处加载，都会返回一个 promise：

```js
getFolderStructure(path) {
  let output;

  const slug = this.generateSlug(path),
      data = this.$store.state.structure[slug];

  if(data) {
    output = Promise.resolve(data);
  } else {

    output = this.dropbox().filesListFolder({
      path: path, 
      include_media_info: true
    })
    .then(response => {
      let entries = response.entries;

      this.$store.commit('structure', {
        path: slug,
        data: entries
      });

      return entries;
    })
    .catch(error => {
      this.isLoading = 'error';
      console.log(error);
    });

  }
  return output;
}
```

有了这个`getFolderStructure`方法，我们现在可以从 API 加载一些数据并将结果存储在全局缓存中，而不更新视图。然而，如果我们希望进一步处理这些信息，该函数会返回这些信息，使用 JavaScript promise。

我们现在可以继续创建我们的下一个方法`displayFolderStructure`，它将使用我们刚刚创建的方法的结果并更新我们的视图，以便应用程序可以再次进行导航。

# 使用`displayFolderStructure`方法显示数据。

现在我们的数据已经准备好被缓存并从存储中提供，我们可以继续使用我们的新方法*display*数据。在`dropbox-viewer`组件中创建一个名为`displayFolderStructure`的新方法：

```js
displayFolderStructure() {

} 
```

这个方法将从之前版本的组件中借用很多代码。请记住，这个方法仅用于显示文件夹，与缓存内容无关。

该方法的过程如下：

1.  将应用程序的加载状态设置为`active`。这让用户知道有事情正在发生。

1.  创建一个空的`structure`对象。

1.  加载`getFolderStructure`方法的内容。

1.  循环遍历结果，并将每个项目添加到`folders`或`files`数组中。

1.  将全局结构对象设置为新创建的对象。

1.  将加载状态设置为`false`，以便可以显示内容。

# 将加载状态设置为 true，并创建一个空的结构对象

该方法的第一步是隐藏结构树并显示加载消息。这可以像以前一样通过将`isLoading`变量设置为`true`来完成。我们还可以在这里创建一个空的`structure`对象，准备好由数据填充：

```js
displayFolderStructure() {
 this.isLoading = true;

 const structure = {
 folders: [],
 files: []
 }
}
```

# 加载`getFolderStructure`方法的内容。

由于`getFolderStructure`方法返回一个 promise，我们需要在继续操作之前解析结果。这可以通过`.then()`函数来完成；我们已经在 Dropbox 类中使用过这个函数。调用该方法，然后将结果赋值给一个变量：

```js
displayFolderStructure() {
  this.isLoading = true;

  const structure = {
    folders: [],
    files: []
  }

 this.getFolderStructure(this.path).then(data => {

 });
}
```

此代码将组件的`path`对象传递给该方法。此路径是用户正在尝试查看的*当前*路径。一旦返回数据，我们可以将其分配给`data`变量，然后在函数内部使用它。

# 循环遍历结果，并将每个项添加到文件夹或文件数组中。

我们已经熟悉了循环遍历条目并检查每个条目的`.tag`属性的代码。如果结果是文件夹，则将其添加到`structure.folders`数组中，否则将其附加到`structure.files`中。

我们只在缓存中存储条目，因此请确保`for`循环更新为直接使用数据，而不是访问条目的属性：

```js
displayFolderStructure() {
  this.isLoading = true;

  const structure = {
    folders: [],
    files: []
  }

  this.getFolderStructure(this.path).then(data => {

    for (let entry of data) {
 // Check ".tag" prop for type
 if(entry['.tag'] == 'folder') {
 structure.folders.push(entry);
 } else {
 structure.files.push(entry);
 }
 }
  });
}
```

# 更新全局结构对象并删除加载状态

此方法的最后一个任务是更新全局结构并删除加载状态。此代码与之前相同：

```js
displayFolderStructure() {
  this.isLoading = true;

  const structure = {
    folders: [],
    files: []
  }

  this.getFolderStructure(this.path).then(data => {

    for (let entry of data) {
      // Check ".tag" prop for type
      if(entry['.tag'] == 'folder') {
        structure.folders.push(entry);
      } else {
        structure.files.push(entry);
      }
    }

    this.structure = structure;
 this.isLoading = false;
  });
}
```

现在我们有了一个将显示数据检索结果的方法。

# 启动该方法

当创建`dropbox-viewer`组件时，可以调用此方法。由于全局 Vue 实例上的`created`函数将 URL 哈希提交到存储中，从而创建了路径变量，因此路径已经被填充。因此，我们不需要向函数传递任何内容。将`created`函数添加到组件中，并在其中调用新方法：

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
    ...
  },

  methods: {

    ...
  },

 created() {
 this.displayFolderStructure();
 }
});
```

现在刷新应用程序将加载文件夹内容。更新 URL 哈希并重新加载页面也将显示该文件夹的内容；但是，单击任何文件夹链接将更新面包屑，但不会更新数据结构。可以通过监视计算的`path`变量来解决此问题。当哈希更新时，它将被更新，因此可以在`watch`对象中触发一个函数。添加一个函数来监视`path`变量的更新，并在更新时触发新方法：

```js
  created() {
    this.displayFolderStructure();
  },

  watch: {
 path() {
 this.displayFolderStructure();
 }
 }
```

通过这样做，我们创建了一个应用程序，再次缓存您访问过的任何文件夹。第一次点击结构时，速度可能会很慢，但是一旦您返回到树的上层并重新进入子文件夹，您几乎看不到加载屏幕。

尽管该应用程序在本章开始时具有相同的功能，但我们已经重构了代码，将检索和缓存以及数据的显示分开。让我们进一步改进我们的应用程序，通过预缓存所选路径的子文件夹。

# 缓存子文件夹

现在，我们可以在不更新 Vue 的情况下缓存文件夹，使用我们的`structure`对象来获取子文件夹的内容。使用`structure`对象中的`folders`数组，我们可以循环遍历并依次缓存每个文件夹。

我们必须确保不会影响应用程序的性能；缓存必须是异步完成的，这样用户就不会意识到这个过程。我们还需要确保不会不必要地运行缓存。

为了实现这一点，我们可以监视`structure`对象。只有在数据从缓存或 API 加载并且 Vue 已更新后，它才会更新。当用户查看文件夹的内容时，我们可以继续循环遍历文件夹以存储它们的内容。

然而，有一个小问题。如果我们监视`structure`变量，我们的代码将永远不会运行，因为对象的直接*内容*不会更新，尽管我们每次都用一个新的对象替换`structure`对象。从一个文件夹到另一个文件夹，结构对象始终具有两个键，即`files`和`folders`，它们都是数组。就 Vue 和 JavaScript 而言，`structure`对象从不改变。

然而，Vue 可以检测到`deep`变量的嵌套更改。这可以在每个变量的基础上启用。类似于组件上的 props，要在 watch 属性上启用更多选项，您需要将其传递给一个对象，而不是直接的函数。

为结构创建一个新的`watch`键，它是一个包含两个值的对象，`deep`和`handler`。`deep`键将被设置为`true`，而`handler`将是在变量更改时触发的函数：

```js
watch: {
  path() {
    this.displayFolderStructure();
  },

  structure: {
 deep: true,
 handler() {

 }
 }
}
```

在这个`handler`中，我们现在可以循环遍历每个文件夹，并为每个文件夹运行`getFolderStructure`方法，使用每个文件夹的`path_lower`属性作为函数参数：

```js
structure: {
  deep: true,
  handler() {
    for (let folder of this.structure.folders) {
 this.getFolderStructure(folder.path_lower);
 }
  }
}
```

通过这段简单的代码，我们的应用程序似乎加快了十倍。您导航到的每个子文件夹都会立即加载（除非您有一个特别长的文件夹列表，并且您快速导航到最后一个文件夹）。为了让您了解缓存的速度和时间，将`console.log()`添加到您的`getFolderStructure`方法中，并打开浏览器开发者工具：

```js
if(data) {
  output = Promise.resolve(data);
} else {

  console.log(`API query for ${path}`);
  output = this.dropbox().filesListFolder({
    path: path, 
    include_media_info: true
  })
  .then(response => {
    console.log(`Response for ${path}`);

    ... 
```

这样您就可以看到所有的 API 调用也是异步完成的 - 应用程序在移动到下一个文件夹之前不会等待前一个文件夹被加载和缓存。这样做的好处是允许较小的文件夹在等待较大的文件夹从 API 返回之前被缓存。

# 替代缓存方法

与任何事物一样，在创建应用程序时，有许多方法可以实现相同的结果。这种方法的缺点是，即使您的文件夹只包含文件，这个函数也会触发，尽管没有任何操作。

另一种方法是再次使用我们的`created`函数，这次在`folder`组件本身上触发，将路径作为参数触发父级方法。

一种方法是使用`$parent`属性。在`folder`组件中，使用`this.$parent`将允许访问`dropbox-viewer`组件上的变量、方法和计算值。

在`folder`组件中添加一个`created`函数，并从 Dropbox 组件中删除`structure`的`watch`属性。然后，调用父级的`getFolderStructure`方法：

```js
Vue.component('folder', {
  template: '<li><strong><a :href="\'#\' + f.path_lower">{{ f.name }}</a></strong></li>',
  props: {
    f: Object
  },
  created() {
 this.$parent.getFolderStructure(this.f.path_lower);
 }
});
```

预览应用程序证明了这种方法的有效性。只有在结构中有文件夹时才触发，这种更清晰的技术将文件夹缓存与文件夹本身绑定在一起，而不是与 Dropbox 代码混在一起。

然而，除非必要，否则应避免使用`this.$parent`，并且只应在极端情况下使用。由于我们有机会使用 props，我们应该这样做。这还给了我们在文件夹上下文中给函数一个更有意义的名称的机会。

导航到 HTML 视图并更新文件夹组件以接受一个新的 prop。我们将称之为 prop cache，并将函数作为值传递。由于属性是动态的，请不要忘记添加一个前导冒号：

```js
<folder :f="entry" :cache="getFolderStructure"></folder>
```

在 JavaScript 的`folder`组件中，在 props 键中添加`cache`关键字。告诉 Vue 输入将是一个函数：

```js
Vue.component('folder', {
  template: '<li><strong><a :href="\'#\' + f.path_lower">{{ f.name }}</a></strong></li>',
  props: {
    f: Object,
    cache: Function
  }
});
```

最后，在`created`函数中调用我们的新`cache()`方法：

```js
Vue.component('folder', {
  template: '<li><strong><a :href="\'#\' + f.path_lower">{{ f.name }}</a></strong></li>',
  props: {
    f: Object,
    cache: Function
  },
 created() {
 this.cache(this.f.path_lower);
 }
});
```

可以通过使用之前的控制台日志来验证缓存。这样可以创建更清晰的代码，更容易阅读，也更容易让其他开发人员阅读。

现在我们的 Dropbox 应用程序正在进展，我们可以继续缓存父文件夹，如果您使用 URL 中的哈希进入子文件夹。

# 缓存父文件夹

缓存父级结构是我们可以采取的下一个预防措施，以帮助加快应用程序的速度。假设我们已经导航到了我们的图像目录`img/holiday/summer`，并希望与朋友或同事共享。我们会将带有此 URL 的 URL 哈希发送给他们，在页面加载时，他们将看到内容。如果他们然后使用面包屑导航到`img/holiday`，例如，他们需要等待应用程序检索内容。

使用`breadcrumb`组件，我们可以缓存父目录，因此在导航到`holiday`文件夹时，用户将立即看到其内容。当用户浏览此文件夹时，所有子文件夹都会使用先前的方法进行缓存。

为了缓存父文件夹，我们已经有一个组件显示具有访问所有父文件夹的 slug 的路径，我们可以通过面包屑循环遍历。

在开始缓存过程之前，我们需要更新组件中的`folders`计算函数。因为目前我们存储的路径是带有散列前缀的，这会导致 Dropbox API 无效的路径。从被推送到输出数组的对象中删除散列，并在模板中以类似的方式添加它，就像`folder`组件一样：

```js
Vue.component('breadcrumb', {
  template: '<div>' +
    '<span v-for="(f, i) in folders">' +
      '<a :href="\'#\' + f.path">{{ f.name || 'Home' }}</a>' +
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
        output.push({'name': item || 'home', 'path': slug});
        slug += '/';
      }

      return output;
    }
  }
});
```

现在我们可以使用输出来显示面包屑并缓存父级结构。

第一步是让`breadcrumb`组件可以访问缓存函数。类似于`folder`组件，将函数作为一个 prop 添加到你的视图中的`breadcrumb`组件中：

```js
<breadcrumb :cache="getFolderStructure"></breadcrumb>
```

在 JavaScript 代码中为组件添加`props`对象。将`cache`属性声明为一个函数，这样 Vue 就知道要期望什么：

```js
Vue.component('breadcrumb', {
  template: '...',
 props: {
 cache: Function
 },
  computed: {
    folders() {
      ...
  }
});
```

父级结构将在`breadcrumb`组件创建时生成。然而，由于我们不希望这个过程阻塞加载过程，所以我们将在组件被`mounted`而不是`created`时触发它。

在组件中添加一个`mounted`函数，并将文件夹的计算值赋给一个变量：

```js
Vue.component('breadcrumb', {
  template: '...',
  props: {
    cache: Function
  },
  computed: {
    folders() {
      ...
    }
  },
  mounted() {
 let parents = this.folders;
 }
});
```

现在我们需要开始缓存文件夹；然而，我们可以在执行缓存的顺序上做得更聪明。我们可以假设用户通常会返回到文件夹树的上一级，所以我们应该在移动到其父级之前理想情况下先缓存直接父级，依此类推。由于我们的文件夹变量是从上到下的，所以我们需要将其反转。

我们可以做的另一件事是删除当前文件夹；因为我们已经在其中，应用程序已经缓存了它。在组件中，反转数组并删除第一个项目：

```js
mounted() {
  let parents = this.folders;
  parents.reverse().shift();
}
```

如果我们在父变量的函数中添加一个控制台日志，我们可以看到它包含了我们现在希望缓存的文件夹。现在，我们可以循环遍历这个数组，为数组中的每个项目调用`cache`函数：

```js
mounted() {
  let parents = this.folders;
  parents.reverse().shift();

  for(let parent of parents) {
 this.cache(parent.path);
 }
}
```

有了这个，我们的父文件夹和子文件夹都被应用程序缓存，使得导航树的上下移动非常快速。然而，在`mounted`函数内部运行`console.log()`会发现，每次导航到一个文件夹时，面包屑都会重新挂载。这是因为视图中的`v-if`语句会每次删除和添加 HTML。

由于我们只需要在初始加载应用程序时缓存父文件夹一次，让我们考虑更改触发缓存的位置。我们只需要在第一次运行这个函数；一旦用户开始在树上向上和向下导航，沿途访问的所有文件夹都将被缓存。

# 缓存父文件夹一次

为了确保我们使用的资源最少，我们可以将面包屑使用的文件夹数组保存在存储中。这意味着`breadcrumb`组件和我们的父级缓存函数可以访问同一个数组。

在存储状态中添加一个`breadcrumb`键，这是我们将存储数组的地方：

```js
const store = new Vuex.Store({
  state: {
    path: '',
    structure: {},
    breadcrumb: []
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
```

接下来，将`breadcrumb`组件中的代码移到`updateHash`mutation 中，以便我们可以更新`path`和`breadcrumb`变量：

```js
updateHash(state) {
  let hash = window.location.hash.substring(1);
  state.path = (hash || '');

 let output = [],
 slug = '',
 parts = state.path.split('/');

 for (let item of parts) {
 slug += item;
 output.push({'name': item || 'home', 'path': slug});
 slug += '/';
 }

 state.breadcrumb = output;
},
```

请注意，不再返回`output`数组，而是将其存储在`state`对象中。现在，我们可以更新`breadcrumb`组件上的文件夹计算函数，以返回存储的数据：

```js
computed: {
  folders() {
 return this.$store.state.breadcrumb;
 }
}
```

现在，我们可以在`dropbox-viewer`组件上创建一个新的方法`cacheParentFolders`，触发我们为`breadcrumb`组件编写的代码。

在`Dropbox`组件上创建一个新的方法，并将代码移到其中。更新父级的位置，并确保触发正确的路径：

```js
cacheParentFolders() {
  let parents = this.$store.state.breadcrumb;
  parents.reverse().shift();

  for(let parent of parents) {
    this.getFolderStructure(parent.path);
  }
}
```

现在，当创建`Dropbox`组件时，我们可以在`created`函数中调用这个方法一次。在现有的方法调用之后添加它：

```js
created() {
  this.displayFolderStructure();
  this.cacheParentFolders();
}
```

现在，我们可以进行一些清理工作，从`breadcrumb`组件中删除`mounted`方法，以及从视图中删除`props`对象和`:cache`属性。这意味着我们的`breadcrumb`组件现在比以前更简单：

```js
Vue.component('breadcrumb', {
  template: '<div>' +
    '<span v-for="(f, i) in folders">' +
      '<a :href="\'#\' + f.path">{{ f.name || 'Home' }}</a>' +
      '<i v-if="i !== (folders.length - 1)"> &raquo; </i>' +
    '</span>' + 
  '</div>',
  computed: {
    folders() {
      return this.$store.state.breadcrumb;
    }
  }
});
```

HTML 恢复到原来的状态：

```js
<breadcrumb></breadcrumb>
```

我们还可以将存储中的`updateHash`变异变得更整洁和更易理解：

```js
updateHash(state, val) {
  let path = (window.location.hash.substring(1) || ''),
    breadcrumb = [],
    slug = '',
    parts = path.split('/');

  for (let item of parts) {
    slug += item;
    breadcrumb.push({'name': item || 'home', 'path': slug});
    slug += '/';
  }

  state.path = path
  state.breadcrumb = breadcrumb;
}
```

现在所有的变量都在顶部声明，`state`在底部更新。变量的数量也减少了。

现在查看应用程序，它似乎工作正常；然而，仔细检查后，`breadcrumb`在初始页面加载时似乎有点滞后。一旦导航到一个文件夹，它就会追上来，但在第一次加载时，它似乎少了一个项目，而在查看 Dropbox 的根目录时则没有任何项目。

这是因为在我们提交`updateHash`变异之前，存储尚未完全初始化。如果我们回忆一下在第四章中介绍的 Vue 实例生命周期，我们可以看到 created 函数非常早就被触发了。将主 Vue 实例更新为在`mounted`上触发变异可以解决这个问题：

```js
const app = new Vue({
  el: '#app',

  store,
  mounted() {
    store.commit('updateHash');
  }
});
```

所有文件夹都已经被缓存，现在我们可以通过存储每个文件的下载链接来继续缓存更多的 API 调用。

我们还可以尝试缓存子文件夹的子文件夹，通过循环遍历每个缓存文件夹的内容，最终缓存整个树。我们不会详细介绍这个，但可以自己尝试一下。

# 缓存文件的下载链接

当用户在文档树中导航时，Dropbox API 仍然被查询了多次。这是因为每次显示一个文件时，我们都会查询 API 以检索下载链接。通过将下载链接响应存储在缓存中，并在导航回到它所在的文件夹时重新显示，可以减少额外的 API 查询。

每次显示一个文件时，都会使用存储中的数据初始化一个新的组件。我们可以利用这一点，因为这意味着我们只需要更新组件实例，然后结果就会被缓存。

在您的文件组件中，更新 API 响应，不仅将结果保存在数据属性的`link`属性上，还保存在文件实例`f`上。这将作为一个新的键`download_link`存储。

在存储数据时，我们可以将两个单独的命令合并为一个命令，使用两个等号：

```js
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
    this.d.filesGetTemporaryLink({path: this.f.path_lower})
      .then(data => {
        this.f.download_link = this.link = data.link;
      });
  }
});
```

这基本上意味着`this.f.download_link`等于`this.link`，它也等于`data.link`，即来自 API 的下载链接。通过在导航到文件夹时存储和显示此信息，我们可以添加一个`if`语句来检查数据是否存在，如果不存在，则查询 API 获取它。

```js
created() {
  if(this.f.download_link) {
 this.link = this.f.download_link;
 } else {
    this.d.filesGetTemporaryLink({path: this.f.path_lower})
      .then(data => {
        this.f.download_link = this.link = data.link;
      });
  }
}
```

在文件创建时这样做可以避免不必要地查询 API。如果我们在缓存文件夹时获取了这些信息，可能会减慢应用程序的速度并存储非必要的信息。想象一下一个包含数百张照片的文件夹 - 我们不希望为每个照片都查询 API，只是为了用户可能进入该文件夹。

这意味着我们应用程序中的所有内容只需要查询 API 一次以获取信息。用户可以随意在文件夹结构中上下导航，随着操作的进行，应用程序只会变得更快。

# 完整的代码 - 带有附加的文档

完成我们的应用程序后，我们现在可以添加一些非常需要的文档。文档化代码总是很好的，因为它给出了代码的原因和解释。良好的文档不仅应该说明代码做什么，还应该说明为什么这样做，允许什么，不允许什么。

一种常用的文档方法是 JavaScript DocBlock 标准。这套约定规定了一些样式指南，供您在文档化代码时遵循。DocBlock 格式化为注释块，并以`@`开头的关键字为特色，例如`@author`，`@example`，或者使用`@param`关键字列出函数可以接受的参数。一个例子是：

```js
/**
 * Displays a folder with a link and cache its contents
 * @example <folder :f="entry" :cache="getFolderStructure"></folder>
 *
 * @param {object} f The folder entry from the tree
 * @param {function} cache The getFolderStructure method from the dropbox-viewer component
 */
```

首先是一个描述，DocBlock 有几个关键字可以帮助布置文档。我们将通过添加文档来完成我们的 Dropbox 应用程序。

让我们首先看一下`breadcrumb`组件：

```js
/**
 * Displays the folder tree breadcrumb
 * @example <breadcrumb></breadcrumb>
 */
Vue.component('breadcrumb', {
  template: '<div>' +
    '<span v-for="(f, i) in folders">' +
      '<a :href="\'#\' + f.path">{{ f.name || 'Home' }}</a>' +
      '<i v-if="i !== (folders.length - 1)"> &raquo; </i>' +
    '</span>' + 
  '</div>',

  computed: {
    folders() {
      return this.$store.state.breadcrumb;
    }
  }
});
```

继续看`folder`组件：

```js
/**
 * Displays a folder with a link and cache its contents
 * @example <folder :f="entry" :cache="getFolderStructure"></folder>
 *
 * @param {object} f The folder entry from the tree
 * @param {function} cache The getFolderStructure method from the dropbox-viewer component
 */
Vue.component('folder', {
  template: '<li><strong><a :href="\'#\' + f.path_lower">{{ f.name }}</a></strong></li>',
  props: {
    f: Object,
    cache: Function
  },
  created() {
    // Cache the contents of the folder
    this.cache(this.f.path_lower);
  }
});
```

接下来，我们看到`file`组件：

```js
/**
 * File component display size of file and download link
 * @example <file :d="dropbox()" :f="entry"></file>
 * 
 * @param {object} f The file entry from the tree
 * @param {object} d The dropbox instance from the parent component
 */
Vue.component('file', {
  template: '<li><strong>{{ f.name }}</strong><span v-if="f.size"> - {{ bytesToSize(f.size) }}</span> - <a v-if="link" :href="link">Download</a></li>',
  props: {
    f: Object,
    d: Object
  },

  data() {
    return {
      // List of file size
      byteSizes: ['Bytes', 'KB', 'MB', 'GB', 'TB'],

      // The download link
      link: false
    }
  },

  methods: {
    /**
     * Convert an integer to a human readable file size
     * @param {integer} bytes
     * @return {string}
     */
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
    // If the download link has be retrieved from the API, use it
    // if not, aquery the API
    if(this.f.download_link) {
      this.link = this.f.download_link;
    } else {
      this.d.filesGetTemporaryLink({path: this.f.path_lower})
        .then(data => {
          this.f.download_link = this.link = data.link;
        });
    }
  }
});
```

现在我们来看一下`dropbox-viewer`组件：

```js
/**
 * The dropbox component
 * @example <dropbox-viewer></dropbox-viewer>
 */
Vue.component('dropbox-viewer', {
  template: '#dropbox-viewer-template',

  data() {
    return {
      // Dropbox API token
      accessToken: 'XXXX',

      // Current folder structure
      structure: {},
      isLoading: true
    }
  },

  computed: {
    // The current folder path
    path() {
      return this.$store.state.path
    }
  },

  methods: {

    /**
     * Dropbox API instance
     * @return {object}
     */
    dropbox() {
      return new Dropbox({
        accessToken: this.accessToken
      });
    },

    /**
     * @param {string} path The path to a folder
     * @return {string} A cache-friendly URL without punctuation/symbals
     */
    generateSlug(path) {
      return path.toLowerCase()
        .replace(/^\/|\/$/g, '')
        .replace(/ /g,'-')
        .replace(/\//g,'-')
        .replace(/[-]+/g, '-')
        .replace(/[^\w-]+/g,'');
    },

    /**
     * Retrieve the folder structure form the cache or Dropbox API
     * @param {string} path The folder path
     * @return {Promise} A promise containing the folder data
     */
    getFolderStructure(path) {
      let output;

      const slug = this.generateSlug(path),
          data = this.$store.state.structure[slug];

      if(data) {
        output = Promise.resolve(data);
      } else {
        output = this.dropbox().filesListFolder({
          path: path, 
          include_media_info: true
        })
        .then(response => {
          let entries = response.entries;

          this.$store.commit('structure', {
            path: slug,
            data: entries
          });

          return entries;
        })
        .catch(error => {
          this.isLoading = 'error';
          console.log(error);
        });

      }
      return output;
    },

    /**
     * Display the contents of getFolderStructure
     * Updates the output to display the folders and folders
     */
    displayFolderStructure() {
      // Set the app to loading
      this.isLoading = true;

      // Create an empty object
      const structure = {
        folders: [],
        files: []
      }

      // Get the structure
      this.getFolderStructure(this.path).then(data => {

        for (let entry of data) {
          // Check ".tag" prop for type
          if(entry['.tag'] == 'folder') {
            structure.folders.push(entry);
          } else {
            structure.files.push(entry);
          }
        }

        // Update the data object
        this.structure = structure;
        this.isLoading = false;
      });
    },

    /**
     * Loop through the breadcrumb and cache parent folders
     */
    cacheParentFolders() {
      let parents = this.$store.state.breadcrumb;
      parents.reverse().shift();

      for(let parent of parents) {
        this.getFolderStructure(parent.path);
      }
    }
  },

  created() {
    // Display the current path & cache parent folders
    this.displayFolderStructure();
    this.cacheParentFolders();
  },

  watch: {
    // Update the view when the path gets updated
    path() {
      this.displayFolderStructure();
    }
  }
});
```

我们还要检查一下 Vuex 存储：

```js
/**
 * The Vuex Store
 */
const store = new Vuex.Store({
  state: {
    // Current folder path
    path: '',

    // The current breadcrumb
    breadcrumb: [],

    // The cached folder contents
    structure: {},
  },
  mutations: {
    /**
     * Update the path & breadcrumb components
     * @param {object} state The state object of the store
     */
    updateHash(state) {

      let path = (window.location.hash.substring(1) || ''),
        breadcrumb = [],
        slug = '',
        parts = path.split('/');

      for (let item of parts) {
        slug += item;
        breadcrumb.push({'name': item || 'home', 'path': slug});
        slug += '/';
      }

      state.path = path
      state.breadcrumb = breadcrumb;
    },

    /**
     * Cache a folder structure
     * @param {object} state The state objet of the store
     * @param {object} payload An object containing the slug and data to store
     */
    structure(state, payload) {
      state.structure[payload.path] = payload.data;
    }
  }
});
```

我们进一步转到 Vue 应用程序*：*

```js
/**
 * The Vue app
 */
const app = new Vue({
  el: '#app',

  // Initialize the store
  store,

  // Update the current path on page load
  mounted() {
    store.commit('updateHash');
  }
});
```

最后，我们通过`window.onhashchange`函数：

```js
/**
 * Update the path & store when the URL hash changes
 */
window.onhashchange = () => {
  app.$store.commit('updateHash');
}
```

最后，视图中的 HTML 如下所示：

```js
<div id="app">
  <dropbox-viewer></dropbox-viewer>
</div>
```

Dropbox 查看器的模板如下所示：

```js
<script type="text/x-template" id="dropbox-viewer-template">
  <div>
    <h1>Dropbox</h1>

    <transition name="fade">
      <div v-if="isLoading">
        <div v-if="isLoading == 'error'">
          <p>There seems to be an issue with the URL entered.</p>
          <p><a href="">Go home</a></p>
        </div>
        <div v-else>
          Loading...
        </div>
      </div>
    </transition>

    <transition name="fade">
      <div v-if="!isLoading">
        <breadcrumb></breadcrumb>
        <ul>
          <template v-for="entry in structure.folders">
            <folder :f="entry" :cache="getFolderStructure"></folder>
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

您会注意到并非所有内容都已记录。一个简单的函数或变量赋值不需要重新解释它的作用，但是对主要变量的注释将帮助任何查看它的人。

# 总结

在本书的这一部分，我们涵盖了很多内容！我们从查询 Dropbox API 以获取文件和文件夹列表开始。然后我们继续添加导航功能，允许用户点击文件夹并下载文件。接下来，我们介绍了 Vuex 和 store 到我们的应用程序中，这意味着我们可以集中路径、面包屑，最重要的是，缓存文件夹内容。最后，我们看了一下缓存子文件夹和文件下载链接。

在本书的下一部分，我们将看看如何创建一个商店。这将包括使用一个名为 Vue router 的新 Vue 插件浏览类别和产品页面。我们还将研究如何将产品添加到购物篮中，并将产品列表和偏好存储在 Vuex store 中。


# 第八章：介绍 Vue-Router 和基于 URL 加载组件

在本书的下几章和最后一节中，我们将创建一个商店界面。这个商店将结合我们迄今学到的所有知识，同时引入一些更多的技术、插件和功能。我们将研究如何从 CSV 文件中检索产品列表，显示它们及其变体，并按制造商或标签对产品进行过滤。我们还将研究如何创建产品详细视图，并允许用户向其在线购物篮中添加和删除产品和产品变体，例如尺寸或颜色。

所有这些都将使用 Vue、Vuex 和一个新的 Vue 插件 Vue-router 来实现。Vue-router 用于构建单页应用程序（SPAs），允许您将组件映射到 URL，或者在`VueRouter`术语中，路由和路径。这是一个非常强大的插件，处理了处理 URL 所需的许多复杂细节。

本章将涵盖以下内容：

+   初始化 Vue-router 及其选项

+   使用 Vue-router 创建链接

+   创建动态路由以根据 URL 更新视图

+   使用 URL 的 props

+   嵌套和命名路由

+   如何使用 Vue-router 进行编程导航

# 安装和初始化 Vue-router

与我们向应用程序添加 Vue 和 Vuex 的方式类似，您可以直接从 unpkg 中包含该库，或者转到以下 URL 并下载一个本地副本：[`unpkg.com/Vue-router`](https://unpkg.com/vue-router)。将 JavaScript 与 Vue 和应用程序的 JavaScript 一起添加到新的 HTML 文档中。还要创建一个应用程序容器元素作为您的视图。在下面的示例中，我将 Vue-router JavaScript 文件保存为`router.js`：

```js
<!DOCTYPE html>
<html>
<head>
  <title></title>
</head>
<body>
  <div id="app"></div>

  <script type="text/javascript" src="js/vue.js"></script>
  <script type="text/javascript" src="js/router.js"></script>
  <script type="text/javascript" src="js/app.js"></script>
</body>
</html>
```

在应用程序的 JavaScript 中初始化一个新的 Vue 实例：

```js
new Vue({
  el: '#app'
});
```

我们现在准备添加`VueRouter`并利用它的功能。然而，在此之前，我们需要创建一些非常简单的组件，我们可以根据 URL 加载和显示这些组件。由于我们将使用路由器加载组件，因此不需要使用`Vue.component`注册它们，而是创建具有与 Vue 组件相同属性的 JavaScript 对象。

对于这个第一个练习，我们将创建两个页面-主页和关于页面。这些页面在大多数网站上都可以找到，它们应该帮助您了解加载的内容在何时何地。在您的 HTML 页面中创建两个模板供我们使用：

```js
<script type="text/x-template" id="homepage">
  <div>
    <h1>Hello &amp; Welcome</h1>
    <p>Welcome to my website. Feel free to browse around.</p>
  </div>
</script>

<script type="text/x-template" id="about">
  <div>
    <h1>About Me</h1>
    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus sed metus magna. Vivamus eget est nisi. Phasellus vitae nisi sagittis, ornare dui quis, pharetra leo. Nullam eget tellus velit. Sed tempor lorem augue, vitae luctus urna ultricies nec. Curabitur luctus sapien elit, non pretium ante sagittis blandit. Nulla egestas nunc sit amet tellus rhoncus, a ultrices nisl varius. Nam scelerisque lacus id justo congue maximus. Etiam rhoncus, libero at facilisis gravida, nibh nisi venenatis ante, sit amet viverra justo urna vel neque.</p>
    <p>Curabitur et arcu fermentum, viverra lorem ut, pulvinar arcu. Fusce ex massa, vehicula id eros vel, feugiat commodo leo. Etiam in sem rutrum, porttitor velit in, sollicitudin tortor. Interdum et malesuada fames ac ante ipsum primis in faucibus. Donec ac sapien efficitur, pretium massa at, vehicula ligula. Vestibulum turpis quam, feugiat sed orci id, eleifend pretium urna. Nullam faucibus arcu eget odio venenatis ornare.</p>
  </div>
</script>
```

不要忘记将所有内容封装在一个"root"元素中（在这里用包装的`<div>`标签表示）。你还需要确保在加载应用程序 JavaScript 之前声明模板。

我们创建了一个 Home 页面模板，`id`为`homepage`，和一个 About 页面，包含一些来自*lorem ipsum*的占位文本，`id`为`about`。在你的 JavaScript 中创建两个引用这两个模板的组件：

```js
const Home = {
  template: '#homepage'
};

const About = {
  template: '#about'
};
```

下一步是给路由器一个占位符来渲染视图中的组件。这可以通过使用自定义的`<router-view>`HTML 元素来实现。使用这个元素可以控制内容的渲染位置。它允许我们在应用视图中直接拥有一个 header 和 footer，而不需要处理混乱的模板或包含组件本身。

在你的应用程序中添加一个`header`、`main`和`footer`元素。在`header`中放置一个 logo，在`footer`中放置一些 credits；在`main`的 HTML 元素中，放置一个`router-view`占位符：

```js
<div id="app">
  <header>
    <div>LOGO</div>
  </header>

  <main>
    <router-view></router-view>
  </main>

  <footer>
    <small>© Myself</small>
  </footer>
</div>
```

应用视图中的所有内容都是可选的，除了`router-view`，但它可以让你了解到路由器 HTML 元素如何在站点结构中实现。

下一步是初始化 Vue-router 并指示 Vue 使用它。创建一个`VueRouter`的新实例，并将其添加到`Vue`实例中——类似于我们在前一节中添加`Vuex`的方式：

```js
const router = new VueRouter();

new Vue({
  el: '#app',

  router
});
```

现在我们需要告诉路由器我们的路由（或路径），以及在遇到每个路由时应该加载的组件。在 Vue-router 实例中创建一个名为`routes`的键和一个数组作为值的对象。这个数组需要包含每个路由的对象：

```js
const router = new VueRouter({
  routes: [
    {
 path: '/',
 component: Home
 },
 {
 path: '/about',
 component: About
 }
  ]
});
```

每个路由对象包含一个`path`和`component`键。`path`是你想要在其上加载`component`的 URL 的字符串。Vue-router 根据先到先得的原则提供组件。例如，如果有多个具有相同路径的路由，将使用遇到的第一个路由。确保每个路由都有开始斜杠——这告诉路由器它是一个根页面而不是子页面，我们将在本章后面介绍子页面。

保存并在浏览器中查看您的应用程序。您应该看到`Home`模板组件的内容。如果观察 URL，您会注意到在页面加载时，路径后面会添加一个哈希和斜杠（`#/`）。这是路由器创建的一种浏览组件和利用地址栏的方法。如果您将其更改为第二个路由的路径`#/about`，您将看到`About`组件的内容。

Vue-router 还可以使用 JavaScript 历史 API 来创建更漂亮的 URL。例如，`yourdomain.com/index.html#about`将变为`yourdomain.com/about`。这是通过在`VueRouter`实例中添加`mode: 'history'`来激活的：

```js
const router = new VueRouter({
  mode: 'history',

  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    }
  ]
});
```

然而，它还需要一些服务器配置来捕获所有请求并将它们重定向到您的`index.html`页面，这超出了本书的范围，但在 Vue-router 文档中有详细说明。

# 更改 Vue-router 的文件夹

可能存在这样的情况，您希望将 Vue 应用程序托管在您网站的子文件夹中。在这种情况下，您需要声明项目的基本文件夹，以便 Vue-router 可以构建和监听正确的 URL。

例如，如果您的应用程序基于`/shop/`文件夹，您可以使用 Vue-router 实例上的`base`参数进行声明：

```js
const router = new VueRouter({
  base: '/shop/',

  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    }
  ]
});
```

这个值需要在开头和结尾都有斜杠。

除了`base`之外，Vue-router 还有其他几个配置选项可用，值得熟悉它们，因为它们可能会解决您以后遇到的问题。

# 链接到不同的路由

随着路由器按预期工作，我们现在可以继续向我们的应用程序中添加链接，允许用户在网站上导航。链接可以通过两种方式实现：我们可以使用传统的`<a href="#/about">`标签，或者我们可以利用路由器提供的新的 HTML 元素`<router-link to="/about">`。当使用`router-link`元素时，它的工作方式与`<a>`标签相同，并且实际上在浏览器中运行时会转换为`<a>`标签，但它允许更多的自定义和与路由器的集成。

强烈建议在可能的情况下使用`router-link`元素，因为它比标准链接具有几个优点：

+   **模式更改**：第一个优点与路由器的`mode`相关。使用路由链接允许您更改路由器的模式，例如从哈希模式更改为历史模式，而无需更改应用程序中的每个链接。

+   **CSS 类**：使用路由链接的另一个优点是应用于“树”中活动链接和当前正在查看的页面的 CSS 类。树中的链接是父页面，也包括根页面（例如，任何指向`/`的链接将始终具有活动类）。这是使用路由器的一个重要优势，因为手动添加和删除这些类将需要复杂的编码。这些类可以自定义，我们将在稍后进行。

+   **URL 参数和命名路由**：使用路由器元素的另一个优点是它使您能够使用命名路由和传递 URL 参数。这进一步允许您在页面的 URL 上拥有一个真实的来源，并使用名称和快捷方式引用路由。关于这个问题将在本章后面进行更详细的介绍。

在视图中添加链接以在页面之间导航。在您的网站的`<header>`中，创建一个新的`<nav>`元素，其中包含一个无序列表。对于每个页面，添加一个包含`router-link`元素的新列表项。在链接路径上添加一个`to`属性：

```js
<nav>
  <ul>
    <li>
      <router-link to="/">Home</router-link>
    </li>
    <li>
      <router-link to="/about">About</router-link>
    </li>
  </ul>
</nav>
```

在浏览器中查看应用程序应该显示两个链接，允许您在两个内容页面之间切换。您还会注意到，通过点击链接，URL 也会更新。

如果您使用浏览器的 HTML 检查器检查链接，您会注意到 CSS 类的变化。主页链接始终具有`router-link-active`类 - 这是因为它要么是活动的本身，要么有一个活动的子页面，比如关于页面。还有另一个 CSS 类，当您在两个页面之间导航时会添加和删除 - `router-link-exact-active`。这个类**只会**应用于当前活动页面上的链接。

让我们自定义应用于视图的类。转到 JavaScript 中路由器的初始化，并向对象添加两个新键 - `linkActiveClass`和`linkExactActiveClass`：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    }
  ],

  linkActiveClass: 'active',
 linkExactActiveClass: 'current'
});
```

这些键应该相当容易理解，但是`linkExactActiveClass`应用于当前页面，即正在查看的页面，而`linkActiveClass`是当页面或其子页面处于活动状态时应用的类。

# 链接到子路由

有时您可能希望链接到子页面。例如`/about/meet-the-team`。幸运的是，不需要太多工作来实现这个。在`routes`数组中创建一个指向具有模板的新组件的新对象：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    },
    {
 path: '/about/meet-the-team',
 component: MeetTheTeam
 }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});  
```

当导航到这个页面时，你会注意到 Home 和 About 链接都有`active`类，并且都没有我们创建的`current`类。如果你在导航中创建一个链接到这个页面，那么一个`current`类将会被应用到它上面。

# 动态路由与参数

Vue 路由器很容易让你拥有动态 URL。动态 URL 允许你使用相同的组件来显示不同的数据，同时使用相同的模板。一个例子是商店，所有的类别页面看起来都一样，但根据 URL 显示不同的数据。另一个例子是产品详情页面——你不想为每个产品创建一个组件，所以你可以使用一个带有 URL 参数的组件。

URL 参数可以出现在路径的任何位置，可以有一个或多个。每个参数都被分配一个键，因此可以创建和访问它们。我们将在第九章中更详细地介绍动态路由和参数，*使用 Vue-Router 动态路由加载数据*。现在，我们将构建一个基本的示例。

在我们进入创建组件之前，让我们来看一下一个新的变量可用于我们——`this.$route`。类似于我们如何通过 Vuex 访问全局存储，这个变量允许我们访问关于路由、URL 和参数的许多信息。

在你的 Vue 实例中，作为一个测试，添加一个`mounted()`函数。在`console.log`中插入`this.$route`参数：

```js
new Vue({
  el: '#app',

  router,
  mounted() {
 console.log(this.$route);
 }
});
```

如果你打开浏览器并查看开发者工具，你应该会看到一个对象被输出。查看这个对象将会显示一些信息，比如路径和与当前路径匹配的组件。前往`/about` URL 将会显示关于该对象的不同信息：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00013.jpeg)

让我们创建一个使用这个对象参数的组件。在你的路由数组中创建一个新对象：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    },
    {
 path: '/user/:name',
 component: User
 }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
}); 
```

你会注意到这个路径与之前的路径不同的地方是在路径中`name`之前有一个冒号。这告诉 Vue-router 这个 URL 的这部分是动态的，但该部分的变量名是`name`。

现在创建一个名为`User`的新组件，并为它创建一个模板。对于这个示例，我们的模板将是内联的，并且我们将使用 ES2015 模板语法。这使用反引号，并允许直接将变量和换行符传递到模板中，而无需对它们进行转义：

```js
const User = {
  template: `<h1>Hello {{ $route.params.name }}</h1>`
};
```

模板中输出的变量来自全局路由实例，并且是参数对象中的`name`变量。变量`name`引用了路由路径中冒号前面的变量，在`routes`数组中。在组件模板中，我们还可以省略`$route`中的`this`变量。

返回浏览器，输入 URL 末尾的`#/user/sarah`。您应该在网页的主体中看到 Hello sarah。查看 JavaScript 浏览器控制台，您应该看到`params`对象中有一个键值对`name: sarah`：

！[](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00014.jpeg)

这个变量在组件内部也对我们可用。例如，如果我们想要将用户姓名的第一个字母大写，我们可以创建一个计算属性，它接受路由参数并进行转换：

```js
const User = {
  template: `<h1>Hello {{ name }}</h1>`,

  computed: {
 name() {
 let name = this.$route.params.name;
 return name.charAt(0).toUpperCase() + name.slice(1);
 }
 }
};
```

如果您对上述代码的作用不熟悉，它会将字符串的第一个字符大写。然后它在大写字母后面分割字符串（即，单词的其余部分），并将其附加到大写字母上。

添加这个`computed`函数并刷新应用程序将产生 Hello sarah。

如前所述，路由可以接受任意数量的参数，并且可以由静态或动态变量分隔。

将路径更改为以下内容（同时保持组件名称相同）：

```js
/:name/user/:emotion
```

这意味着您需要转到`/sarah/user/happy`才能看到用户组件。但是，您将可以访问一个名为`emotion`的新参数，这意味着您可以使用以下模板来渲染 sarah is happy!：

```js
const User = {
  template: `<h1>{{ name }} is {{ $route.params.emotion }}</h1>`,

  computed: {
    name() {
      let name = this.$route.params.name;
      return name.charAt(0).toUpperCase() + name.slice(1);
    }
  }
};

const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    },
    {
 path: '/:name/user/:emotion',
      component: User
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

在接下来的几章中，当我们构建商店时，动态路由将非常有用，因为我们将同时用于产品和类别。

# GET 参数

除了动态路由，Vue-router 还以一种非常简单的方式处理 GET 参数。GET 参数是您可以传递给网页的额外 URL 参数，它们以键值对的形式出现。使用 GET 参数时，第一个参数前面有一个`?`，这告诉浏览器要期望参数。任何后续的参数都用和号分隔。一个例子是：

```js
example.com/?name=sarah&amp;emotion=happy
```

这个 URL 将产生`name`的值为`sarah`，`emotion`的值为`happy`。它们通常用于过滤或搜索 - 下次在 Google 上搜索时，查看 URL，您会注意到地址栏中有`?q=Your+search+query`。

Vue 路由器将这些参数在`this.$route`变量的`query`对象中提供给开发者。尝试在 URL 末尾添加`?name=sarah`，然后打开 JavaScript 开发者工具。检查查询对象将显示一个以`name`为键，`sarah`为值的对象：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00015.jpeg)

在构建商店类别的筛选时，我们将使用查询对象。

# 使用 props

虽然直接在组件中使用路由参数完全可以正常工作，但这不是一个好的实践，因为它将组件直接与路由绑定在一起。相反，应该使用`props`，就像我们在本书中之前为 HTML 组件使用它们一样。当启用和声明时，通过 URL 传递的参数可用于像通过 HTML 属性传递的参数一样使用。

使用 props 作为路由组件的参数传递选项和参数是一种更好的方式，因为它有很多好处。首先，它将组件与特定的 URL 结构解耦，正如您将看到的，我们可以直接将 props 传递给组件本身。它还有助于使您的路由组件更清晰；传入的参数在组件本身中清晰地展示，并且整个组件的代码更加清晰。

Props 只适用于动态路由，GET 参数仍然可以通过前面的技术访问。

使用上述示例，为`name`和`emotion`参数声明`props`。在使用基于 URL 的变量时，您将希望使用`String`数据类型：

```js
const User = {
  template: `<h1>{{ name }} is {{ $route.params.emotion }}</h1>`,
  props: {
 name: String,
 emotion: String
 },
  computed: {
    name() {
      let name = this.$route.params.name;
      return name.charAt(0).toUpperCase() + name.slice(1);
    }
  }
};
```

现在我们有了`this.name`的两个可用方式——通过`props`和计算值。然而，由于我们通过`props`有了`this.name`和`this.emotion`，我们可以更新组件以使用这些变量，而不是`$route`参数。

为了避免与 prop 冲突，将计算函数更新为`formattedName()`。我们还可以从函数中删除变量声明，因为新变量更易读：

```js
const User = {
  template: `<h1>{{ formattedName }} is {{ this.emotion }}</h1>`,
  props: {
    name: String,
    emotion: String
  },
  computed: {
    formattedName() {
      return this.name.charAt(0).toUpperCase() + this.name.slice(1);
    }
  }
};
```

在`props`起作用之前，需要告诉 Vue-router 在特定路由上使用它们。这在`routes`数组中启用，逐个路由设置，并且最初设置为`props: true`的值：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    },
    {
      path: '/:name/user/:emotion',
      component: User,
      props: true
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

# 设置 prop 默认值

现在将路由参数作为`props`可用，这使我们可以轻松创建一个默认值。如果我们想要使参数可选，我们需要添加几个`if()`语句来检查变量的存在性。

然而，使用 props，我们可以像之前一样声明默认值。为情感变量添加一个默认值：

```js
const User = {
  template: `<h1>{{ formattedName }} is {{ this.emotion }}</h1>`,
  props: {
    name: String,
    emotion: {
 type: String,
 default: 'happy'
 }
  },
  computed: {
    formattedName() {
      return this.name.charAt(0).toUpperCase() + this.name.slice(1);
    }
  }
};
```

我们现在可以在我们的路由器中创建一个新的路由，该路由使用相同的组件，但没有最后的变量。不要忘记为新的路由启用`props`：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    },
    {
 path: '/:name/user',
 component: User,
 props: true
 }, 
    {
      path: '/:name/user/:emotion',
      component: User,
      props: true
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

现在，通过访问`/sarah/user`，我们应该看到声明 sarah 很开心的文本。

# 使用静态 props

除了布尔值之外，路由中的 props 参数还可以接受一个包含要传递的 props 列表的对象。这允许您使用相同的组件并根据 URL 更改其状态，而无需通过路径传递变量，例如，如果您想要激活或停用模板的一部分。

通过 URL 传递 props 对象时，它会覆盖整个 props 对象，这意味着您必须声明所有或不声明任何 props 变量。props 变量也将优先于动态的基于 URL 的变量。

更新你的新的`/:name/user`路径，将`props`包含在路由中-从路径中删除`:name`变量，使其变为`/user`：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About
    },
    {
      path: '/user',
      component: User,
      props: {
 name: 'Sarah',
 emotion: 'happy'
 }
    }, 
    {
      path: '/:name/user/:emotion',
      component: User,
      props: true
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

导航到`/user`应该显示与之前相同的句子。在某些情况下，通过“幕后”（不使用 URL）传递`props`是理想的，这样您可能不希望用户共享特定的 URL 或根据易于更改的参数更改应用程序的状态。

# 嵌套路由

嵌套路由与子路由不同，因为它们存在于已经匹配路由开始部分的组件中。这允许您在现有视图中显示不同的内容。

一个很好的例子是 Twitter。如果您访问 Twitter 用户的个人资料页面，您可以查看他们关注的人，关注他们的人以及他们创建的列表。如果您在浏览页面时观察 URL，您会注意到一个重复的模式：用户名后跟不同的页面。嵌套路由和子路由之间的区别在于，嵌套路由允许您在不同的子页面中保持组件相同（例如，标题和侧边栏）。

这样做的好处是用户可以收藏和分享链接，使页面更易访问，并且有利于 SEO。使用简单的切换或选项卡框来显示视图中的不同内容很难实现这些优势。

要将 Twitter 模式复制到 Vue 路由中，它将如下所示：

```js
https://twitter.com/:user/:page
```

如果我们使用之前的路由方法创建这个，我们将不得不为每个页面构建组件，这些组件在其模板中包含侧边栏中的标题和用户信息-如果您需要更新代码，那将是一种痛苦！

让我们为我们的关于页面创建一些嵌套路由。在我们的商店应用程序中，我们不会使用嵌套路由，但了解 Vue 路由器的功能是很重要的。

创建两个新组件-`AboutContact`，它将显示联系信息，和`AboutFood`，一个将详细介绍您喜欢吃的食物的组件！虽然不是必需的，但在组件名称中保留对父组件（在本例中为 About）的引用是一个好主意-这样可以在以后查看它们时将组件联系在一起！为每个组件提供一个带有一些固定内容的模板：

```js
const AboutContact = {
  template: `<div>
    <h2>This is some contact information about me</h2>
    <p>Find me online, in person or on the phone</p>
  </div>`
};

const AboutFood = {
  template: `<div>
    <h2>Food</h2>
    <p>I really like chocolate, sweets and apples.</p>
  </div>`
};
```

下一步是在您的`#about`模板中创建占位符，以便嵌套路由可以渲染在其中。该元素与我们之前看到的元素完全相同-`<router-view>`元素。为了证明它可以放在任何地方，在模板中的两个段落之间添加它：

```js
<script type="text/x-template" id="about">
  <div>
    <h1>About Me</h1>
    <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Vivamus sed metus magna. Vivamus eget est nisi. Phasellus vitae nisi sagittis, ornare dui quis, pharetra leo. Nullam eget tellus velit. Sed tempor lorem augue, vitae luctus urna ultricies nec. Curabitur luctus sapien elit, non pretium ante sagittis blandit. Nulla egestas nunc sit amet tellus rhoncus, a ultrices nisl varius. Nam scelerisque lacus id justo congue maximus. Etiam rhoncus, libero at facilisis gravida, nibh nisi venenatis ante, sit amet viverra justo urna vel neque.</p>

    <router-view></router-view>

    <p>Curabitur et arcu fermentum, viverra lorem ut, pulvinar arcu. Fusce ex massa, vehicula id eros vel, feugiat commodo leo. Etiam in sem rutrum, porttitor velit in, sollicitudin tortor. Interdum et malesuada fames ac ante ipsum primis in faucibus. Donec ac sapien efficitur, pretium massa at, vehicula ligula. Vestibulum turpis quam, feugiat sed orci id, eleifend pretium urna. Nullam faucibus arcu eget odio venenatis ornare.</p>
  </div>
</script>
```

在浏览器中查看关于页面不会渲染任何内容，也不会破坏应用程序。下一步是为这些组件添加嵌套路由到路由器中。我们不是将它们添加到顶级`routes`数组中，而是在`/about`路由内创建一个数组，键为`children`。该数组的语法与主数组完全相同-即，一个路由对象的数组。

为每个`routes`添加一个包含`path`和`component`键的对象。关于路径的要注意的是，如果您希望路径添加到父级的末尾，它不应该以`/`开头。

例如，如果您希望 URL 为`/about/contact`来渲染`AboutContact`组件，您可以将路由组件设置如下：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About,
      children: [
 {
 path: 'contact', 
 component: AboutContact
 }, 
 {
 path: 'food', 
 component: AboutFood
 }
 ]
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

但是，如果您希望 URL 仅为`/contact`，但仍然在`About`组件中渲染`AboutContact`组件，您可以添加前导斜杠。尝试在没有斜杠的情况下查看应用程序，然后添加斜杠，看看它所产生的差异。如果您希望在加载父级时显示子路由而没有 URL 的第二部分，您可以使用空路径-`path: ''`。

现在，将其保留为没有斜杠，并添加前面的`children`数组。转到浏览器并导航到关于页面。在 URL 的末尾添加`/contact`或`/food`，注意新内容出现在您之前添加到模板中的`<router-link>`元素的位置。

可以从任何地方创建到这些组件的链接，方式与您链接主页和关于页面的方式相同。您可以将它们添加到`about`模板中，这样它们只会在导航到该页面时出现，或者将它们添加到应用程序视图中的主导航中。

# 创建 404 页面

在构建应用程序或网站时，尽管有着良好的意图，问题、错误和错误确实会发生。因此，最好在适当的位置设置错误页面。最常见的页面是 404 页面-当链接不正确或页面已移动时显示的消息。 404 是页面未找到的官方 HTTP 代码。

如前所述，Vue-router 将根据先到先服务的原则匹配路由。我们可以利用这一点，使用通配符（`*`）字符作为最后一个路由。由于通配符匹配*每个*路由，因此只有未匹配先前路由的 URL 将被此路由捕获。

创建一个名为`PageNotFound`的新组件，其中包含一个简单的模板，并添加一个使用通配符字符作为路径的新路由：

```js
const PageNotFound = {
 template: `<h1>404: Page Not Found</h1>`
};

const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About,
      children: [
        {
          path: 'contact', 
          component: AboutContact
        }, 
        {
          path: 'food', 
          component: AboutFood
        }
      ]
    },
 {
 path: '*', 
 component: PageNotFound
 }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

在浏览器中打开应用程序，并在 URL 的末尾输入任何内容（除了`about`），然后按下*Enter*键-您应该会看到 404 标题。

尽管这是模拟未找到页面的请求，但实际上并未向浏览器发送正确的 HTTP 代码。如果您在生产中使用 Vue Web 应用程序，建议设置服务器端错误检查，以便在 URL 不正确的情况下，可以正确通知浏览器。

# 命名组件、路由和视图

在使用`Vue-router`时，不需要为路由和组件添加名称，但这是一个好的做法，并且是一个好习惯。

# 命名组件

具有名称的组件可以更容易地调试错误。在 Vue 中，当组件抛出 JavaScript 错误时，它将给出该组件的名称，而不是将`Anonymous`列为组件。

例如，如果您尝试在 food 组件中输出一个不可用的变量`{{ test }}`。默认情况下，JavaScript 控制台错误如下所示：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00016.jpeg)

请注意堆栈中的两个`<Anonymous>`组件。

通过为组件添加名称，我们可以轻松地确定问题所在。在下面的示例中，已经为`About`和`AboutFood`组件添加了名称：

![](https://github.com/OpenDocCN/freelearn-vue-zh/raw/master/docs/vue2-ex/img/00017.jpeg)

您可以轻松地看到错误出现在`<AboutFood>`组件中。

将组件命名的方法就是在对象中添加一个名为 name 的键，并将名称作为值。这些名称遵循与创建 HTML 元素组件时相同的规则：不允许空格，但允许连字符和字母。为了让我能够快速识别代码，我选择将组件命名为与定义它的变量相同的名称：

```js
const About = {
  name: 'About',
  template: '#about'
};

const AboutFood = {
  name: 'AboutFood',
  template: `<div>
    <h2>Food</h2>
    <p>I really like chocolate, sweets and apples.</p>
  </div>`
}
```

# 命名路由

在使用`VueRouter`时，您还可以为路由本身命名。这使您能够简化路由的位置并更新路径，而无需在应用程序中查找和替换所有实例。

请按照以下示例将`name`键添加到您的`routes`中：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      component: About,
      children: [
        {
          name: 'contact',
          path: 'contact', 
          component: AboutContact
        }, 
        {
          name: 'food',
          path: 'food', 
          component: AboutFood
        }
      ]
    },
    {
      path: '*', 
      component: PageNotFound
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

现在，您可以在创建`router-link`组件时使用该名称，如下所示：

```js
<router-link :to="{name: 'food'}">Food</router-link>
```

请注意`to`属性之前的冒号。这确保内容被解析为对象，而不是字面字符串。使用命名路由的另一个优点是能够向动态路径传递特定属性。使用本章前面的示例，我们可以以编程方式构建 URL，将数据从路径构建中抽象出来。这就是命名路由真正发挥作用的地方。假设我们有以下路径：

```js
{ name: 'user', path: '/:name/user/:emotion', component: User }
```

我们需要向 URL 传递一个名称和情感变量以渲染组件。我们可以像之前一样直接传递到 URL，或者使用带有命名路由的`to`对象表示法：

```js
<router-link :to="{name: 'user', params: { name: 'sarah', emotion: 'happy' }}">
  Sarah is Happy
</router-link>
```

在浏览器中查看时，将正确生成锚链接。

```js
/sarah/user/happy
```

这使我们能够使用变量重新排列 URL，而无需更新应用程序的其余部分。如果您想在 URL 末尾传递参数（例如，`?name=sarah`），则可以将`params`键更改为`query`，因为它遵循相同的格式：

```js
<router-link :to="{name: 'user', query: { name: 'sarah', emotion: 'happy' }}">
  Sarah is Happy
</router-link>
```

重新配置路径以不接受参数后，将生成以下链接：

```js
/user?name=sarah&amp;emotion=happy
```

在交换`params`和`query`时要小心-它们可能会影响您使用`path`还是`name`。使用`path`时，将忽略`params`对象，而`query`对象不会被忽略。要使用`params`对象，您需要使用命名路由。或者，使用`$`变量将参数传递到`path`中。

# 命名视图

Vue 路由器还允许您为视图命名，从而可以将不同的组件传递给应用程序的不同部分。例如，商店可能会有侧边栏和主要内容区域。不同的页面可以以不同的方式利用这些区域。

关于页面可以使用主要内容显示关于内容，同时使用侧边栏显示联系方式。然而，商店页面将使用主要内容列出产品，并使用侧边栏显示过滤器。

为此，创建第二个`router-view`元素作为原始元素的兄弟元素。保留原始元素的位置，但在第二个元素上添加一个`name`属性，以适当的标题命名：

```js
<main>
  <router-view></router-view>
</main>

<aside>
    <router-view name="sidebar"></router-view>
</aside>
```

在路由器实例中声明路由时，我们现在将使用一个新的键`components`，并删除之前的单数`component`键。这个键接受一个对象，其中包含视图的名称和组件的名称的键值对。

建议将主路由保留为未命名状态，这样您就不需要更新每个路由。如果决定为主路由命名，那么您需要为应用程序中的每个路由执行此步骤。

更新`About`路由以使用这个新的键，并将其转换为一个对象。下一步是告诉代码每个组件将放在哪里。

使用默认值作为键，将`About`组件设置为值。这将把 About 组件的内容放在未命名的`router-view`中，即主要的`router-view`。这也是使用单数`component`键的简写方式：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      components: {
 default: About
 }
    },
    {
      path: '*', 
      component: PageNotFound
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

接下来，添加第二个键值，指定第二个`router-view`的名称为`sidebar`。在`/about` URL 导航到时，命名要填充此区域的组件。为此，我们将使用`AboutContact`组件：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
      components: {
        default: About,
        sidebar: AboutContact
      }
    },
    {
      path: '*', 
      component: PageNotFound
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

在浏览器中运行应用程序将呈现两个组件，其中联系组件的内容显示在侧边栏中。

# 使用编程方式导航、重定向和添加别名

在构建应用程序时，可能会遇到需要一些不同的导航技术的情况。这些可能是以编程方式导航，例如在组件或主 Vue 实例中，当用户访问特定 URL 时重定向用户，或者使用不同的 URL 加载相同的组件。

# 以编程方式导航

您可能希望从代码、组件或操作中更改路径、URL 或用户流程。例如，当用户添加了一个项目后，将用户发送到购物篮。

要做到这一点，您可以在路由实例上使用`push()`函数。push 的值可以是一个直接 URL 的字符串，也可以接受一个对象来传递命名路由或路由参数。`push`函数允许的内容与`router-link`元素上的`to=""`属性完全相同。例如：

```js
const About = {
  name: 'About',
  template: '#about',
  methods: {
    someAction() {
      /* Some code here */

      // direct user to contact page
      this.$router.push('/contact');
    }
  }
};
```

或者，您可以使用参数指定一个命名路由：

```js
this.$router.push({name: 'user', params: { name: 'sarah', emotion: 'happy' }});
```

# 重定向

使用`VueRouter`进行重定向非常简单。一个重定向的例子可能是将您的`/about`页面移动到`/about-us`的 URL。您将希望将第一个 URL 重定向到第二个 URL，以防有人分享或收藏了您的链接，或者搜索引擎缓存了该 URL。

您可能会想创建一个基本组件，在创建时使用`router.push()`函数将用户发送到新的 URL。

相反，您可以添加一个路由并在其中指定重定向：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
 path: '/about',
 redirect: '/about-us'
 },
    {
      path: '/about-us',
      component: About
    },
    {
      path: '*', 
      component: PageNotFound
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

再次强调，重定向键的内容可以是一个字面字符串或一个对象，就像`push()`函数一样。在上述示例中，如果用户访问`/about`，他们将立即被重定向到`/about-us`，并显示`About`组件。

# 别名路由

有些情况下，您可能希望在两个 URL 下显示相同的组件。虽然不推荐作为标准做法，但在某些特殊情况下可能需要这样做。

别名键会添加到现有路由中，并接受一个路径的字符串。使用上述示例，无论用户访问`/about`还是`/about-us`，都将显示`About`组件：

```js
const router = new VueRouter({
  routes: [
    {
      path: '/',
      component: Home
    },
    {
      path: '/about',
 alias: '/about-us',
      component: About,
    },
    {
      path: '*', 
      component: PageNotFound
    }
  ],

  linkActiveClass: 'active',
  linkExactActiveClass: 'current'
});
```

# 总结

您现在应该熟悉了 Vue-router 的使用方法，如何初始化它，有哪些选项可用，以及如何创建新的静态和动态路由。在接下来的几章中，我们将开始创建我们的商店，首先加载一些商店数据并创建一个产品页面。
