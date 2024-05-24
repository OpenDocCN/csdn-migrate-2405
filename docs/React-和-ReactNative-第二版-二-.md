# React 和 ReactNative 第二版（二）

> 原文：[`zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32`](https://zh.annas-archive.org/md5/CC615F617A68B98794CE06AC588C6A32)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：打造可重用的组件

本章的重点是向您展示如何实现不止一种用途的 React 组件。阅读完本章后，您将对如何组合应用程序功能感到自信。

本章以简要介绍 HTML 元素及其在帮助实现功能方面的工作方式开始。然后，您将看到一个单片组件的实现，并发现它将在未来引起的问题。接下来的部分致力于以一种使功能由更小的组件组成的方式重新实现单片组件。

最后，本章以讨论渲染 React 组件树结束，并为您提供一些建议，以避免由于分解组件而引入过多复杂性。我将通过重申高级功能组件与实用组件的概念来结束这一最后部分。

# 可重用的 HTML 元素

让我们思考一下 HTML 元素。根据 HTML 元素的类型，它要么是*以功能为中心*，要么是*以实用为中心*。实用为中心的 HTML 元素比以功能为中心的 HTML 元素更具重用性。例如，考虑`<section>`元素。这是一个通用元素，可以在任何地方使用，但它的主要目的是组成功能的结构方面——功能的外壳和功能的内部部分。这就是`<section>`元素最有用的地方。

另一方面，您还有诸如`<p>`、`<span>`和`<button>`之类的元素。这些元素提供了高度的实用性，因为它们从设计上就是通用的。当用户可以点击时，您应该使用`<button>`元素，从而产生一个动作。这比功能的概念低一个级别。

虽然谈论具有高度实用性的 HTML 元素与针对特定功能的元素很容易，但当涉及*数据*时，讨论就会更加详细。HTML 是静态标记——React 组件将静态标记与数据结合在一起。问题是，如何确保您正在创建正确的以功能为中心和以实用为中心的组件？

本章的目标是找出如何从定义功能的单片 React 组件转变为与实用组件相结合的更小的以功能为中心的组件。

# 单片组件的困难

如果您可以为任何给定功能实现一个组件，那将简化您的工作。至少，就不会有太多需要维护的组件，也不会有太多数据流通的路径，因为一切都将是组件内部的。

然而，这个想法出于许多原因是行不通的。拥有单体功能组件使得协调任何团队开发工作变得困难。单体组件变得越大，以后重构为更好的东西就会变得越困难。

还有功能重叠和功能通信的问题。重叠是因为功能之间的相似之处而发生的——一个应用程序不太可能具有完全彼此独特的一组功能。这将使应用程序非常难以学习和使用。组件通信基本上意味着一个功能中的某些东西的状态将影响另一个功能中的某些东西的状态。状态很难处理，当有很多状态打包到单体组件中时更是如此。

学习如何避免单体组件的最佳方法是亲身体验一个。您将在本节的其余部分中实现一个单体组件。在接下来的部分中，您将看到如何将此组件重构为更可持续的东西。

# JSX 标记

我们要实现的单体组件是一个列出文章的功能。这只是为了举例说明，所以我们不希望组件过大。它将是简单的，但是单体的。用户可以向列表中添加新项目，切换列表中项目的摘要，并从列表中删除项目。这是组件的`render`方法：

```jsx
render() {
 const { articles, title, summary } = this.data.toJS();

  return (
    <section>
      <header>
        <h1>Articles</h1>
        <input
          placeholder="Title"
          value={title}
          onChange={this.onChangeTitle}
        />
        <input
          placeholder="Summary"
          value={summary}
          onChange={this.onChangeSummary}
        />
        <button onClick={this.onClickAdd}>Add</button>
      </header>
      <article>
        <ul>
          {articles.map(i => (
            <li key={i.id}>
              <a
                href={`#${i.id}`}
                title="Toggle Summary"
                onClick={this.onClickToggle.bind(null, i.id)}
              >
                {i.title}
              </a>
              &nbsp;
              <a
                href={`#${i.id}`}
                title="Remove"
                onClick={this.onClickRemove.bind(null, i.id)}
              >
                ✗
              </a>
              <p style={{ display: i.display }}>{i.summary}</p>
            </li>
          ))}
        </ul>
      </article>
    </section>
  );
} 
```

在一个地方使用的 JSX 肯定比必要的要多。您将在接下来的部分中改进这一点，但现在让我们为这个组件实现初始状态。

我强烈建议您从[`github.com/PacktPublishing/React-and-React-Native-Second-Edition`](https://github.com/PacktPublishing/React-and-React-Native-Second-Edition)下载本书的配套代码。我可以拆分组件代码，以便在这些页面上解释它。但是，如果您可以完整地看到代码模块，并运行它们，学习体验会更容易。

# 初始状态和状态助手

现在让我们看看这个组件的初始状态：

```jsx
// The state of this component is consists of
// three properties: a collection of articles,
// a title, and a summary. The "fromJS()" call
// is used to build an "Immutable.js" Map. Also
// note that this isn't set directly as the component
// state - it's in a "data" property of the state -
// otherwise, state updates won't work as expected.
state = {
  data: fromJS({
    articles: [
      {
        id: cuid(),
        title: 'Article 1',
        summary: 'Article 1 Summary',
        display: 'none'
      },
      {
        id: cuid(),
        title: 'Article 2',
        summary: 'Article 2 Summary',
        display: 'none'
      },
      {
        id: cuid(),
        title: 'Article 3',
        summary: 'Article 3 Summary',
        display: 'none'
      },
      {
        id: cuid(),
        title: 'Article 4',
        summary: 'Article 4 Summary',
        display: 'none'
      }
    ],
    title: '',
    summary: ''
  })
}; 
```

有两个有趣的函数用于初始化状态。第一个是来自`cuid`包的`cuid()`——一个用于生成唯一 ID 的有用工具。第二个是来自`immutable`包的`fromJS()`。以下是引入这两个依赖项的导入：

```jsx
// Utility for constructing unique IDs... 
import cuid from 'cuid'; 

// For building immutable component states... 
import { fromJS } from 'immutable'; 
```

正如其名称所示，`fromJS()`函数用于构建不可变的数据结构。`Immutable.js`对于操作 React 组件的状态非常有用的功能。在本书的其余部分，你将继续使用`Immutable.js`，并且随着学习的深入，你将了解更多具体内容，从这个例子开始。

要更深入地了解**Immutable.js**，请查看《精通 Immutable.js》：[`www.packtpub.com/web-development/mastering-immutablejs`](https://www.packtpub.com/web-development/mastering-immutablejs)

你可能还记得上一章中提到的`setState()`方法只能使用普通对象。嗯，`Immutable.js`对象不是普通对象。如果我们想使用不可变数据，就需要将它们包装在一个普通对象中。让我们实现一个帮助器的获取器和设置器：

```jsx
// Getter for "Immutable.js" state data... 
get data() { 
  return this.state.data; 
} 

// Setter for "Immutable.js" state data... 
set data(data) { 
  this.setState({ data }); 
} 
```

现在，你可以在我们的事件处理程序中使用不可变的组件状态。

# 事件处理程序实现

在这一点上，你已经有了初始状态、状态辅助属性和组件的 JSX。现在是时候实现事件处理程序本身了：

```jsx
// When the title of a new article changes, update the state
// of the component with the new title value, by using "set()"
// to create a new map.
onChangeTitle = e => {
  this.data = this.data.set('title', e.target.value);
};

// When the summary of a new article changes, update the state
// of the component with the new summary value, by using "set()"
// to create a new map.
onChangeSummary = e => {
  this.data = this.data.set('summary', e.target.value);
};

// Creates a new article and empties the title
// and summary inputs. The "push()" method creates a new
// list and "update()" is used to update the list by
// creating a new map.
onClickAdd = () => {
  this.data = this.data
    .update('articles', a =>
      a.push(
        fromJS({
          id: cuid(),
          title: this.data.get('title'),
          summary: this.data.get('summary'),
          display: 'none'
        })
      )
    )
    .set('title', '')
    .set('summary', '');
};

// Removes an article from the list. Calling "delete()"
// creates a new list, and this is set in the new component
// state.
onClickRemove = id => {
  const index = this.data
    .get('articles')
    .findIndex(a => a.get('id') === id);

  this.data = this.data.update('articles', a => a.delete(index));
};

// Toggles the visibility of the article summary by
// setting the "display" state of the article. This
// state is dependent on the current state.
onClickToggle = id => {
  const index = this.data
    .get('articles')
    .findIndex(a => a.get('id') === id);

  this.data = this.data.update('articles', articles =>
    articles.update(index, a =>
      a.update('display', display => (display ? '' : 'none'))
    )
  );
};
```

天啊！这是很多`Immutable.js`代码！不用担心，实际上这比使用普通 JavaScript 实现这些转换要少得多。以下是一些指针，帮助你理解这段代码：

+   `setState()`总是以一个普通对象作为其参数调用。这就是为什么我们引入了数据设置器。当你给`this.data`赋一个新值时，它会用一个普通对象调用`setState()`。你只需要关心`Immutable.js`数据。同样，数据获取器返回`Immutable.js`对象而不是整个状态。

+   不可变方法总是返回一个新实例。当你看到像`article.set(...)`这样的东西时，它实际上并没有改变`article`，而是创建了一个新的实例。

+   在`render()`方法中，不可变数据结构被转换回普通的 JavaScript 数组和对象，以便在 JSX 标记中使用。

如果需要，尽管花费你需要的时间来理解这里发生了什么。随着你在书中的进展，你会看到不可变状态可以被 React 组件利用的方式。这些事件处理程序只能改变这个组件的状态。也就是说，它们不会意外地改变其他组件的状态。正如你将在接下来的部分中看到的，这些处理程序实际上已经相当完善了。

这是渲染输出的截图：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/82062a09-5dad-4592-bbd9-46ee033c8c8d.png)

# 重构组件结构

你有一个庞大的功能组件，现在怎么办？让我们把它做得更好。

在本节中，你将学习如何将刚刚在前一节中实现的功能组件分割成更易维护的组件。你将从 JSX 开始，因为这可能是最好的重构起点。然后，你将为这个功能实现新的组件。

接下来，你将使这些新组件变成功能性的，而不是基于类的。最后，你将学会如何使用渲染属性来减少应用程序中直接组件的依赖数量。

# 从 JSX 开始

任何庞大组件的 JSX 都是找出如何将其重构为更小组件的最佳起点。让我们来可视化一下我们当前正在重构的组件的结构：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/67e3c588-4bad-4016-a2c7-1ab4337467b7.png)

JSX 的顶部部分是表单控件，所以这很容易成为自己的组件：

```jsx
<header> 
  <h1>Articles</h1> 
  <input 
    placeholder="Title" 
    value={title} 
    onChange={this.onChangeTitle} 
  /> 
  <input 
    placeholder="Summary" 
    value={summary} 
    onChange={this.onChangeSummary} 
  /> 
  <button onClick={this.onClickAdd}>Add</button> 
</header> 
```

接下来，你有文章列表：

```jsx
<ul> 
  {articles.map(i => ( 
    <li key={i.id}> 
      <a 
        href="#" 

        onClick={ 
          this.onClickToggle.bind(null, i.id) 
        } 
      > 
        {i.title} 
      </a> 
      &nbsp; 
      <a 
        href="#" 

        onClick={this.onClickRemove.bind(null, i.id)} 
      > 
        ✗
      </a> 
      <p style={{ display: i.display }}> 
        {i.summary} 
      </p> 
    </li> 
  ))} 
</ul> 
```

在这个列表中，有可能有一个文章项目，它将是`<li>`标签中的所有内容。

单单 JSX 就展示了 UI 结构如何可以被分解成更小的 React 组件。没有声明性的 JSX 标记，这种重构练习将会很困难。

# 实现文章列表组件

文章列表组件的实现如下：

```jsx
import React, { Component } from 'react';

export default class ArticleList extends Component {
  render() {
    // The properties include things that are passed in
    // from the feature component. This includes the list
    // of articles to render, and the two event handlers
    // that change state of the feature component.
    const { articles, onClickToggle, onClickRemove } = this.props;

    return (
      <ul>
        {articles.map(article => (
          <li key={article.id}>
            {/* The "onClickToggle()" callback changes
                the state of the "MyFeature" component. */}
            <a
              href={`#${article.id}`}
              title="Toggle Summary"
              onClick={onClickToggle.bind(null, article.id)}
            >
              {article.title}
            </a>
            &nbsp;
            {/* The "onClickRemove()" callback changes
                the state of the "MyFeature" component. */}
            <a
              href={`#${article.id}`}
              title="Remove"
              onClick={onClickRemove.bind(null, article.id)}
            >
              ✗
            </a>
            <p style={{ display: article.display }}>
              {article.summary}
            </p>
          </li>
        ))}
      </ul>
    );
  }
}
```

你只需从庞大的组件中取出相关的 JSX，并放到这里。现在让我们看看功能组件 JSX 是什么样的：

```jsx
render() {
  const { articles, title, summary } = this.data.toJS();

  return (
    <section>
      <header>
        <h1>Articles</h1>
        <input
          placeholder="Title"
          value={title}
          onChange={this.onChangeTitle}
        />
        <input
          placeholder="Summary"
          value={summary}
          onChange={this.onChangeSummary}
        />
        <button onClick={this.onClickAdd}>Add</button>
      </header>

      {/* Now the list of articles is rendered by the
           "ArticleList" component. This component can
           now be used in several other components. */}
      <ArticleList
        articles={articles}
        onClickToggle={this.onClickToggle}
        onClickRemove={this.onClickRemove}
      />
    </section>
  );
} 
```

文章列表现在由`<ArticleList>`组件渲染。要渲染的文章列表作为属性传递给这个组件，以及两个事件处理程序。

等等，为什么我们要将事件处理程序传递给子组件？原因是`ArticleList`组件不需要担心状态或状态如何改变。它只关心呈现内容，并确保适当的事件回调连接到适当的 DOM 元素。这是我稍后在本章中会扩展的*容器组件*概念。

# 实现文章项目组件

在实现文章列表组件之后，您可能会决定进一步拆分此组件，因为该项目可能会在另一页上的另一个列表中呈现。实现文章列表项作为其自己的组件最重要的一点是，我们不知道标记将来会如何改变。

另一种看待它的方式是，如果事实证明我们实际上不需要该项目作为其自己的组件，这个新组件并不会引入太多间接性或复杂性。话不多说，这就是文章项目组件：

```jsx
import React, { Component } from 'react';

export default class ArticleItem extends Component {
  render() {
    // The "article" is mapped from the "ArticleList"
    // component. The "onClickToggle()" and
    // "onClickRemove()" event handlers are passed
    // all the way down from the "MyFeature" component.
    const { article, onClickToggle, onClickRemove } = this.props;

    return (
      <li>
        {/* The "onClickToggle()" callback changes
            the state of the "MyFeature" component. */}
        <a
          href={`#{article.id}`}
          title="Toggle Summary"
          onClick={onClickToggle.bind(null, article.id)}
        >
          {article.title}
        </a>
        &nbsp;
        {/* The "onClickRemove()" callback changes
            the state of the "MyFeature" component. */}
        <a
          href={`#{article.id}`}
          title="Remove"
          onClick={onClickRemove.bind(null, article.id)}
        >
          ✗
        </a>
        <p style={{ display: article.display }}>{article.summary}</p>
      </li>
    );
  }
}

```

这是由`ArticleList`组件呈现的新的`ArticleItem`组件：

```jsx
import React, { Component } from 'react';
import ArticleItem from './ArticleItem';

export default class ArticleList extends Component {
  render() {
    // The properties include things that are passed in
    // from the feature component. This includes the list
    // of articles to render, and the two event handlers
    // that change state of the feature component. These,
    // in turn, are passed to the "ArticleItem" component.
    const { articles, onClickToggle, onClickRemove } = this.props;

    // Now this component maps to an "<ArticleItem>" collection.
    return (
      <ul>
        {articles.map(i => (
          <ArticleItem
            key={i.id}
            article={i}
            onClickToggle={onClickToggle}
            onClickRemove={onClickRemove}
          />
        ))}
      </ul>
    );
  }
}
```

您看到这个列表只是映射了文章列表吗？如果您想要实现另一个还进行一些过滤的文章列表呢？如果是这样，拥有可重用的`ArticleItem`组件是有益的。

# 实现添加文章组件

现在你已经完成了文章列表，是时候考虑用于添加新文章的表单控件了。让我们为这个功能的这一方面实现一个组件：

```jsx
import React, { Component } from 'react';

export default class AddArticle extends Component {
  render() {
    const {
      name,
      title,
      summary,
      onChangeTitle,
      onChangeSummary,
      onClickAdd
    } = this.props;

    return (
      <section>
        <h1>{name}</h1>
        <input
          placeholder="Title"
          value={title}
          onChange={onChangeTitle}
        />
        <input
          placeholder="Summary"
          value={summary}
          onChange={onChangeSummary}
        />
        <button onClick={onClickAdd}>Add</button>
      </section>
    );
  }
}

```

现在，您的功能组件只需要呈现`<AddArticle>`和`<ArticleList>`组件：

```jsx
render() { 
  const {  
    articles,  
    title,  
    summary, 
  } = this.state.data.toJS(); 

  return ( 
    <section> 
      { /* Now the add article form is rendered by the 
           "AddArticle" component. This component can 
           now be used in several other components. */ } 
      <AddArticle 
        name="Articles" 
        title={title} 
        summary={summary} 
        onChangeTitle={this.onChangeTitle} 
        onChangeSummary={this.onChangeSummary} 
        onClickAdd={this.onClickAdd} 
      /> 

      { /* Now the list of articles is rendered by the 
           "ArticleList" component. This component can 
           now be used in several other components. */ } 
      <ArticleList 
        articles={articles} 
        onClickToggle={this.onClickToggle} 
        onClickRemove={this.onClickRemove} 
      /> 
    </section> 
  ); 
} 
```

该组件的重点是功能数据，同时它会推迟到其他组件来呈现 UI 元素。

# 使组件功能化

在实现这些新组件时，您可能已经注意到它们除了使用属性值呈现 JSX 之外没有任何职责。这些组件是*纯函数组件*的良好候选者。每当您遇到仅使用属性值的组件时，最好将它们制作成功能性组件。首先，这明确表明组件不依赖于任何状态或生命周期方法。它还更有效，因为当 React 检测到组件是函数时，它不会执行太多工作。

这是文章列表组件的功能版本：

```jsx
import React from 'react';
import ArticleItem from './ArticleItem';

export default ({ articles, onClickToggle, onClickRemove }) => (
  <ul>
    {articles.map(i => (
      <ArticleItem
        key={i.id}
        article={i}
        onClickToggle={onClickToggle}
        onClickRemove={onClickRemove}
      />
    ))}
  </ul>
);
```

这是文章项目组件的功能版本：

```jsx
import React from 'react';

export default ({ article, onClickToggle, onClickRemove }) => (
  <li>
    {/* The "onClickToggle()" callback changes
         the state of the "MyFeature" component. */}
    <a
      href={`#${article.id}`}
      title="Toggle Summary"
      onClick={onClickToggle.bind(null, article.id)}
    >
      {article.title}
    </a>
    &nbsp;
    {/* The "onClickRemove()" callback changes
         the state of the "MyFeature" component. */}
    <a
      href={`#${article.id}`}
      title="Remove"
      onClick={onClickRemove.bind(null, article.id)}
    >
      ✗
    </a>
    <p style={{ display: article.display }}>{article.summary}</p>
  </li>
);
```

这是添加文章组件的功能版本：

```jsx
import React from 'react';

export default ({
  name,
  title,
  summary,
  onChangeTitle,
  onChangeSummary,
  onClickAdd
}) => (
  <section>
    <h1>{name}</h1>
    <input
      placeholder="Title"
      value={title}
      onChange={onChangeTitle}
    />
    <input
      placeholder="Summary"
      value={summary}
      onChange={onChangeSummary}
    />
    <button onClick={onClickAdd}>Add</button>
  </section>
);
```

使组件变成功能性的另一个好处是，减少了引入不必要方法或其他数据的机会。

# 利用渲染属性

想象一下实现一个由几个较小的组件组成的特性，就像你在本章中一直在做的那样。`MyFeature`组件依赖于`ArticleList`和`AddArticle`。现在想象一下，在应用程序的不同部分使用`MyFeature`，在那里使用不同的`ArticleList`或`AddArticle`的实现是有意义的。根本的挑战是用一个组件替换另一个组件。

渲染属性是解决这一挑战的一种好方法。其思想是，你向组件传递一个属性，其值是一个返回要渲染的组件的函数。这样，你可以根据需要配置子组件，而不是让特性组件直接依赖它们；你可以将它们作为渲染属性值传递进去。

**渲染属性**不是 React 16 的新特性。它是一种技术，其流行程度与 React 16 的发布同时增加。这是一种官方认可的处理依赖和替换问题的方法。你可以在这里阅读更多关于渲染属性的内容：[`reactjs.org/docs/render-props.html`](https://reactjs.org/docs/render-props.html)让我们来看一个例子。不是让`MyFeature`直接依赖于`AddArticle`和`ArticleList`，你可以将它们作为渲染属性传递。当`MyFeature`使用渲染属性来填补`<AddArticle>`和`<ArticleList>`原来的位置时，`MyFeature`的`render()`方法是什么样子的：

```jsx
// Now when <MyFeature> is rendered, it uses render props to
// render <ArticleList> and <AddArticle>. It no longer has
// a direct dependency to these components.
render() {
  const { articles, title, summary } = this.data.toJS();
  const {
    props: { addArticle, articleList },
    onClickAdd,
    onClickToggle,
    onClickRemove,
    onChangeTitle,
    onChangeSummary
  } = this;

  return (
    <section>
      {addArticle({
        title,
        summary,
        onChangeTitle,
        onChangeSummary,
        onClickAdd
      })}
      {articleList({ articles, onClickToggle, onClickRemove })}
    </section>
  );
}
```

`addArticle()`和`articleList()`函数被调用，传递的是与`<AddArticle>`和`<ArticleList>`应该传递的相同的属性值。现在的区别是，这个模块不再将`AddArticle`或`ArticleList`作为依赖导入。

现在让我们来看一下`index.js`，在这里`<MyFeature>`被渲染：

```jsx
// <MyFeature> is now passed a "addArticle" and a "articleList"
// property. These are functions that return components to render.
render(
  <MyFeature
    addArticle={({
      title,
      summary,
      onChangeTitle,
      onChangeSummary,
      onClickAdd
    }) => (
      <AddArticle
        name="Articles"
        title={title}
        summary={summary}
        onChangeTitle={onChangeTitle}
        onChangeSummary={onChangeSummary}
        onClickAdd={onClickAdd}
      />
    )}
    articleList={({ articles, onClickToggle, onClickRemove }) => (
      <ArticleList
        articles={articles}
        onClickToggle={onClickToggle}
        onClickRemove={onClickRemove}
      />
    )}
  />,
  document.getElementById('root')
);
```

这里现在发生的事情比只渲染`<MyFeature>`时要多得多。让我们分解一下为什么会这样。在这里，您传递了`addArticle`和`articleList`渲染属性。这些属性值是从`MyComponent`接受参数值的函数。例如，`onClickToggle()`函数来自`MyFeature`，用于更改该组件的状态。您可以使用渲染属性函数将其传递给将要呈现的组件，以及任何其他值。这些函数的返回值最终被呈现。

# 呈现组件树

让我们花点时间来反思一下在本章中我们已经取得的成就。曾经是单片的功能组件最终几乎完全专注于*状态数据*。它处理了初始状态并处理了状态的转换，如果有的话，它还会处理获取状态的网络请求。这是 React 应用程序中典型的*容器组件*，也是数据的起点。

您实现的新组件，用于更好地组合功能，是这些数据的接收者。这些组件与它们的容器之间的区别在于，它们只关心在它们呈现时传递给它们的属性。换句话说，它们只关心特定时间点的*数据快照*。从这里，这些组件可能将属性数据作为属性传递给它们自己的子组件。组合 React 组件的通用模式如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/2cfd94f4-e9eb-48f0-bc45-3f120c2c3055.png)

容器组件通常只包含一个直接子组件。在这个图表中，您可以看到容器既有一个项目详细信息组件，也有一个列表组件。当然，这两个类别会有所不同，因为每个应用程序都是不同的。这种通用模式有三个级别的组件组合。数据从容器一直流向实用组件。

一旦添加了超过三层，应用程序架构就变得难以理解。会有偶尔需要添加四层 React 组件的情况，但一般情况下，应该避免这样做。

# 功能组件和实用组件

在庞大的组件示例中，你开始时只有一个完全专注于某个特性的组件。这意味着该组件在应用程序的其他地方几乎没有效用。

这是因为顶层组件处理应用程序状态。**有状态的组件**在任何其他上下文中都很难使用。当你重构庞大的特性组件时，你创建了更远离数据的新组件。一般规则是，你的组件离有状态数据越远，它们的效用就越大，因为它们的属性值可以从应用程序的任何地方传递进来。

# 总结

本章是关于避免庞大的组件设计。然而，在任何 React 组件的设计中，庞大的组件通常是一个必要的起点。

你开始学习不同的 HTML 元素具有不同程度的效用。接下来，你了解了庞大的 React 组件的问题，并演示了如何实现庞大的组件。

然后，你花了几节课学习如何将庞大的组件重构为更可持续的设计。通过这个练习，你学到了容器组件只需要考虑处理状态，而较小的组件具有更多的效用，因为它们的属性值可以从任何地方传递进来。你还学到了可以使用渲染属性更好地控制组件的依赖关系和替换。

在下一章中，你将学习关于 React 组件生命周期。这对于实现容器组件来说是一个特别相关的话题。

# 测试你的知识

1.  为什么应该避免庞大的 React 组件？

1.  因为一旦组件达到一定的大小，整个应用程序的性能就会开始受到影响。

1.  因为它们难以理解，并且难以在以后重构为更小的可重用组件。

1.  你不需要担心避免庞大的组件。

1.  为什么要使组件功能化？

1.  功能组件只依赖于传递给它的属性值。它们不依赖于状态或生命周期方法，这两者都是潜在的问题来源。

1.  功能组件更容易阅读。

1.  不应该使组件功能化，即使它们没有任何状态。

1.  渲染属性如何简化 React 应用程序？

1.  它们减少了你需要为给定组件编写的代码量。

1.  它们不会简化 React 应用程序。

1.  它们减少了组件的直接依赖数量，允许您组合新的行为。

# 更多阅读

点击以下链接获取更多信息：

+   [`reactjs.org/docs/render-props.html`](https://reactjs.org/docs/render-props.html)

+   [`reactjs.org/docs/components-and-props.html#functional-and-class-components`](https://reactjs.org/docs/components-and-props.html#functional-and-class-components)


# 第六章：React 组件生命周期

本章的目标是让您了解 React 组件的生命周期以及如何编写响应生命周期事件的代码。您将学习为什么组件首先需要生命周期。然后，您将使用这些方法实现几个初始化其属性和状态的组件。

接下来，您将学习如何通过避免在不必要时进行渲染来优化组件的渲染效率。然后，您将了解如何在 React 组件中封装命令式代码以及在组件卸载时如何进行清理。最后，您将学习如何使用新的 React 16 生命周期方法捕获和处理错误。

# 组件为什么需要生命周期

React 组件经历生命周期。实际上，您在本书中迄今为止在组件中实现的`render()`方法实际上是一个生命周期方法。渲染只是 React 组件中的一个生命周期事件。

例如，当组件挂载到 DOM 时，当组件更新时等都有生命周期事件。生命周期事件是另一个移动部分，因此您希望将其保持最少。正如您将在本章中学到的那样，一些组件确实需要响应生命周期事件以执行初始化、渲染启发式、在组件从 DOM 中卸载时进行清理，或者处理组件抛出的错误。

以下图表让您了解组件如何通过其生命周期流程，依次调用相应的方法：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/d221b7fd-e25f-492e-a4bb-dc37f6939493.png)

这是 React 组件的两个主要生命周期流程。第一个发生在组件初始渲染时。第二个发生在组件更新时。以下是每个方法的大致概述：

+   `getDerivedStateFromProps()`: 此方法允许您根据组件的属性值更新组件的状态。当组件首次渲染和接收新的属性值时，将调用此方法。

+   `render()`: 返回组件要渲染的内容。当组件首次挂载到 DOM 时，当它接收新的属性值时以及调用`setState()`时都会调用此方法。

+   `componentDidMount()`: 这在组件挂载到 DOM 后调用。这是您可以执行组件初始化工作的地方，例如获取数据。

+   `shouldComponentUpdate()`: 您可以使用此方法将新状态或属性与当前状态或属性进行比较。然后，如果不需要重新渲染组件，可以返回 false。此方法用于使您的组件更有效。

+   `getSnapshotBeforeUpdate()`: 此方法允许您在实际提交到 DOM 之前直接在组件的 DOM 元素上执行操作。此方法与`render()`的区别在于`getSnapshotBeforeUpdate()`不是异步的。使用`render()`时，调用它和实际在 DOM 中进行更改之间的 DOM 结构可能会发生变化的可能性很大。

+   `componentDidUpdate()`: 当组件更新时调用此方法。您很少需要使用此方法。

此图表中未包括的另一个生命周期方法是`componentWillUnmount()`。这是组件即将被移除时调用的唯一生命周期方法。我们将在本章末尾看到如何使用此方法的示例。在此之前，让我们开始编码。

# 初始化属性和状态

在本节中，您将看到如何在 React 组件中实现初始化代码。这涉及使用在组件首次创建时调用的生命周期方法。首先，您将实现一个基本示例，该示例使用来自 API 的数据设置组件。然后，您将看到如何从属性初始化状态，以及如何在属性更改时更新状态。

# 获取组件数据

当初始化组件时，您将希望填充其状态或属性。否则，组件除了其骨架标记之外将没有任何内容可渲染。例如，假设您想要渲染以下用户列表组件：

```jsx
import React from 'react';
import { Map } from 'immutable';

// This component displays the passed-in "error"
// property as bold text. If it's null, then
// nothing is rendered.
const ErrorMessage = ({ error }) =>
  Map([[null, null]]).get(error, <strong>{error}</strong>);

// This component displays the passed-in "loading"
// property as italic text. If it's null, then
// nothing is rendered.
const LoadingMessage = ({ loading }) =>
  Map([[null, null]]).get(loading, <em>{loading}</em>);

export default ({
  error, 
  loading,
  users
}) => (
  <section>
    {/* Displays any error messages... */}
    <ErrorMessage error={error} />

    {/* Displays any loading messages, while
         waiting for the API... */}
    <LoadingMessage loading={loading} />

    {/* Renders the user list... */}
    <ul>{users.map(i => <li key={i.id}>{i.name}</li>)}</ul>
  </section>
);
```

此 JSX 依赖于三个数据：

+   加载中：在获取 API 数据时显示此消息

+   `error`: 如果出现问题，将显示此消息

+   `users`: 从 API 获取的数据

此处使用了两个辅助组件：`ErrorMessage`和`LoadingMessage`。它们分别用于格式化`error`和`loading`状态。但是，如果`error`或`loading`为 null，您不希望在组件中引入命令式逻辑来处理此情况。这就是为什么您使用`Immutable.js`映射的一个很酷的小技巧：

1.  您创建了一个具有单个**键值对**的映射。键为 null，值也为 null。

1.  您使用`error`或`loading`属性调用`get()`。如果`error`或`loading`属性为 null，则找到键并且不渲染任何内容。

1.  `get()`接受第二个参数，如果找不到键，则返回该参数。这是您传递您的*真值*值并完全避免命令逻辑的地方。这个特定的组件很简单，但是当存在两种以上可能性时，这种技术尤其强大。

您应该如何进行 API 调用并使用响应来填充`users`集合？答案是使用一个容器组件进行 API 调用，然后渲染`UserList`组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

import { users } from './api';
import UserList from './UserList';

export default class UserListContainer extends Component {
  state = {
    data: fromJS({
      error: null,
      loading: 'loading...',
      users: []
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // When component has been rendered, "componentDidMount()"
  // is called. This is where we should perform asynchronous
  // behavior that will change the state of the component.
  // In this case, we're fetching a list of users from
  // the mock API.
  componentDidMount() {
    users().then(
      result => {
        // Populate the "users" state, but also
        // make sure the "error" and "loading"
        // states are cleared.
        this.data = this.data
          .set('loading', null)
          .set('error', null)
          .set('users', fromJS(result.users));
      },
      error => {
        // When an error occurs, we want to clear
        // the "loading" state and set the "error"
        // state.
        this.data = this.data
          .set('loading', null)
          .set('error', error);
      }
    );
  }

  render() {
    return <UserList {...this.data.toJS()} />;
  }
}
```

让我们来看看`render()`方法。它的工作是渲染`<UserList>`组件，并将`this.state`作为属性传递。实际的 API 调用发生在`componentDidMount()`方法中。此方法在组件挂载到 DOM 后调用。

由于`componentDidMount()`的命名，React 开发人员认为在发出组件数据的请求之前等待组件挂载到 DOM 是不好的。换句话说，如果 React 在发送请求之前必须执行大量工作，用户体验可能会受到影响。实际上，获取数据是一个异步任务，在`render()`之前或之后启动它对您的应用程序来说没有真正的区别。

您可以在这里阅读更多信息：[`reactjs.org/blog/2018/03/27/update-on-async-rendering.html`](https://reactjs.org/blog/2018/03/27/update-on-async-rendering.html)

一旦 API 调用返回数据，`users`集合就会被填充，导致`UserList`重新渲染自身，只是这一次，它有了需要的数据。让我们来看看这里使用的`users()`模拟 API 函数调用：

```jsx
// Returns a promise that's resolved after 2
// seconds. By default, it will resolve an array
// of user data. If the "fail" argument is true,
// the promise is rejected.
export function users(fail) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      if (fail) {
        reject('epic fail');
      } else {
        resolve({
          users: [
            { id: 0, name: 'First' },
            { id: 1, name: 'Second' },
            { id: 2, name: 'Third' },
          ],
        });
      }
    }, 2000);
  });
}
```

它返回一个在 2 秒后解析为数组的 promise。Promise 是模拟诸如 API 调用之类的东西的好工具，因为它们使您能够在 React 组件中使用不止 HTTP 调用作为数据源。例如，您可能正在从本地文件中读取数据，或者使用返回解析来自各种来源的数据的库。

当`loading`状态为字符串，`users`状态为空数组时，`UserList`组件渲染如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/96766a75-d06b-4aa7-bd38-854a10e61098.png)

当`loading`为`null`且`users`不为空时，它渲染如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/e2a88063-51bf-4331-b5cc-544e7d75ea7b.png)

我想再次强调`UserListContainer`和`UserList`组件之间的责任分离。因为容器组件处理生命周期管理和实际的 API 通信，你可以创建一个通用的用户列表组件。事实上，它是一个不需要任何状态的功能组件，这意味着你可以在应用程序中的其他容器组件中重用它。

# 使用属性初始化状态

前面的例子向你展示了如何通过在`componentDidMount()`生命周期方法中进行 API 调用来初始化容器组件的状态。然而，组件状态中唯一填充的部分是`users`集合。你可能想填充其他不来自 API 端点的状态部分。

例如，当状态初始化时，`error`和`loading`状态消息已经设置了默认值。这很好，但是如果渲染`UserListContainer`的代码想要使用不同的加载消息怎么办？你可以通过允许属性覆盖默认状态来实现这一点。让我们继续完善`UserListContainer`组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

import { users } from './api';
import UserList from './UserList';

class UserListContainer extends Component {
  state = {
    data: fromJS({
      error: null,
      users: []
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // When component has been rendered, "componentDidMount()"
  // is called. This is where we should perform asynchronous
  // behavior that will change the state of the component.
  // In this case, we're fetching a list of users from
  // the mock API.
  componentDidMount() {
    users().then(
      result => {
        // Populate the "users" state, but also
        // make sure the "error" and "loading"
        // states are cleared.
        this.data = this.data
          .set('error', null)
          .set('users', fromJS(result.users));
      },
      error => {
        // When an error occurs, we want to clear
        // the "loading" state and set the "error"
        // state.
        this.data = this.data
          .set('loading', null)
          .set('error', error);
      }
    );
  }

  render() {
    return <UserList {...this.data.toJS()} />;
  }

  // Called right before render, you can use this method
  // to update the state of the component based on prop
  // values.
  static getDerivedStateFromProps(props, state) {
    return {
      ...state,
      data: state.data.set(
        'loading',
        state.data.get('users').size === 0 ? props.loading : null
      )
    };
  }
}

UserListContainer.defaultProps = {
  loading: 'loading...'
};

export default UserListContainer;

```

`loading`属性不再具有默认字符串值。相反，`defaultProps`为属性提供默认值。新的生命周期方法是`getDerivedStateFromProps()`。它使用`loading`属性来设置`loading`状态。由于`loading`属性有一个默认值，所以只需改变状态是安全的。该方法在组件挂载之前和组件的后续重新渲染时被调用。

这个方法是静态的，因为在 React 16 中有内部变化。预期这个方法的行为像一个纯函数，没有副作用。如果这个方法是一个实例方法，你将可以访问组件上下文，并且副作用将很常见。

使用这种新的 React 16 方法的挑战在于它在初始渲染和后续重新渲染时都会被调用。在 React 16 之前，你可以使用`componentWillMount()`方法来运行只在初始渲染之前运行的代码。在这个例子中，你必须检查`users`集合中是否有值，然后再将`loading`状态设置为 null - 你不知道这是初始渲染还是第 40 次渲染。

现在让我们看看如何将状态数据传递给`UserListContainer`：

```jsx
import React from 'react';
import { render } from 'react-dom';

import UserListContainer from './UserListContainer';

// Renders the component with a "loading" property.
// This value ultimately ends up in the component state.
render(
  <UserListContainer loading="playing the waiting game..." />,
  document.getElementById('root')
);

```

当首次渲染`UserList`时，初始加载消息是什么样子的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/70f311e6-6a6c-4c1f-8d6c-dcd3eb3496c3.png)

仅仅因为组件有状态并不意味着你不能进行定制。接下来，你将学习这个概念的一个变种——使用属性更新组件状态。

# 使用属性更新状态

你已经看到了`componentDidMount()`和`getDerivedStateFromProps()`生命周期方法如何帮助你的组件获取所需的数据。还有一个情景你需要考虑——重新渲染组件容器。

让我们来看一个简单的`button`组件，它会跟踪被点击的次数：

```jsx
import React from 'react';

export default ({
  clicks,
  disabled,
  text,
  onClick
}) => (
  <section>
    {/* Renders the number of button clicks,
         using the "clicks" property. */}
    <p>{clicks} clicks</p>

    {/* Renders the button. It's disabled state
         is based on the "disabled" property, and
         the "onClick()" handler comes from the
         container component. */}
    <button disabled={disabled} onClick={onClick}>
      {text}
    </button>
  </section>
);

```

现在，让我们为这个功能实现一个容器组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

import MyButton from './MyButton';

class MyFeature extends Component {
  state = {
    data: fromJS({
      clicks: 0,
      disabled: false,
      text: ''
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // Click event handler, increments the "click" count.
  onClick = () => {
    this.data = this.data.update('clicks', c => c + 1);
  };

  // Renders the "<MyButton>" component, passing it the
  // "onClick()" handler, and the state as properties.
  render() {
    return <MyButton onClick={this.onClick} {...this.data.toJS()} />;
  }

  // If the component is re-rendered with new
  // property values, this method is called with the
  // new property values. If the "disabled" property
  // is provided, we use it to update the "disabled"
  // state. Calling "setState()" here will not
  // cause a re-render, because the component is already
  // in the middle of a re-render.
  static getDerivedStateFromProps({ disabled, text }, state) {
    return {
      ...state,
      data: state.data.set('disabled', disabled).set('text', text)
    };
  }
}

MyFeature.defaultProps = {
  text: 'A Button'
};

export default MyFeature;

```

与前面的例子相同的方法在这里也被使用。`getDerivedStateFromProps()`方法在每次渲染之前被调用，这是你可以使用属性值来确定组件状态是否应该更新的地方。让我们看看如何重新渲染这个组件以及状态是否如预期般行为：

```jsx
import React from 'react';
import { render as renderJSX } from 'react-dom';

import MyFeature from './MyFeature';

// Determines the state of the button
// element in "MyFeature".
let disabled = true;

function render() {
  // Toggle the state of the "disabled" property.
  disabled = !disabled;

  renderJSX(
    <MyFeature {...{ disabled }} />,
    document.getElementById('root')
  );
}

// Re-render the "<MyFeature>" component every
// 3 seconds, toggling the "disabled" button
// property.
setInterval(render, 3000);

render();

```

果然，一切都按计划进行。每当按钮被点击时，点击计数器都会更新。`<MyFeature>`每 3 秒重新渲染一次，切换按钮的`disabled`状态。当按钮重新启用并且点击恢复时，计数器会从上次停止的地方继续。

这是`MyButton`组件在首次渲染时的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/81a1ef60-a155-482b-aa83-29f6abb95d2b.png)

这是在点击了几次后，按钮进入禁用状态后的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/da9f9124-eb36-41c7-b4bb-beb8438a46c6.png)

# 优化渲染效率

接下来你要学习的下一个生命周期方法用于实现改进组件渲染性能的启发式。你会发现，如果组件的状态没有改变，那么就没有必要进行渲染。然后，你将实现一个组件，该组件使用来自 API 的特定元数据来确定是否需要重新渲染组件。

# 渲染还是不渲染

`shouldComponentUpdate()`生命周期方法用于确定当被要求渲染时组件是否会进行渲染。例如，如果实现了这个方法，并返回 false，那么组件的整个生命周期都会被中断，不会进行渲染。如果组件渲染了大量数据并且经常重新渲染，这个检查就非常重要。关键是要知道组件状态是否已经改变。

这就是不可变数据的美妙之处——你可以轻松地检查它是否发生了变化。如果你正在使用`Immutable.js`等库来控制组件的状态，这一点尤为真实。让我们看一个简单的列表组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

export default class MyList extends Component {
  state = {
    data: fromJS({
      items: [...Array(5000).keys()]
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // If this method returns false, the component
  // will not render. Since we're using an Immutable.js
  // data structure, we simply need to check for equality.
  // If "state.data" is the same, then there's no need to
  // render because nothing has changed since the last render.
  shouldComponentUpdate(props, state) {
    return this.data !== state.data;
  }

  // Renders the complete list of items, even if it's huge.
  render() {
    const items = this.data.get('items');

    return <ul>{items.map(i => <li key={i}>{i}</li>)}</ul>;
  }
}

```

`items`状态初始化为一个包含 5000 个项目的`Immutable.js` `List`。这是一个相当大的集合，所以你不希望 React 内部的虚拟 DOM 不断地对比这个列表。虚拟 DOM 在它所做的事情上是高效的，但远不及能执行简单的渲染检查的代码高效。你在这里实现的`shouldComponentRender()`方法正是这样做的。它比较新状态和当前状态；如果它们是相同的对象，完全绕过虚拟 DOM。

现在，让我们让这个组件开始工作，看看你能获得什么样的效率提升：

```jsx
import React from 'react';
import { render as renderJSX } from 'react-dom';

import MyList from './MyList';

// Renders the "<MyList>" component. Then, it sets
// the state of the component by changing the value
// of the first "items" element. However, the value
// didn't actually change, so the same Immutable.js
// structure is reused. This means that
// "shouldComponentUpdate()" will return false.
function render() {
  const myList = renderJSX(
    <MyList />,
    document.getElementById('root')
  );

  // Not actually changing the value of the first
  // "items" element. So, Immutable.js recognizes
  // that nothing changed, and instead of
  // returning a new object, it returns the same
  // "myList.data" reference.
  myList.data = myList.data.setIn(['items', 0], 0);
}

// Instead of performing 500,000 DOM operations,
// "shouldComponentUpdate()" turns this into
// 5000 DOM operations.
for (let i = 0; i < 100; i++) {
  render();
}

```

你正在循环渲染`<MyList>`。每次迭代都有 5000 个列表项要渲染。由于状态没有改变，`shouldComponentUpdate()`的调用在每次迭代中都返回`false`。出于性能原因，这很重要，因为迭代次数很多。在真实应用中，你不会有代码在紧密循环中重新渲染组件。这段代码旨在测试 React 的渲染能力。如果你注释掉`shouldComponentUpdate()`方法，你就会明白我的意思。这个组件的性能概况如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/1ade8d3e-1c1c-4b04-80df-f819ab16b356.png)

初始渲染时间最长——几百毫秒。但接下来有很多微小的时间片段，对用户体验完全不可感知。这些是`shouldComponentUpdate()`返回 false 的结果。现在让我们注释掉这个方法，看看这个概况会如何改变：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/703a99d7-f415-4b53-9187-3dac6cf212be.png)

没有`shouldComponentUpdate()`，最终结果是更长的时间片段，对用户体验有极大的负面影响。

你可能注意到，我们实际上是使用`Immutable.js`的`setIn()`来改变状态。这应该会导致状态改变，对吧？实际上，这将返回相同的`Immutable.js`实例，原因很简单，我们设置的值与当前值相同：`0`。当没有发生改变时，`Immutable.js`方法返回相同的对象，因为它没有发生变化。

# 使用元数据优化渲染

在本节中，你将学习如何使用 API 响应的元数据来确定组件是否应该重新渲染自己。这里是一个简单的用户详情组件：

```jsx
import React, { Component } from 'react';

export default class MyUser extends Component {
  state = {
    modified: new Date(),
    first: 'First',
    last: 'Last'
  };

  // The "modified" property is used to determine
  // whether or not the component should render.
  shouldComponentUpdate(props, state) {
    return Number(state).modified > Number(this.state.modified);
  }

  render() {
    const { modified, first, last } = this.state;

    return (
      <section>
        <p>{modified.toLocaleString()}</p>
        <p>{first}</p>
        <p>{last}</p>
      </section>
    );
  }
}
```

`shouldComponentUpdate()`方法正在比较新的`modified`状态和旧的`modified`状态。这段代码假设`modified`值是一个反映 API 返回的数据实际修改时间的日期。这种方法的主要缺点是`shouldComponentUpdate()`方法现在与 API 数据紧密耦合。优点是，你可以像使用不可变数据一样获得性能提升。

这就是这个启发式方法的实际效果：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyUser from './MyUser';

// Performs the initial rendering of "<MyUser>".
const myUser = render(<MyUser />, document.getElementById('root'));

// Sets the state, with a new "modified" value.
// Since the modified state has changed, the
// component will re-render.
myUser.setState({
  modified: new Date(),
  first: 'First1',
  last: 'Last1'
});

// The "first" and "last" states have changed,
// but the "modified" state has not. This means
// that the "First2" and "Last2" values will
// not be rendered.
myUser.setState({
  first: 'First2',
  last: 'Last2'
});
```

`MyUser`组件现在完全依赖于`modified`状态。如果它不大于先前的`modified`值，就不会发生渲染。

在渲染两次后，组件的外观如下：

在这个例子中，我没有使用不可变状态数据。在本书中，我将使用普通的 JavaScript 对象作为简单示例的状态。`Immutable.js`是这项工作的好工具，所以我会经常使用它。与此同时，我想明确指出`Immutable.js`并不需要在每种情况下都使用。

# 渲染命令式组件

到目前为止，在本书中，你渲染的所有内容都是直接的声明式 HTML。生活从来都不是那么简单：有时你的 React 组件需要在底层实现一些命令式的代码。

这就是关键——隐藏命令式操作，使渲染组件的代码不必触及它。在本节中，你将实现一个简单的 jQuery UI 按钮 React 组件，以便你可以看到相关的生命周期方法如何帮助你封装命令式代码。

# 渲染 jQuery UI 小部件

jQuery UI 小部件库在标准 HTML 之上实现了几个小部件。它使用渐进增强技术，在支持新功能的浏览器中增强基本 HTML。为了使这些小部件工作，你首先需要以某种方式将 HTML 渲染到 DOM 中；然后，进行命令式函数调用来创建和与小部件交互。

在这个例子中，你将创建一个 React 按钮组件，作为 jQuery UI 小部件的包装器。使用 React 组件的人不需要知道，在幕后，它正在进行命令式调用来控制小部件。让我们看看按钮组件的样子：

```jsx
import React, { Component } from 'react';

// Import all the jQuery UI widget stuff...
import $ from 'jquery';
import 'jquery-ui/ui/widgets/button';
import 'jquery-ui/themes/base/all.css';

export default class MyButton extends Component {
  // When the component is mounted, we need to
  // call "button()" to initialize the widget.
  componentDidMount() {
    $(this.button).button(this.props);
  }

  // After the component updates, we need to use
  // "this.props" to update the options of the
  // jQuery UI button widget.
  componentDidUpdate() {
    $(this.button).button('option', this.props);
  }

  // Renders the "<button>" HTML element. The "onClick()"
  // handler will always be a assigned, even if it's a
  // noop function. The "ref" property is used to assign
  // "this.button". This is the DOM element itself, and
  // it's needed by the "componentDidMount()" and
  // "componentDidUpdate()" methods.
  render() {
    return (
      <button
        onClick={this.props.onClick}
        ref={button => {
          this.button = button;
        }}
      />
    );
  }
}

```

jQuery UI 按钮小部件期望`<button>`元素，因此组件呈现为此。还分配了来自组件属性的`onClick()`处理程序。这里还使用了`ref`属性，它将`button`参数分配给`this.button`。这样做的原因是，组件可以直接访问组件的底层 DOM 元素。通常，组件不需要访问任何 DOM 元素，但在这里，您需要向元素发出命令。

例如，在`componentDidMount()`方法中，调用了`button()`函数，并将其属性传递给组件。`componentDidUpdate()`方法执行类似的操作，当属性值更改时调用。现在，让我们看一下按钮容器组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

import MyButton from './MyButton';

class MyButtonContainer extends Component {
  // The initial state is an empty Immutable map, because
  // by default, we won't pass anything to the jQuery UI
  // button widget.
  state = {
    data: fromJS({})
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // When the component is mounted for the first time,
  // we have to bind the "onClick()" handler to "this"
  // so that the handler can set the state.
  componentDidMount() {
    this.data = this.data.merge(this.props, {
      onClick: this.props.onClick.bind(this)
    });
  }

  // Renders the "<MyButton>" component with this
  // component's state as properties.
  render() {
    return <MyButton {...this.state.data.toJS()} />;
  }
}

// By default, the "onClick()" handler is a noop.
// This makes it easier because we can always assign
// the event handler to the "<button>".
MyButtonContainer.defaultProps = {
  onClick: () => {}
};

export default MyButtonContainer;

```

您有一个控制状态的容器组件，然后将其作为属性传递给`<MyButton>`。

`{...data}`语法称为 JSX 扩展属性。这允许您将对象作为属性传递给元素。您可以在此处阅读更多关于此功能的信息。

该组件具有默认的`onClick()`处理函数。但是，您可以将不同的点击处理程序作为属性传递。此外，它会自动绑定到组件上下文，如果处理程序需要更改按钮状态，则这很有用。让我们看一个例子：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyButtonContainer from './MyButtonContainer';

// Simple button event handler that changes the
// "disabled" state when clicked.
function onClick() {
  this.data = this.data.set('disabled', true);
}

render(
  <section>
    {/* A simple button with a simple label. */}
    <MyButtonContainer label="Text" />

    {/* A button with an icon, and a hidden label. */}
    <MyButtonContainer
      label="My Button"
      icon="ui-icon-person"
      showLabel={false}
    />

    {/* A button with a click event handler. */}
    <MyButtonContainer label="Disable Me" onClick={onClick} />
  </section>,
  document.getElementById('root')
);

```

在这里，您有三个 jQuery UI 按钮小部件，每个都由一个 React 组件控制，看不到任何命令式代码。按钮的外观如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/3ef4d930-c2a8-4938-ba32-055e764f300d.png)

# 在组件之后进行清理

在这一部分，您将学习如何在组件之后进行清理。您不必显式地从 DOM 中卸载组件-React 会为您处理。有一些 React 不知道的东西，因此在组件被移除后无法为您清理。

正是为了这些清理任务，`componentWillUnmount()`生命周期方法存在。清理 React 组件之后的一个用例是异步代码。

例如，想象一个组件，在组件首次挂载时发出 API 调用以获取一些数据。现在，想象一下，在 API 响应到达之前，该组件从 DOM 中移除。

# 清理异步调用

如果您的异步代码尝试设置已卸载的组件的状态，将不会发生任何事情。会记录一个警告，并且状态不会被设置。记录这个警告实际上非常重要；否则，您将很难解决微妙的竞争条件错误。

正确的方法是创建可取消的异步操作。这是你在本章前面实现的`users()` API 函数的修改版本：

```jsx
// Adapted from:
// https://facebook.github.io/react/blog/2015/12/16/ismounted-antipattern.html
function cancellable(promise) {
  let cancelled = false;

  // Creates a wrapper promise to return. This wrapper is
  // resolved or rejected based on the wrapped promise, and
  // on the "cancelled" value.
  const promiseWrapper = new Promise((resolve, reject) => {
    promise.then(
      value => {
        return cancelled ? reject({ cancelled: true }) : resolve(value);
      },
      error => {
        return cancelled
          ? reject({ cancelled: true })
          : reject(error);
      }
    );
  });

  // Adds a "cancel()" method to the promise, for
  // use by the React component in "componentWillUnmount()".
  promiseWrapper.cancel = function cancel() {
    cancelled = true;
  };

  return promiseWrapper;
}

export function users(fail) {
  // Make sure that the returned promise is "cancellable", by
  // wrapping it with "cancellable()".
  return cancellable(
    new Promise((resolve, reject) => {
      setTimeout(() => {
        if (fail) {
          reject(fail);
        } else {
          resolve({
            users: [
              { id: 0, name: 'First' },
              { id: 1, name: 'Second' },
              { id: 2, name: 'Third' }
            ]
          });
        }
      }, 4000);
    })
  );
}
```

关键是`cancellable()`函数，它用新的 promise 包装了一个 promise。新的 promise 有一个`cancel()`方法，如果调用则拒绝 promise。它不会改变 promise 同步的实际异步行为。然而，它确实为在 React 组件中使用提供了一个通用和一致的接口。

现在让我们看一个具有取消异步行为能力的容器组件：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';
import { render } from 'react-dom';

import { users } from './api';
import UserList from './UserList';

// When the "cancel" link is clicked, we want to render
// a new element in "#app". This will unmount the
// "<UserListContainer>" component.
const onClickCancel = e => {
  e.preventDefault();

  render(<p>Cancelled</p>, document.getElementById('root'));
};

export default class UserListContainer extends Component {
  state = {
    data: fromJS({
      error: null,
      loading: 'loading...',
      users: []
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  componentDidMount() {
    // We have to store a reference to any async promises,
    // so that we can cancel them later when the component
    // is unmounted.
    this.job = users();

    this.job.then(
      result => {
        this.data = this.data
          .set('loading', null)
          .set('error', null)
          .set('users', fromJS(result.users));
      },

      // The "job" promise is rejected when it's cancelled.
      // This means that we need to check for the "cancelled"
      // property, because if it's true, this is normal
      // behavior.
      error => {
        if (!error.cancelled) {
          this.data = this.data
            .set('loading', null)
            .set('error', error);
        }
      }
    );
  }

  // This method is called right before the component
  // is unmounted. It is here, that we want to make sure
  // that any asynchronous behavior is cleaned up so that
  // it doesn't try to interact with an unmounted component.
  componentWillUnmount() {
    this.job.cancel();
  }

  render() {
    return (
      <UserList onClickCancel={onClickCancel} {...this.data.toJS()} />
    );
  }
}
```

`onClickCancel()`处理程序实际上替换了用户列表。这调用了`componentWillUnmount()`方法，在那里您可以取消`this.job`。值得注意的是，当在`componentDidMount()`中进行 API 调用时，会在组件中存储对 promise 的引用。否则，您将无法取消异步调用。

在进行挂起的 API 调用期间呈现组件时，组件的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/98f270e9-d5a8-4163-8080-aba152c213eb.png)

# 使用错误边界包含错误

React 16 的一个新功能——**错误边界**——允许您处理意外的组件失败。与其让应用程序的每个组件都知道如何处理可能遇到的任何错误，**错误边界**是一个机制，您可以使用它来包装具有错误处理行为的组件。最好将错误边界视为 JSX 的`try`/`catch`语法。

让我们重新访问本章中的第一个示例，其中您使用 API 函数获取了组件数据。`users()`函数接受一个布尔参数，当为 true 时，会导致 promise 被拒绝。这是您想要处理的事情，但不一定是在进行 API 调用的组件中。实际上，`UserListContainer`和`UserList`组件已经设置好了处理这样的 API 错误。挑战在于，如果有很多组件，这将是大量的错误处理代码。此外，错误处理是特定于一个 API 调用的——如果其他地方出了问题怎么办？

以下是您可以用于此示例的`UserListContainer`的修改后源代码：

```jsx
import React, { Component } from 'react';
import { fromJS } from 'immutable';

import { users } from './api';
import UserList from './UserList';

export default class UserListContainer extends Component {
  state = {
    data: fromJS({
      error: null,
      loading: 'loading...',
      users: []
    })
  };

  // Getter for "Immutable.js" state data...
  get data() {
    return this.state.data;
  }

  // Setter for "Immutable.js" state data...
  set data(data) {
    this.setState({ data });
  }

  // When component has been rendered, "componentDidMount()"
  // is called. This is where we should perform asynchronous
  // behavior that will change the state of the component.
  // In this case, we're fetching a list of users from
  // the mock API.
  componentDidMount() {
    users(true).then(
      result => {
        // Populate the "users" state, but also
        // make sure the "error" and "loading"
        // states are cleared.
        this.data = this.data
          .set('loading', null)
          .set('error', null)
          .set('users', fromJS(result.users));
      },
      error => {
        // When an error occurs, we want to clear
        // the "loading" state and set the "error"
        // state.
        this.data = this.data
          .set('loading', null)
          .set('error', error);
      }
    );
  }

  render() {
    // If the error state has a string value in it, it
    // means that something went wrong during the asynchronous
    // data fetching for this component. You can just throw an
    // error using this string instead of rendering.
    if (this.data.get('error') !== null) {
      throw new Error(this.data.get('error'));
    }
    return <UserList {...this.data.toJS()} />;
  }
}
```

这个组件大部分与第一个示例中的相同。第一个区别是对`users()`的调用，现在它传递了 true：

```jsx
componentDidMount() {
  users(true).then(
    ...
```

这个调用将失败，导致错误状态被设置。第二个区别在于`render()`方法：

```jsx
if (this.data.get('error') !== null) {
  throw new Error(this.data.get('error'));
}
```

它不是将错误状态转发到`UserList`组件，而是通过抛出错误而不是尝试渲染更多组件将错误传递回组件树。这里的关键设计变化是，该组件现在假设在组件树的更高位置有某种错误边界，将相应地处理这些错误。

您可能想知道为什么错误在渲染时抛出，而不是在`componentDidMount()`中拒绝承诺时抛出。问题在于像这样异步获取数据意味着 React 内部实际上无法捕获从异步承诺处理程序中抛出的异常。对于可能导致组件失败的异步操作，最简单的解决方案是将错误存储在组件状态中，但如果存在错误，则在实际渲染任何内容之前抛出错误。

现在让我们创建错误边界本身：

```jsx
import React, { Component } from 'react';

// A basic error boundary used to display error messages.
export default class ErrorBoundary extends Component {
  state = {
    error: null
  };

  // This lifecycle method is only called if a component
  // lower in the tree than this component throws an error.
  // You can handle the error however you like in this method,
  // including setting it as a state value so that it can be used
  // for rendering.
  componentDidCatch(error) {
    this.setState({ error });
  }

  // If there's no error, you can just render the boundary's
  // children as usual. If there's an error, you can render
  // the error message while ignoring the child components.
  render() {
    if (this.state.error === null) {
      return this.props.children;
    } else {
      return <strong>{this.state.error.toString()}</strong>;
    }
  }
}
```

这就是`componentDidCatch()`生命周期方法的用法，当它捕获到错误时，设置该组件的错误状态。当渲染时，如果设置了`error`状态，则渲染错误消息。否则，像往常一样渲染子组件。

以下是如何使用这个`ErrorBoundary`组件：

```jsx
import React from 'react';
import { render } from 'react-dom';

import ErrorBoundary from './ErrorBoundary';
import UserListContainer from './UserListContainer';

// The <ErrorBoundary> component can wrap any component you need.
// You can also create different error boundary components that
// render errors differently.
render(
  <ErrorBoundary>
    <UserListContainer />
  </ErrorBoundary>,
  document.getElementById('root')
);
```

`UserListContainer`或其任何子级抛出的任何错误都将被`ErrorBoundary`捕获和处理：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/cba62616-0a38-4e25-93ca-d2bc108b927f.png)

现在，您可以删除传递给`UserListContainer`中的`users()`的参数，以阻止其失败。在`UserList`组件中，假设您有一个错误，尝试在数字上调用`toUpperCase()`：

```jsx
import React from 'react';
import { Map } from 'immutable';

// This component displays the passed-in "loading"
// property as italic text. If it's null, then
// nothing is rendered.
const LoadingMessage = ({ loading }) =>
  Map([[null, null]]).get(loading, <em>{loading}</em>);

export default ({
  error, // eslint-disable-line react/prop-types
  loading, // eslint-disable-line react/prop-types
  users // eslint-disable-line react/prop-types
}) => (
  <section>
    {/* Displays any loading messages, while
         waiting for the API... */}
    <LoadingMessage loading={loading} />

    {/* Attempts to render the user list but throws an
        error by attempting to call toUpperCase() on a number. */}
    <ul>
      {users.map(i => <li key={i.id.toUpperCase()}>{i.name}</li>)}
    </ul>
  </section>
);
```

您将获得不同的错误抛出，但由于它位于与先前错误相同的边界下，它将以相同的方式处理：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/6a30a766-067f-4b42-a24a-d7bdb6cfb950.png)如果您使用`create-react-app`和`react-scripts`运行项目，您可能会注意到应用程序中的每个错误都会有一个错误叠加层，即使这些错误已被错误边界处理。如果您使用右上角的**x**关闭叠加层，您可以看到您的组件如何处理应用程序中的错误。

# 总结

在本章中，您学到了很多关于 React 组件生命周期的知识。我们首先讨论了为什么 React 组件首先需要生命周期。原来 React 不能自动完成所有工作，所以我们需要编写一些代码，在组件生命周期的适当时间运行。

接下来，您实现了几个组件，它们能够从 JSX 属性中获取初始数据并初始化它们的状态。然后，您学会了通过提供`shouldComponentRender()`方法来实现更高效的 React 组件。

您学会了如何隐藏一些组件需要实现的命令式代码，以及如何在异步行为之后进行清理。最后，您学会了如何使用 React 16 的新错误边界功能。

在接下来的章节中，您将学习一些技术，以确保您的组件被传递了正确的属性。

# 测试您的知识

1.  `render()`是一个生命周期方法吗？

1.  是的，`render()`与任何其他生命周期方法没有区别。

1.  不，`render()`只是用来获取组件的内容。

1.  以下哪项是`componentWillUnmount()`方法的有效用法？

1.  删除组件添加的 DOM 元素。

1.  取消组件卸载时将失败的异步操作。

1.  组件即将卸载时记录日志。

1.  哪个生命周期方法被错误边界组件使用？

1.  `componentDidCatch()`

1.  `componentWillCatch()`

1.  `componentError()`

# 进一步阅读

您可以访问以下链接获取更多信息：

+   [`reactjs.org/docs/react-component.html`](https://reactjs.org/docs/react-component.html)

+   [`reactjs.org/docs/state-and-lifecycle.html`](https://reactjs.org/docs/state-and-lifecycle.html)


# 第七章：验证组件属性

在本章中，你将学习关于 React 组件中的属性验证。乍一看，这可能看起来很简单，但这是一个重要的主题，因为它可以使组件无 bug。我将从讨论**可预测的结果**开始，以及如何使组件在整个应用程序中具有可移植性。

接下来，你将通过一些 React 自带的类型检查属性验证器的示例进行学习。然后，你将学习一些更复杂的属性验证场景。最后，我将用一个示例来结束本章，展示如何实现自定义验证器。

# 了解预期结果

在 React 组件中的**属性验证**就像 HTML 表单中的字段验证。验证表单字段的基本原则是让用户知道他们提供了一个不可接受的值。理想情况下，验证错误消息应该清晰明了，以便用户可以轻松地解决问题。通过 React 组件属性验证，你正在做同样的事情——让意外值的情况变得容易修复。属性验证增强了开发人员的体验，而不是用户体验。

属性验证的关键方面是了解作为属性值传递到组件的内容。例如，如果你期望一个数组，而实际传递了一个布尔值，可能会出现问题。如果你使用`prop-types` React 验证包来验证属性值，那么你就知道传递了一些意外的内容。如果组件期望一个数组以便调用`map()`方法，如果传递了布尔值，它将失败，因为布尔值没有`map()`方法。然而，在这种失败发生之前，你会看到属性验证警告。

这并不是要通过属性验证来**快速失败**，而是为开发人员提供信息。当属性验证失败时，你知道作为组件属性提供了一些不应该有的内容。这是要找到代码中传递值的位置并修复它的问题。

快速失败是软件架构的一个特性，系统会完全崩溃，而不是继续以不一致的状态运行。

# 推广可移植组件

当您知道组件属性可以期望什么时，组件使用的上下文变得不那么重要。这意味着只要组件能够验证其属性值，组件在哪里使用实际上并不重要；它可以轻松地被任何功能使用。

如果您想要一个通用组件，可以跨应用程序功能进行移植，您可以编写组件验证代码，也可以编写在渲染时运行的**防御性代码**。编程防御性的挑战在于它削弱了声明式 React 组件的价值。使用 React 风格的属性验证，您可以避免编写防御性代码。相反，属性验证机制在某些情况下会发出警告，通知您需要修复某些问题。

防御性代码是在生产环境中需要考虑许多边缘情况的代码。在开发过程中无法检测到潜在问题时，例如 React 组件属性验证，编写防御性代码是必要的。

# 简单属性验证器

在本节中，您将学习如何使用`prop-types`包中提供的简单属性类型验证器。然后，您将学习如何接受任何属性值，以及如何将属性**必需**而不是**可选**。

# 基本类型验证

让我们来看看处理 JavaScript 值最基本类型的验证器。您将经常使用这些验证器，因为您想知道一个属性是字符串还是函数，例如。这个例子还将介绍您在组件上设置验证所涉及的机制。这是组件；它只是使用基本标记呈现一些属性：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

const MyComponent = ({
  myString,
  myNumber,
  myBool,
  myFunc,
  myArray,
  myObject
}) => (
  <section>
    {/* Strings and numbers can be rendered
         just about anywhere. */}
    <p>{myString}</p>
    <p>{myNumber}</p>

    {/* Booleans are typically used as property values. */}
    <p>
      <input type="checkbox" defaultChecked={myBool} />
    </p>

    {/* Functions can return values, or be assigned as
         event handler property values. */}
    <p>{myFunc()}</p>

    {/* Arrays are typically mapped to produce new JSX elements. */}
    <ul>{myArray.map(i => <li key={i}>{i}</li>)}</ul>

    {/* Objects typically use their properties in some way. */}
    <p>{myObject.myProp}</p>
  </section>
);

// The "propTypes" specification for this component.
MyComponent.propTypes = {
  myString: PropTypes.string,
  myNumber: PropTypes.number,
  myBool: PropTypes.bool,
  myFunc: PropTypes.func,
  myArray: PropTypes.array,
  myObject: PropTypes.object
};

export default MyComponent;

```

属性验证机制有两个关键部分。首先，您有静态的`propTypes`属性。这是一个类级别的属性，而不是实例属性。当 React 找到`propTypes`时，它将使用此对象作为组件的属性规范。其次，您有来自`prop-types`包的`PropTypes`对象，其中包含几个内置的验证器函数。

`PropTypes`对象曾经是内置在 React 中的。它从 React 核心中分离出来，并移动到`prop-types`包中，因此成为了一个可选择使用的内容 - 这是 React 开发人员的一个请求，他们不使用属性验证。

在这个例子中，`MyComponent`有六个属性，每个属性都有自己的类型。当您查看`propTypes`规范时，可以看到这个组件将接受什么类型的值。让我们使用一些属性值来渲染这个组件：

```jsx
import React from 'react';
import { render as renderJSX } from 'react-dom';

import MyComponent from './MyComponent';

// The properties that we'll pass to the component.
// Each property is a different type, and corresponds
// to the "propTypes" spec of the component.
const validProps = {
  myString: 'My String',
  myNumber: 100,
  myBool: true,
  myFunc: () => 'My Return Value',
  myArray: ['One', 'Two', 'Three'],
  myObject: { myProp: 'My Prop' }
};

// These properties don't correspond to the "<MyComponent>"
// spec, and will cause warnings to be logged.
const invalidProps = {
  myString: 100,
  myNumber: 'My String',
  myBool: () => 'My Reaturn Value',
  myFunc: true,
  myArray: { myProp: 'My Prop' },
  myObject: ['One', 'Two', 'Three']
};

// Renders "<MyComponent>" with the given "props".
function render(props) {
  renderJSX(
    <MyComponent {...props} />,
    document.getElementById('root')
  );
}

render(validProps);
render(invalidProps);

```

第一次渲染`<MyComponent>`时，它使用`validProps`属性。这些值都符合组件属性规范，因此控制台中不会记录任何警告。第二次，使用`invalidProps`属性，这将导致属性验证失败，因为每个属性中都使用了错误的类型。控制台输出应该类似于以下内容：

```jsx
Invalid prop `myString` of type `number` supplied to `MyComponent`, expected `string` 
Invalid prop `myNumber` of type `string` supplied to `MyComponent`, expected `number` 
Invalid prop `myBool` of type `function` supplied to `MyComponent`, expected `boolean` 
Invalid prop `myFunc` of type `boolean` supplied to `MyComponent`, expected `function` 
Invalid prop `myArray` of type `object` supplied to `MyComponent`, expected `array` 
Invalid prop `myObject` of type `array` supplied to `MyComponent`, expected `object` 
TypeError: myFunc is not a function 
```

最后一个错误很有趣。您可以清楚地看到属性验证正在抱怨无效的属性类型。这包括传递给`myFunc`的无效函数。因此，尽管在属性上进行了类型检查，但组件仍会尝试调用该值，就好像它是一个函数一样。

渲染输出如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/fe0fcdfb-8e2b-4b88-9860-538c1cee3c61.png)再次强调，React 组件中属性验证的目的是帮助您在开发过程中发现错误。当 React 处于生产模式时，属性验证将完全关闭。这意味着您不必担心编写昂贵的属性验证代码；它永远不会在生产中运行。但是错误仍然会发生，所以要修复它。

# 要求值

让我们对前面的示例进行一些调整。组件属性规范需要特定类型的值，但只有在将属性作为 JSX 属性传递给组件时才会进行检查。例如，您可以完全省略`myFunc`属性，它也会通过验证。幸运的是，`PropTypes`函数有一个工具，让您可以指定必须提供属性并且必须具有特定类型。以下是修改后的组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

const MyComponent = ({
  myString,
  myNumber,
  myBool,
  myFunc,
  myArray,
  myObject
}) => (
  <section>
    <p>{myString}</p>
    <p>{myNumber}</p>
    <p>
      <input type="checkbox" defaultChecked={myBool} />
    </p>
    <p>{myFunc()}</p>
    <ul>{myArray.map(i => <li key={i}>{i}</li>)}</ul>
    <p>{myObject.myProp}</p>
  </section>
);

// The "propTypes" specification for this component. Every
// property is required, because they each have the
// "isRequired" property.
MyComponent.propTypes = {
  myString: PropTypes.string.isRequired,
  myNumber: PropTypes.number.isRequired,
  myBool: PropTypes.bool.isRequired,
  myFunc: PropTypes.func.isRequired,
  myArray: PropTypes.array.isRequired,
  myObject: PropTypes.object.isRequired
};

export default MyComponent; 
```

这个组件和前面部分实现的组件之间没有太多变化。主要区别在于`propTypes`中的规格。`isRequired`值被附加到每个使用的类型验证器上。因此，例如，`string.isRequired`表示属性值必须是字符串，并且属性不能为空。现在让我们测试一下这个组件：

```jsx
import React from 'react';
import { render as renderJSX } from 'react-dom';

import MyComponent from './MyComponent';

const validProps = {
  myString: 'My String',
  myNumber: 100,
  myBool: true,
  myFunc: () => 'My Return Value',
  myArray: ['One', 'Two', 'Three'],
  myObject: { myProp: 'My Prop' }
};

// The same as "validProps", except it's missing
// the "myObject" property. This will trigger a
// warning.
const missingProp = {
  myString: 'My String',
  myNumber: 100,
  myBool: true,
  myFunc: () => 'My Return Value',
  myArray: ['One', 'Two', 'Three']
};

// Renders "<MyComponent>" with the given "props".
function render(props) {
  renderJSX(
    <MyComponent {...props} />,
    document.getElementById('root')
  );
}

render(validProps);
render(missingProp);

```

第一次渲染时，组件使用了所有正确的属性类型。第二次渲染时，组件没有使用 `myObject` 属性。控制台错误应该如下：

```jsx
Required prop `myObject` was not specified in `MyComponent`. 
Cannot read property 'myProp' of undefined 
```

由于属性规范和后续对 `myObject` 的错误消息，很明显需要为 `myObject` 属性提供一个对象值。最后一个错误是因为组件假设存在一个具有 `myProp` 作为属性的对象。

理想情况下，在这个例子中，你应该验证 `myProp` 对象属性，因为它直接用在 JSX 中。在 JSX 标记中使用的特定属性可以验证对象的形状，正如你将在本章后面看到的那样。

# 任何属性值

本节的最后一个主题是 `any` 属性验证器。也就是说，它实际上并不关心它得到什么值——任何值都是有效的，包括根本不传递值。事实上，`isRequired` 验证器可以与 `any` 验证器结合使用。例如，如果你正在开发一个组件，你只想确保传递了某些东西，但还不确定你将需要哪种类型，你可以做类似这样的事情：`myProp: PropTypes.any.isRequired`。

拥有 `any` 属性验证器的另一个原因是为了一致性。每个组件都应该有属性规范。在开始时，`any` 验证器是有用的，当你不确定属性类型时。你至少可以开始属性规范，然后随着事情的展开逐渐完善它。

现在让我们来看一些代码：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

// Renders a component with a header and a simple
// progress bar, using the provided property
// values.
const MyComponent = ({ label, value, max }) => (
  <section>
    <h5>{label}</h5>
    <progress {...{ max, value }} />
  </section>
);

// These property values can be anything, as denoted by
// the "PropTypes.any" prop type.
MyComponent.propTypes = {
  label: PropTypes.any,
  value: PropTypes.any,
  max: PropTypes.any
};

export default MyComponent;
```

这个组件实际上并不验证任何东西，因为它的属性规范中的三个属性将接受任何东西。然而，这是一个很好的起点，因为乍一看，我就可以看到这个组件使用的三个属性的名称。所以以后，当我决定这些属性应该具有哪些类型时，更改是简单的。现在让我们看看这个组件的实际效果：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyComponent from './MyComponent';

render(
  <section>
    {/* Passes a string and two numbers to
         "<MyComponent>". Everything works as
         expected. */}
    <MyComponent label="Regular Values" max={20} value={10} />

    {/* Passes strings instead of numbers to the
         progress bar, but they're correctly
         interpreted as numbers. */}
    <MyComponent label="String Values" max="20" value="10" />

    {/* The "label" has no issue displaying
         "MAX_SAFE_INTEGER", but the date that's
         passed to "max" causes the progress bar
         to break. */}
    <MyComponent
      label={Number.MAX_SAFE_INTEGER}
      max={new Date()}
      value="10"
    />
  </section>,
  document.getElementById('root')
);
```

字符串和数字在几个地方是可以互换的。只允许其中一个似乎过于限制了。正如你将在下一节中看到的，React 还有其他属性验证器，允许你进一步限制组件允许的属性值。

我们的组件在渲染时是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/070e9a68-1e63-4c79-a9d3-f31bb093adb2.png)

# 类型和值验证器

在这一部分，你将学习 React `prop-types`包中更高级的验证功能。首先，你将学习检查可以在 HTML 标记内渲染的值的元素和节点验证器。然后，你将看到如何检查特定类型，超出了你刚刚学到的原始类型检查。最后，你将实现寻找特定值的验证。

# 可以渲染的东西

有时，你只想确保属性值是可以由 JSX 标记渲染的东西。例如，如果属性值是一组普通对象，这不能通过将其放在`{}`中来渲染。你必须将数组项映射到 JSX 元素。

这种检查特别有用，如果你的组件将属性值传递给其他元素作为子元素。让我们看一个例子，看看这是什么样子的：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

const MyComponent = ({ myHeader, myContent }) => (
  <section>
    <header>{myHeader}</header>
    <main>{myContent}</main>
  </section>
);

// The "myHeader" property requires a React
// element. The "myContent" property requires
// a node that can be rendered. This includes
// React elements, but also strings.
MyComponent.propTypes = {
  myHeader: PropTypes.element.isRequired,
  myContent: PropTypes.node.isRequired
};

export default MyComponent;
```

这个组件有两个属性，需要渲染数值。`myHeader`属性需要一个`element`，可以是任何 JSX 元素。`myContent`属性需要一个`node`，可以是任何 JSX 元素或任何字符串值。让我们给这个组件传递一些值并渲染它：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyComponent from './MyComponent';

// Two React elements we'll use to pass to
// "<MyComponent>" as property values.
const myHeader = <h1>My Header</h1>;
const myContent = <p>My Content</p>;

render(
  <section>
    {/* Renders as expected, both properties are passed
         React elements as values. */}
    <MyComponent {...{ myHeader, myContent }} />

    {/* Triggers a warning because "myHeader" is expecting
         a React element instead of a string. */}
    <MyComponent myHeader="My Header" {...{ myContent }} />

    {/* Renders as expected. A string is a valid type for
         the "myContent" property. */}
    <MyComponent {...{ myHeader }} myContent="My Content" />

    {/* Renders as expected. An array of React elements
         is a valid type for the "myContent" property. */}
    <MyComponent
      {...{ myHeader }}
      myContent={[myContent, myContent, myContent]}
    />
  </section>,
  document.getElementById('root')
);
```

`myHeader`属性对其接受的值更加严格。`myContent`属性将接受一个字符串、一个元素或一个元素数组。当从属性中传递子数据时，这两个验证器非常重要，就像这个组件所做的那样。例如，尝试将一个普通对象或函数作为子元素传递将不起作用，最好使用验证器检查这种情况。

当渲染时，这个组件看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/34cff75d-ef5e-493b-bf5c-0952fff62538.png)

# 需要特定类型

有时，你需要一个属性验证器，检查你的应用程序定义的类型。例如，假设你有以下用户类：

```jsx
import cuid from 'cuid';

// Simple class the exposes an API that the
// React component expects.
export default class MyUser {
  constructor(first, last) {
    this.id = cuid();
    this.first = first;
    this.last = last;
  }

  get name() {
    return `${this.first} ${this.last}`;
  }
}
```

现在，假设你有一个组件想要使用这个类的实例作为属性值。你需要一个验证器来检查属性值是否是`MyUser`的实例。让我们实现一个做到这一点的组件：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

import MyUser from './MyUser';

const MyComponent = ({ myDate, myCount, myUsers }) => (
  <section>
    {/* Requires a specific "Date" method. */}
    <p>{myDate.toLocaleString()}</p>

    {/* Number or string works here. */}
    <p>{myCount}</p>
    <ul>
      {/* "myUsers" is expected to be an array of
           "MyUser" instances. So we know that it's
           safe to use the "id" and "name" property. */}
      {myUsers.map(i => <li key={i.id}>{i.name}</li>)}
    </ul>
  </section>
);

// The properties spec is looking for an instance of
// "Date", a choice between a string or a number, and
// an array filled with specific types.
MyComponent.propTypes = {
  myDate: PropTypes.instanceOf(Date),
  myCount: PropTypes.oneOfType([PropTypes.string, PropTypes.number]),
  myUsers: PropTypes.arrayOf(PropTypes.instanceOf(MyUser))
};

export default MyComponent; 
```

这个组件有三个需要特定类型的属性，每一个都超出了本章中到目前为止所见的基本类型验证器。让我们现在逐步了解这些：

+   `myDate`需要一个`Date`的实例。它使用`instanceOf()`函数来构建一个验证函数，确保值是`Date`的实例。

+   `myCount` 要求值要么是一个数字，要么是一个字符串。这个验证器函数是通过结合 `oneOfType`、`PropTypes.number()` 和 `PropTypes.string()` 创建的。

+   `myUsers` 需要一个 `MyUser` 实例的数组。这个验证器是通过结合 `arrayOf()` 和 `instanceOf()` 构建的。

这个例子说明了通过结合 React 提供的属性验证器可以处理的场景数量。渲染输出如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/aac1c9ee-ab58-4201-905a-e5ea0eb47ca0.png)

# 需要特定的值

到目前为止，我专注于验证属性值的类型，但这并不总是你想要检查的。有时候，特定的值很重要。让我们看看如何验证特定的属性值：

```jsx
import React from 'react';
import PropTypes from 'prop-types';

// Any one of these is a valid "level"
// property value.
const levels = new Array(10).fill(null).map((v, i) => i + 1);

// This is the "shape" of the object we expect
// to find in the "user" property value.
const userShape = {
  name: PropTypes.string,
  age: PropTypes.number
};

const MyComponent = ({ level, user }) => (
  <section>
    <p>{level}</p>
    <p>{user.name}</p>
    <p>{user.age}</p>
  </section>
);

// The property spec for this component uses
// "oneOf()" and "shape()" to define the required
// property values.
MyComponent.propTypes = {
  level: PropTypes.oneOf(levels),
  user: PropTypes.shape(userShape)
};

export default MyComponent; 
```

`level` 属性预期是来自 `levels` 数组的数字。这很容易使用 `oneOf()` 函数进行验证。`user` 属性预期一个特定的形状。形状是对象的预期属性和类型。在这个例子中定义的 `userShape` 需要一个 `name` 字符串和一个 `age` 数字。`shape()` 和 `instanceOf()` 之间的关键区别是你不一定关心类型。你可能只关心组件 JSX 中使用的值。

让我们看看这个组件是如何使用的：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyComponent from './MyComponent';

render(
  <section>
    {/* Works as expected. */}
    <MyComponent level={10} user={{ name: 'Name', age: 32 }} />

    {/* Works as expected, the "online"
         property is ignored. */}
    <MyComponent user={{ name: 'Name', age: 32, online: false }} />

    {/* Fails. The "level" value is out of range,
         and the "age" property is expecting a
         number, not a string. */}
    <MyComponent level={11} user={{ name: 'Name', age: '32' }} />
  </section>,
  document.getElementById('root')
);
```

组件渲染时的样子如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/73b1b803-db22-4c20-84ae-72d2b13e0105.png)

# 编写自定义属性验证器

在这最后一节中，你将学习如何构建自己的自定义属性验证函数，并将它们应用在属性规范中。一般来说，只有在绝对必要的情况下才应该实现自己的属性验证器。`prop-types` 中提供的默认验证器涵盖了广泛的场景。

然而，有时候，你需要确保非常特定的属性值被传递给组件。记住，这些不会在生产模式下运行，所以验证器函数迭代集合是完全可以接受的。现在让我们实现一些自定义验证器函数：

```jsx
import React from 'react';

const MyComponent = ({ myArray, myNumber }) => (
  <section>
    <ul>{myArray.map(i => <li key={i}>{i}</li>)}</ul>
    <p>{myNumber}</p>
  </section>
);

MyComponent.propTypes = {
  // Expects a property named "myArray" with a non-zero
  // length. If this passes, we return null. Otherwise,
  // we return a new error.
  myArray: (props, name, component) =>
    Array.isArray(props[name]) && props[name].length
      ? null
      : new Error(`${component}.${name}: expecting non-empty array`),

  // Expects a property named "myNumber" that's
  // greater than 0 and less than 99\. Otherwise,
  // we return a new error.
  myNumber: (props, name, component) =>
    Number.isFinite(props[name]) &&
    props[name] > 0 &&
    props[name] < 100
      ? null
      : new Error(
          `${component}.${name}: expecting number between 1 and 99`
        )
};

export default MyComponent;

```

`myArray` 属性预期一个非空数组，`myNumber` 属性预期一个大于 `0` 且小于 `100` 的数字。让我们尝试传递一些数据给这些验证器：

```jsx
import React from 'react';
import { render } from 'react-dom';

import MyComponent from './MyComponent';

render(
  <section>
    {/* Renders as expected... */}
    <MyComponent
      myArray={['first', 'second', 'third']}
      myNumber={99}
    />

    {/* Both custom validators fail... */}
    <MyComponent myArray={[]} myNumber={100} />
  </section>,
  document.getElementById('root')
);
```

第一个元素渲染得很好，因为这两个验证器都返回 null。然而，空数组和数字 `100` 导致这两个验证器都返回错误：

```jsx
MyComponent.myArray: expecting non-empty array 
MyComponent.myNumber: expecting number between 1 and 99 
```

渲染输出如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/react-rn-2e/img/cc4bf346-2ab7-4e36-a9a4-77b8e9392185.png)

# 摘要

本章的重点是 React 组件属性验证。当您实施属性验证时，您知道可以期望什么；这有助于可移植性。组件不关心属性值是如何传递给它的，只要它们是有效的即可。

然后，您将使用基本的 React 验证器来处理几个示例，这些验证器检查原始 JavaScript 类型。您还了解到，如果属性是必需的，必须明确指出。接下来，您将学习如何通过组合 React 提供的内置验证器来验证更复杂的属性值。

最后，您将实现自己的自定义验证器函数，以执行超出`prop-types`验证器可能的验证。在下一章中，您将学习如何通过新数据和行为扩展 React 组件。

# 测试您的知识

1.  以下是描述`prop-types`包的最佳描述之一？

1.  用于编译 React 组件的强类型 JavaScript 实用程序。

1.  用于在开发过程中验证传递给组件的 prop 值的工具。

1.  用于在生产环境中验证传递给组件的 prop 值的工具。

1.  如何验证属性值是否可以呈现？

1.  如果它具有`toString()`函数，则足以呈现它。

1.  使用**`PropTypes.node`**验证器。

1.  使用`PropTypes.renderable`验证器。

1.  PropTypes.shape 验证器的目的是什么？

1.  确保对象具有特定类型的特定属性，忽略任何其他属性。

1.  确保作为 prop 传递的对象是特定类的对象。

1.  确保对象具有特定的属性名称。

# 进一步阅读

+   [`reactjs.org/docs/typechecking-with-proptypes.html`](https://reactjs.org/docs/typechecking-with-proptypes.html)
