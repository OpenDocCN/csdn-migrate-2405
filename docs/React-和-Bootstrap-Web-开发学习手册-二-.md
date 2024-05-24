# React 和 Bootstrap Web 开发学习手册（二）

> 原文：[`zh.annas-archive.org/md5/59c715363f0dff298e7d1cff58a50a77`](https://zh.annas-archive.org/md5/59c715363f0dff298e7d1cff58a50a77)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章. 使用 ReactJS 与 DOM 交互

在上一章中，我们学习了什么是 JSX，以及如何在 JSX 中创建组件。与许多其他框架一样，React 还有其他原型可以帮助我们构建我们的 Web 应用程序。每个框架都有不同的方式与 DOM 元素交互。React 使用快速的内部合成 DOM 来执行差异并为您计算最有效的 DOM 突变，其中您的组件实际上存在。

React 组件类似于接受 props 和 state 的函数（这将在后面的部分中解释）。React 组件只呈现单个根节点。如果我们想呈现多个节点，那么它们必须被包装到单个根节点中。

在我们开始使用表单组件之前，我们应该先看一下 props 和 state。

# Props 和 state

React 组件将您的原始数据转换为丰富的 HTML，props 和 state 一起构建该原始数据以保持您的 UI 一致。

好的，让我们确定它到底是什么：

+   Props 和 state 都是普通的 JS 对象。

+   它们通过`render`更新触发。

+   React 通过调用`setState(data,callback)`来管理组件状态。这种方法将数据合并到此状态中，并重新呈现组件以保持我们的 UI 最新。例如，下拉菜单的状态（可见或隐藏）。

+   React 组件 props（属性）随时间不会改变。例如，下拉菜单项。有时组件只使用这种`props`方法获取一些数据并呈现它，这使得您的组件无状态。

+   同时使用`props`和`state`有助于您创建一个交互式应用程序。![Props 和 state](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_04_001.jpg)

参考第三章中的实时示例，*ReactJS-JSX*。您将更好地理解状态和属性的工作原理。

在这个例子中，我们正在管理切换的状态（显示或隐藏）和切换按钮的文本作为属性。

# 表单组件

在 React 中，表单组件与其他本机组件不同，因为它们可以通过用户交互进行修改，例如`<input>`、`<textarea>`和`<option>`。

以下是支持的事件列表：

+   `onChange`、`onInput`和`onSubmit`

+   `onClick`、`onContextMenu`、`onDoubleClick`、`onDrag`、`onDragEnd`、`onDragEnter`和`onDragExit`

+   `onDragLeave`、`onDragOver`、`onDragStart`、`onDrop`、`onMouseDown`、`onMouseEnter`和`onMouseLeave`

+   `onMouseMove`、`onMouseOut`、`onMouseOver`和`onMouseUp`

可以在官方文档中找到支持的事件的完整列表：[`facebook.github.io/react/docs/events.html#supported-events`](https://facebook.github.io/react/docs/events.html#supported-events)。

## 表单组件中的 Props

正如我们所知，ReactJS 组件有自己的 props 和类似状态的形式，支持通过用户交互受影响的一些 props：

`<input>`和`<textarea>`

| **组件** | **支持的 Props** |
| --- | --- |
| `<input>`和`<textarea>` | Value, defaultValue |
| `<input>`类型的复选框或单选按钮 | Checked, defaultChecked |
| `<select>` | Selected, defaultValue |

### 注意

在 HTML `<textarea>`组件中，值是通过子元素设置的，但在 React 中可以通过`value`设置。`onChange`属性由所有原生组件支持，例如其他 DOM 事件，并且可以监听所有冒泡变化事件。

`onChange`属性在用户交互和更改时在浏览器中起作用：

+   `<input>`和`<textarea>`的`value`

+   `<input>`类型的`radio`和`checkbox`的`checked`状态

+   `<option>`组件的`selected`状态

在本章中，我们将演示如何使用我们刚刚查看的属性（prop）和状态来控制组件。然后，我们将看看如何从组件中应用它们来控制行为。

## 受控组件

我们要看的第一个组件是控制用户输入到`textarea`中的组件，当字符达到最大长度时阻止用户输入；它还会在用户输入时更新剩余字符：

```jsx
render: function() { 
    return <textarea className="form-control" value="fdgdfgd" />; 
}
```

在上述代码中，我们声明了`textarea`的值，因此当用户输入时，它不会对`textarea`的值进行更改。要控制这一点，我们需要使用`onChange`事件：

```jsx
var style = {color: "#ffaaaa"}; 
var max_Char='140'; 
var Teaxtarea = React.createClass({ 
    getInitialState: function() { 
        return {value: 'Controlled!!!', char_Left: max_Char}; 
    }, 
    handleChange: function(event) { 
        var input = event.target.value; 
        this.setState({value: input}); 
    }, 
    render: function() { 
        return ( 
            <form> 
                <div className="form-group"> 
                    <label htmlFor="comments">Comments <span style=
                    {style}>*</span></label>(<span>
                    {this.state.char_Left}</span> characters left) 
                    <textarea className="form-control" value=
                    {this.state.value} maxLength={max_Char} onChange=
                    {this.handleChange} /> 
                </div> 
            </form> 
        ); 
    } 
}) 

```

观察以下截图：

![受控组件](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_04_002.jpg)

在上述截图中，我们接受并控制用户提供的值，并更新`<textarea>`组件的`prop`值。

### 注意

`this.state()`应该只包含表示 UI 状态所需的最小数据量。

但现在我们还想在`<span>`中更新`textarea`的剩余字符：

```jsx
this.setState({ 
    value: input.substr(0, max_Char),char_Left: max_Char - 
    input.length 
});
```

在上述代码中，`this`将控制`textarea`的剩余值，并在用户输入时更新剩余字符。

## 不受控组件

正如我们在 ReactJS 中所见，使用`value`属性时，我们可以控制用户输入，所以没有`value`属性的`<textarea>`是一个非受控组件：

```jsx
render: function() { 
    return <textarea className="form-control"/> 
}
```

这将渲染一个带有空值的`textarea`，用户可以输入值，这些值会立即反映在渲染的元素上，因为非受控组件有自己的内部状态。如果要初始化默认值，我们需要使用`defaultValue`属性：

```jsx
render:function() { 
    return <textarea className="form-control" defaultValue="Lorem 
    lipsum"/> 
} 

```

看起来像是受控组件，我们之前见过的。

# 在提交时获取表单值

正如我们所见，`state`和`prop`将让您控制组件的值并处理该组件的状态。

好的，现在让我们在我们的添加票务表单中添加一些高级功能，它可以验证用户输入并在 UI 上显示票务。

## Ref 属性

React 提供了`ref`非 DOM 属性来访问组件。`ref`属性可以是一个回调函数，在组件挂载后立即执行。

所以我们将在我们的表单元素中附加`ref`属性来获取值：

```jsx
var AddTicket = React.createClass({ 
    handleSubmitEvent: function (event) { 
        event.preventDefault(); 
        console.log("Email--"+this.refs.email.value.trim()); 
        console.log("Issue Type--"+this.refs.issueType.value.trim()); 
        console.log("Department--"+this.refs.department.value.trim()); 
        console.log("Comments--"+this.refs.comment.value.trim()); 
    }, 
    render: function() { 
        return ( 
        ); 
    } 
});
```

现在，我们将在`return`方法中添加表单元素的 JSX：

```jsx
<form onSubmit={this.handleSubmitEvent}>
    <div className="form-group">
        <label htmlFor="email">Email <span style={style}>*</span>
        </label>
        <input type="text" id="email" className="form-control" 
        placeholder="Enter email" required ref="email"/>
    </div>
    <div className="form-group">
        <label htmlFor="issueType">Issue Type <span style={style}>*
        </span></label>
        <select className="form-control" id="issueType" required
        ref="issueType">
            <option value="">-----Select----</option>
            <option value="Access Related Issue">Access Related 
            Issue</option>
            <option value="Email Related Issues">Email Related
            Issues</option>
            <option value="Hardware Request">Hardware Request</option>
            <option value="Health & Safety">Health & Safety</option>
            <option value="Network">Network</option>
            <option value="Intranet">Intranet</option>
            <option value="Other">Other</option>
        </select>
    </div>
    <div className="form-group">
        <label htmlFor="department">Assign Department <span style=
        {style}>*</span></label>
        <select className="form-control" id="department" required
        ref="department">
            <option value="">-----Select----</option>
            <option value="Admin">Admin</option>
            <option value="HR">HR</option>
            <option value="IT">IT</option>
            <option value="Development">Development</option>
        </select>
    </div>
    <div className="form-group">
        <label htmlFor="comments">Comments <span style={style}>*</span>
        </label>(<span id="maxlength">200</span> characters left)
        <textarea className="form-control" rows="3" id="comments" 
        required ref="comment"></textarea>
    </div>
    <div className="btn-group">
        <button type="submit" className="btn 
        btn-primary">Submit</button>
        <button type="reset" className="btn btn-link">cancel</button>
    </div>
</form>

```

在前面的代码中，我在我们的表单元素上添加了`ref`属性和`onSubmit`，调用了函数名`handleSubmitEvent`。在这个函数内部，我们使用`this.refs`来获取值。

现在，打开你的浏览器，让我们看看我们代码的输出：

![Ref 属性](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_04_003.jpg)

我们成功地获取了组件的值。很清楚数据是如何在我们的组件中流动的。在控制台中，我们可以看到用户单击**提交**按钮时表单的值。

现在，让我们在 UI 中显示这张票的信息。

首先，我们需要获取表单的值并管理表单的状态：

```jsx
var AddTicket = React.createClass({ 
    handleSubmitEvent: function (event) { 
        event.preventDefault(); 

        var values  = { 
            date: new Date(), 
            email: this.refs.email.value.trim(), 
            issueType: this.refs.issueType.value.trim(), 
            department: this.refs.department.value.trim(), 
            comment: this.refs.comment.value.trim() 
        }; 
        this.props.addTicketList(values); 
    }, 
)};
```

现在我们将创建 AddTicketsForm 组件，它将负责管理和保存 addTicketList（值）的状态：

```jsx
var AddTicketsForm = React.createClass({  
    getInitialState: function () { 
        return { 
            list: {} 
        }; 
    }, 
    updateList: function (newList) { 
        this.setState({ 
            list: newList 
        }); 
    }, 

    addTicketList: function (item) { 
        var list = this.state.list; 

        list[item] = item; 
        //pass the item.id in array if we are using key attribute. 
        this.updateList(list); 
    }, 
    render: function () { 
        var items = this.state.list; 
        return ( 
            <div className="container"> 
            <div className="row"> 
            <div className="col-sm-6"> 
            <List items={items} /> 
            <AddTicket addTicketList={this.addTicketList} /> 
        </div> 
        </div> 
        </div> 
        ); 
    } 
});
```

让我们看一下前面的代码：

+   `getInitialState`：这个属性初始化了`<List />`组件的默认状态

+   `addTicketList`：这个属性保存数值并传递到`updateList`中的状态

+   `updateList`：这是用于更新票务列表以使我们的 UI 同步

现在我们需要创建`<List items={items} />`组件，当我们提交表单时，它会迭代列表：

```jsx
var List = React.createClass({  
    getListOfIds: function (items) { 
        return Object.keys(items); 
    }, 
    createListElements: function (items) { 
        var item; 
        return ( 
            this 
            .getListOfIds(items) 
            .map(function createListItemElement(itemId) { 
                item = items[itemId]; 
                return (<ListPanel item={item} />);//key={item.id} 
            }.bind(this)) 
            .reverse() 
        ); 
    }, 
    render: function () { 
        var items = this.props.items; 
        var listItemElements = this.createListElements(items); 

        return ( 
            <div className="bg-info"> 
                {listItemElements} 
            </div> 
        ); 
    } 
});
```

让我们了解一下前面的代码：

+   `getListOfIds`：这将遍历项目中的所有键，并返回我们与`<ListPanel item={item}/>`组件映射的列表

+   `.bind(this)`：`this`关键字将作为第二个参数传递，当调用函数时会给出适当的值

在`render`方法中，我们只是渲染元素的列表。此外，我们还可以根据`render`方法内部的长度添加条件：

```jsx
<p className={listItemElements.length > 0 ? "":"bg-info"}> 
    {listItemElements.length > 0 ? listItemElements : "You have not
    raised any ticket yet. Fill this form to submit the ticket"} 
</p> 

```

它将验证长度，并根据返回值 TRUE 或 FALSE 显示消息或应用 Bootstrap 类`.bg-info`。

现在我们需要创建一个`<ListPanel />`组件，以在 UI 中显示票务列表：

```jsx
var ListPanel = React.createClass({ 
    render: function () { 
        var item = this.props.item; 
        return ( 
            <div className="panel panel-default"> 
            <div className="panel-body"> 
            {item.issueType}<br/> 
            {item.email}<br/> 
            {item.comment} 
            </div> 
            <div className="panel-footer"> 
            {item.date.toString()} 
            </div> 
            </div> 
        ); 
    } 
}); 

```

现在，让我们结合我们的代码，看看在浏览器中的结果：

```jsx
var style = {color: "#ffaaaa"}; 
var AddTicketsForm = React.createClass({  
    getInitialState: function () { 
        return { 
            list: {} 
        }; 
    }, 
    updateList: function (newList) { 
        this.setState({ 
            list: newList 
        }); 
    }, 

    addTicketList: function (item) { 
        var list = this.state.list; 
        list[item] = item; 
        this.updateList(list); 
    }, 
    render: function () { 
        var items = this.state.list; 
        return ( 
            <div className="container"> 
            <div className="row"> 
            <div className="col-sm-12"> 
            <List items={items} /> 
            <AddTicket addTicketList={this.addTicketList} /> 
            </div> 
            </div> 
            </div> 
        ); 
    }  
}); 

//AddTicketsForm components code ends here

var ListPanel = React.createClass({
    render: function () {
        var item = this.props.item;
        return (
        <div className="panel panel-default">
            <div className="panel-body">
                {item.issueType}<br/>
                {item.email}<br/>
                {item.comment}
            </div>
        <div className="panel-footer">
            {item.date.toString()}
        </div>
        </div>
        );
    }
});

// We'll wrap ListPanel component in List

var List = React.createClass({
    getListOfIds: function (items) {
        return Object.keys(items);
    },
    createListElements: function (items) {
        var item;
        return (
            this
            .getListOfIds(items)
            .map(function createListItemElement(itemId) {
                item = items[itemId];
                return (
                    <ListPanel item={item} />
                );//key={item.id}
            }.bind(this))
            .reverse()
        );
    },
    render: function () {
        var items = this.props.items;
        var listItemElements = this.createListElements(items);
        return (
            <p className={listItemElements.length > 0 ? "":"bg-info"}>
            {listItemElements.length > 0 ? listItemElements : "You
            have not raised any ticket yet. Fill this form to submit
            the ticket"}
            </p>
        );
    }
});
```

在上述代码中，我们正在迭代项目并将其作为 props 传递给`<Listpanel/>`组件：

```jsx
var AddTicket = React.createClass({
    handleSubmitEvent: function (event) {
        event.preventDefault();
        var values  = {
            date: new Date(),
            email: this.refs.email.value.trim(),
            issueType: this.refs.issueType.value.trim(),
            department: this.refs.department.value.trim(),
            comment: this.refs.comment.value.trim()
        };
        this.props.addTicketList(values);
    },
    render: function() {
    return (

// Form template

ReactDOM.render( 
    <AddTicketsForm />, 
    document.getElementById('form') 
);
```

以下是我们 HTML 页面的标记。

```jsx
<link rel="stylesheet" href="css/bootstrap.min.css">
<style type="text/css">
    div.bg-info {
        padding: 15px;
    }
</style>
</head>
<body>
    <div class="container">
        <div class="row">
            <div class="col-sm-6">
                <h2>Add Ticket</h2>
                <hr/>
            </div>
        </div>
    </div>
    <div id="form">
    </div>
    <script type="text/javascript" src="js/react.js"></script>
    <script type="text/javascript" src="js/react-dom.js"></script>
    <script src="js/browser.min.js"></script>
    <script src="component/advance-form.js" type="text/babel"></script>
</body>

```

打开您的浏览器，让我们在提交之前看看我们表单的输出：

![Ref 属性](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_04_004.jpg)

以下截图显示了提交表单后的外观：

![Ref 属性](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_04_005.jpg)

看起来不错。我们的第一个完全功能的 React 组件已经准备好了。

### 注意

永远不要在任何组件内部访问`refs`，也不要将它们附加到无状态函数。

观察以下截图：

![Ref 属性](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_04_006.jpg)

我们收到此警告消息是因为 React 的`key`（可选）属性，它接受一个唯一的 ID。每当我们提交表单时，它将迭代`List`组件以更新 UI。例如：

```jsx
createListElements: function (items) { 
    var item; 

    return ( 
        this 
        .getListOfIds(items) 
        .map(function createListItemElement(itemId,id) { 
        item = items[itemId]; 
            return (<ListPanel key={id} item={item} />); 
        }.bind(this)) 
        .reverse() 
    ); 
},
```

React 提供了 add-ons 模块来解决这种类型的警告并生成唯一的 ID，但它只在 npm 中可用。在后续章节中，我们将展示如何使用 React npm 模块。以下是一些流行的 add-ons 列表：

+   `TransitionGroup`和`CSSTransitionGroup`：用于处理动画和过渡

+   `LinkedStateMixin`：使用户的表单输入数据和组件状态之间的交互变得容易

+   `cloneWithProps`：更改组件的 props 并进行浅拷贝

+   `createFragment`：用于创建一组外部键控的子元素

+   `Update`：一个帮助函数，使在 JavaScript 中处理数据变得容易

+   `PureRenderMixin:`性能增强器

+   `shallowCompare:` 一个帮助函数，用于对 props 和 state 进行浅比较

## Bootstrap 辅助类

Bootstrap 提供了一些辅助类，以提供更好的用户体验。在`AddTicketsForm`表单组件中，我们使用了 Bootstrap 辅助类`*-info`，它可以帮助屏幕阅读器以颜色传达消息的含义。其中一些是`*-muted`，`*-primary`，`*-success`，`*-info`，`*-warning`和`*-danger`。

要更改文本的颜色，我们可以使用`.text*`：

```jsx
<p class="text-info">...</p>
```

要更改背景颜色，我们可以使用`.bg*`：

```jsx
<p class="bg-info">...</p>
```

### 插入符

要显示指示下拉方向的插入符，我们可以使用：

```jsx
<span class="caret"></span>
```

### 清除浮动

通过在父元素上使用`clearfix`，我们可以清除子元素的浮动：

```jsx
<div class="clearfix">... 
    <div class="pull-left"></div> 
    <div class="pull-right"></div> 
</div> 

```

# 总结

在本章中，我们已经看到 props 和 state 在使组件交互以及在 DOM 交互中发挥重要作用。Refs 是与 DOM 元素交互的好方法。通过流式响应 props 和 state 来做这件事将会很不方便。借助 refs，我们可以调用任何公共方法并向特定的子实例发送消息。

本章中展示的关键示例将帮助您理解和澄清有关 props、state 和 DOM 交互的概念。

最后一个示例涵盖了使用多个 JSX 组件和 Bootstrap 创建高级添加票据表单，这将为您提供更多关于创建 React 组件以及如何使用 refs 与它们交互的想法。您可以像操作 HTML 一样轻松地使用它和调整它。

如果您仍然不确定 state 和 props 的工作原理以及 React 如何与 DOM 交互，我建议您再次阅读本章，这也将在您查看未来章节时帮助您。

如果您已经完成了，那么让我们继续阅读第五章，“React 中的 jQuery Bootstrap 组件”，这一章主要讲述了 React 中的 Redux 架构。


# 第五章：React 中的 jQuery Bootstrap 组件

到目前为止，我们已经介绍了如何创建 DOM 元素以及 DOM 如何与 React 组件交互。正如我们所见，每个框架都有不同的方式与 DOM 元素交互，而 React 使用快速的内部合成 DOM 来执行差异并为您计算最有效的 DOM 变化，这是您的组件实际存在的地方。

在本章中，我们将看看 jQuery Bootstrap 组件在 React 虚拟 DOM 中是如何工作的。我们还将涵盖以下主题：

+   组件生命周期方法

+   组件集成

+   Bootstrap 模态框

+   具体示例

这将让您更好地理解如何处理 React 中的 jQuery Bootstrap 组件。

在 Bootstrap 中，我们有很多可重用的组件，使开发人员的生活更轻松。在第一章和第二章中，我们解释了 Bootstrap 的集成。所以让我们从一个小组件开始，将其集成到 React 中。

# 警报

在 Bootstrap 中，我们有`alert`组件来根据用户操作在 UI 中显示消息，使您的组件更具交互性。

首先，我们需要将文本包裹在包含`close`按钮的`.alert`类中。

Bootstrap 还提供了表示不同颜色的上下文类，根据消息的不同而不同：

+   `.alert-success`

+   `.alert-info`

+   `.alert-warning`

+   `.alert-error`

## 用法

Bootstrap 为我们提供了`alert`组件的预定义结构，这使得将其包含在我们的项目中变得容易：

```jsx
<div class="alert alert-info alert-dismissible fade in" role="alert">
    <button type="button" class="close" data-dismiss="alert"
    aria-label="Close">
    <span aria-hidden="true">&times;</span>
    </button>
</div>

```

当我们将`close`按钮用作我们声明了`alert`类的包装标记的子元素时，我们需要向该元素添加`.alert-dismissible`类，就像前面的示例代码中所示的那样。

添加自定义属性`data-dismiss="alert"`将为我们在`alert`中提供`close`功能。

# 在 React 中的 Bootstrap 警报组件

现在我们将把 Bootstrap `alert`组件与我们在第四章中开发的 React 受控组件（`textarea`）集成起来，*ReactJS 中的 DOM 交互*，在那里我们开发了一个带有受控组件的表单。我们通过一个示例防止用户在`textarea`中写入超过`140`个字符的文本。

在以下示例中，我们将看到如何将警报/警告消息与相同的组件绑定。在这里，我们只是扩展了开发的受控组件。

您可能还在第四章中看到了以下截图，显示了带有`textarea`中注释的受控组件。在括号中，您可以看到定义的字符限制：

![React 中的 Bootstrap 警报组件](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_001.jpg)

添加`alert`组件后，当用户达到最大字符限制时，它将显示在 UI 中。

为此，首先，我们需要将 Bootstrap 组件包装到 React 结构中。让我们通过实际示例来了解一下：

```jsx
var BootstrapAlert = React.createClass({  
    render: function() { 
        return ( 
            <div className={(this.props.className) + ' alert'}
            role="alert" ref="alertMsg"> 
                <button type="button" className="close"
                data-dismiss="alert" aria-label="Close" onClick=
                {this.handleClose}> 
                <span aria-hidden="true">×</span></button> 
                <strong>Ooops!</strong> You reached the max limit  
            </div>     
        ); 
    } 
}); 

```

我们创建了一个名为`BootstrapAlert`的组件，并将 HTML 包装在`render`方法中。

`onClick`调用`handleClose`函数，该函数将处理`close`事件。这是 React 的默认函数，因为我们在 JavaScript 中有`.show()`和`.hide()`默认函数。

在我们集成 jQuery Bootstrap 组件之前，我们必须了解组件中的 React 生命周期方法。

# 组件生命周期方法

在 React 中，每个组件都有自己特定的回调函数。当我们考虑 DOM 操作或在 React（jQuery）中集成其他插件时，这些回调函数起着重要作用。让我们看一些组件生命周期中常用的方法：

+   `getInitialState()`: 此方法将帮助您获取组件的初始状态。

+   `componentDidMount`：此方法在组件在 DOM 中首次渲染或挂载时自动调用。在集成 JavaScript 框架时，我们将使用此方法执行操作，例如`setTimeout`或`setInterval`，或发送 AJAX 请求。

+   `componentWillReceiveProps`：此方法将用于接收新的`props`。

### 注意

没有替代方法，如`componentWillReceiveState`。如果我们需要在`state`更改时执行操作，那么我们使用`componentWillUpdate`。

+   `componentWillUnmount`：此方法在组件从 DOM 中卸载之前调用。清理在`componentDidMount`方法中挂载的 DOM 内存元素。

+   `componentWillUpdate`：此方法在更新新的`props`和`state`之前调用。

+   `componentDidUpdate`：在组件在 DOM 中更新后立即调用此方法。

# 组件集成

我们现在了解了组件的生命周期方法。现在让我们使用这些方法在 React 中集成我们的组件。请观察以下代码：

```jsx
componentDidMount: function() { 
    // When the component is mount into the DOM 
    $(this.refs.alertMsg).hide(); 
          // Bootstrap's alert events 
// functionality. Lets hook into one of them: 
    $(this.refs.alertMsg).on('closed.bs.alert', this.handleClose); 
  }, 
  componentWillUnmount: function() {  
      $(this.refs.alertMsg).off('closed.bs.alert', this.handleClose); 
  }, 
  show: function() { 
      $(this.refs.alertMsg).show(); 
  }, 
  close: function() { 
      $(this.refs.alertMsg).alert('close'); 
  }, 
  hide: function() { 
      $(this.refs.alertMsg).hide(); 
  }, 
  render: function() { 
      return ( 
      <div className={(this.props.className) + ' alert'} role="alert"
      ref="alertMsg"> 
          <button type="button" className="close" data-dismiss="alert"
          aria-label="Close" onClick={this.handleClose}> 
          <span aria-hidden="true">x</span></button> 
          <strong>Oh snap!</strong> You reached the max limit  
      </div>      
    ); 
  }, 
}); 

```

让我们看一下上述代码的解释：

+   `componentDidMount()`默认情况下使用`refs`关键字在组件挂载到 DOM 时隐藏`alert`组件

+   `alert`组件为我们提供了一些在调用`close`方法时被调用的事件

+   当调用`close`方法时，将调用`close.bs.alert`

当我们使用`componentWillUnmount`组件时，也使用 jQuery 的`.off`来移除事件处理程序。当我们点击关闭（x）按钮时，它会调用 Closehandler 并调用 close

我们还创建了一些控制我们组件的自定义事件：

+   `.hide()`: 用于隐藏组件

+   `.show()`: 用于显示组件

+   `.close()`: 用于关闭警报

请观察以下代码：

```jsx
var Teaxtarea = React.createClass({ 
    getInitialState: function() { 
        return {value: 'Controlled!!!', char_Left: max_Char}; 
    }, 
    handleChange: function(event) { 
        var input = event.target.value; 
        this.setState({value: input.substr(0, max_Char),char_Left:   
        max_Char - input.length}); 
        if (input.length == max_Char){ 
            this.refs.alertBox.show(); 
        } 
        else{ 
        this.refs.alertBox.hide(); 
        } 
    }, 
    handleClose: function() { 
        this.refs.alertBox.close(); 
    }, 

    render: function() { 
        var alertBox = null; 
        alertBox = ( 
            <BootstrapAlert className="alert-warning fade in" 
            ref="alertBox" onClose={this.handleClose}/> 
        ); 
        return ( 
            <div className="example"> 
            {alertBox} 
                <div className="form-group"> 
                    <label htmlFor="comments">Comments <span style=
                    {style}>*</span></label(<span{this.state.char_Left}
                    </span> characters left) 
                    <textarea className="form-control" value=
                    {this.state.value} maxLength={max_Char} onChange=
                    {this.handleChange} /> 
                </div> 
            </div> 
        ); 
    } 
}); 
ReactDOM.render( 
    <Teaxtarea />, 
    document.getElementById('alert') 
); 

```

使用`if`条件，根据字符长度隐藏和显示警报。`handleClose()`方法将调用我们之前创建的`close`方法来关闭警报。

在`render`方法中，我们使用`className`属性、`ref`键和`onClose`属性来渲染我们的组件以处理`close`方法。

类中的`.fade`给我们在关闭警报时提供了淡出效果。

现在让我们结合我们的代码，快速在浏览器中查看一下：

```jsx
'use strict'; 
var max_Char='140'; 
var style = {color: "#ffaaaa"}; 

var BootstrapAlert = React.createClass({  
    componentDidMount: function() { 
        // When the component is added 
        $(this.refs.alertMsg).hide();  
        // Bootstrap's alert class exposes a few events for hooking 
        into modal 
        // functionality. Lets hook into one of them: 
        $(this.refs.alertMsg).on('closed.bs.alert', this.handleClose); 
    }, 
    componentWillUnmount: function() { 
        $(this.refs.alertMsg).off('closed.bs.alert', this.
        handleClose); 
    }, 
    show: function() { 
        $(this.refs.alertMsg).show(); 
    }, 
    close: function() { 
        $(this.refs.alertMsg).alert('close'); 
    }, 
    hide: function() { 
        $(this.refs.alertMsg).hide(); 
    },  
    render: function() { 
        return ( 
            <div className={(this.props.className) + ' alert'}
            role="alert" ref="alertMsg"> 
                <button type="button" className="close" 
                data-dismiss="alert" aria-label="Close" onClick=
                {this.handleClose}> 
                <span aria-hidden="true">×</span></button> 
                <strong>oops!</strong> You reached the max limit  
            </div> 

        ); 
    } 
}); 

var Teaxtarea = React.createClass({ 
    getInitialState: function() { 
        return {value: '', char_Left: max_Char}; 
    }, 
    handleChange: function(event) { 
        var input = event.target.value; 
        this.setState({value: input.substr(0, max_Char),char_Left: 
        max_Char - input.length}); 
        if (input.length == max_Char){ 
            this.refs.alertBox.show(); 
        } 
        else{ 
            this.refs.alertBox.hide(); 
        } 
    }, 
    handleClose: function() { 
        this.refs.alertBox.close(); 
    }, 

    render: function() { 
        var alertBox = null; 
        alertBox = ( 
            <BootstrapAlert className="alert-warning fade in"
            ref="alertBox"/> 
        ); 
        return ( 
            <div className="example"> 
            {alertBox} 
                <div className="form-group"> 
                    <label htmlFor="comments">Comments <span style=
                    {style}>*</span></label>(<span
                    {this.state.char_Left}</span> characters left) 
                    <textarea className="form-control" value=
                    {this.state.value} maxLength={max_Char} onChange=
                    {this.handleChange} /> 
                </div> 
            </div> 
        ); 
    } 
}); 
ReactDOM.render( 
    <Teaxtarea />, 
    document.getElementById('alert') 
);
```

请观察以下截图：

![组件集成](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_002.jpg)

当我们点击关闭（**x**）按钮时，它会调用`Closehandler`并调用`close`事件来关闭警报消息。一旦关闭，您将需要刷新页面才能重新打开它。请观察以下截图：

![组件集成](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_003.jpg)

### 注意

使用`console.log()`，我们可以验证我们的组件是否已挂载或卸载。

现在让我们看一下 Bootstrap 组件的另一个示例。

## Bootstrap 模态框

Bootstrap 模态组件向用户显示少量信息，而不会将您带到新页面。

来自 Bootstrap 网站（[`getbootstrap.com/javascript`](http://getbootstrap.com/javascript)）的下表显示了模态框可用的全部选项：

| **名称** | **类型** | **默认** | **描述** |
| --- | --- | --- | --- |
| `backdrop` | 布尔值 | `true` | `backdrop`允许我们在用户点击外部时关闭模态框。它为`backdrop`提供了一个静态值，不会在点击时关闭模态框。 |
| `keyboard` | 布尔值 | `true` | 按下*Esc*键关闭模态框。 |
| `show` | 布尔值 | `true` | 初始化模态框。 |
| `remote` | 路径 | `false` | 自 3.3.0 版本起，此选项已被弃用，并在 4 版本中已删除。建议使用数据绑定框架进行客户端模板化，或者自己调用`jQuery.load`。 |

Bootstrap 网站（[`getbootstrap.com/javascript`](http://getbootstrap.com/javascript)）的以下表格显示了 Bootstrap 模态组件可用的完整事件列表：

| **事件类型** | **描述** |
| --- | --- |
| `show.bs.modal` | 当调用`show`（`$('.modal').show();`）实例方法时，立即触发此事件。 |
| `shown.bs.modal` | 当模态框对用户可见时触发此事件（我们需要等待 CSS 过渡完成）。 |
| `hide.bs.modal` | 当调用`hide`（`$('.modal').hide();`）实例方法时，立即触发此事件。 |
| `hidden.bs.modal` | 当模态框从用户那里隐藏完成时触发此事件（我们需要等待 CSS 过渡完成）。 |
| `loaded.bs.modal` | 当模态框使用`remote`选项加载内容时触发此事件。 |

每当我们集成任何其他组件时，我们必须了解库或插件提供的组件选项和事件。

首先，我们需要创建一个`button`组件来打开一个`modal`弹出窗口：

```jsx
// Bootstrap's button to open the modal 
var BootstrapButton = React.createClass({ 
    render: function() { 
        return ( 
            <button {...this.props} 
            role="button" 
            type="button" 
            className={(this.props.className || '') + ' btn'} /> 
        ); 
    } 
}); 

```

现在，我们需要创建一个`modal-dialog`组件，并将`button`和`dialog`组件挂载到 DOM 中。

我们还将创建一些处理`show`和`hide`模态框事件的事件：

```jsx
var BootstrapModal = React.createClass({ 
    componentDidMount: function() { 
        // When the component is mount into the DOM 
        $(this.refs.root).modal({keyboard: true, show: false}); 

        // capture the Bootstrap's modal events 
        $(this.refs.root).on('hidden.bs.modal', this.handleHidden); 
    }, 
    componentWillUnmount: function() { 
        $(this.refs.root).off('hidden.bs.modal', this.handleHidden); 
    }, 
    close: function() { 
        $(this.refs.root).modal('hide'); 
    }, 
    open: function() { 
        $(this.refs.root).modal('show'); 
    }, 
    render: function() { 
        var confirmButton = null; 
        var cancelButton = null; 

    if (this.props.confirm) { 
        confirmButton = ( 
            <BootstrapButton 
                onClick={this.handleConfirm} 
                className="btn-primary"> 
                {this.props.confirm} 
            </BootstrapButton> 
        ); 
    } 
    if (this.props.cancel) { 
        cancelButton = ( 
            <BootstrapButton onClick={this.handleCancel} className=
            "btn-default"> 
            {this.props.cancel} 
            </BootstrapButton> 
        ); 
    } 

    return ( 
        <div className="modal fade" ref="root"> 
        <div className="modal-dialog"> 
        <div className="modal-content"> 
        <div className="modal-header"> 
        <button 
            type="button" 
            className="close" 
            onClick={this.handleCancel}> 
            &times; 
        </button> 
        <h3>{this.props.title}</h3> 
        </div> 
        <div className="modal-body"> 
            {this.props.children} 
        </div> 
        <div className="modal-footer"> 
            {cancelButton} 
            {confirmButton} 
</div> 
</div> 
</div> 
</div> 
    ); 
  }, 
  handleCancel: function() { 
      if (this.props.onCancel) { 
          this.props.onCancel(); 
      } 
  }, 
  handleConfirm: function() { 
      if (this.props.onConfirm) { 
          this.props.onConfirm(); 
      } 
  }, 
  handleHidden: function() { 
      if (this.props.onHidden) { 
          this.props.onHidden(); 
      } 
  } 
}); 

```

在`componentDidMount()`中，我们正在使用一些选项初始化`modal`组件，并将`hidden.bs.modal`事件注入`modal`中。

`close()`和`show()`函数触发模态框的`hide`/`show`事件。

在`render()`方法中，我们包含了带有`props`和`ref`键的模态框 HTML 模板来操作模板。

`handleCancel()`，`handleConfirm()`和`handleHidden()`处理我们组件的每个状态。

`.modal-*`类为我们提供了 Bootstrap 的样式，使我们的应用更加用户友好。

现在我们需要使用`render`函数来渲染我们的组件：

```jsx
var ReactBootstrapModalDialog = React.createClass({ 
    handleCancel: function() { 
        if (confirm('Are you sure you want to cancel the dialog 
        info?')) { 
            this.refs.modal.close(); 
        } 
    }, 
    render: function() { 
        var modal = null; 
        modal = ( 
            <BootstrapModal 
                ref="modal" 
                confirm="OK" 
                cancel="Cancel" 
                onCancel={this.handleCancel} 
                onConfirm={this.closeModal} 
                onHidden={this.handleModalDidClose} 
                > 
                This is a React component powered by jQuery and                      Bootstrap! 
            </BootstrapModal> 
        ); 
        return ( 
            {modal} 
            <BootstrapButton onClick={this.openModal} className="btn-
            default"> 
            Open modal 
            </BootstrapButton> 
        ); 
    }, 
    openModal: function() { 
        this.refs.modal.open(); 
    }, 
    closeModal: function() { 
        this.refs.modal.close(); 
    }, 
    handleModalDidClose: function() { 
        alert("The modal has been dismissed!"); 
    } 
}); 

```

我们在`<BootstrapModal>`中传递`props`并渲染`<BootstrapButton>`。

使用`this`关键字，我们调用一个函数来调用`modal`事件并在每次事件触发时显示警报：

```jsx
ReactDOM.render(<ReactBootstrapModalDialog />, 
document.getElementById('modal')); 

```

让我们快速在浏览器中查看一下我们的组件：

![Bootstrap 模态](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_004.jpg)

哎呀！我们出现了一个错误。我认为这可能是因为我们没有将组件包裹在`render`方法内。它应该始终与一个父元素一起包装：

```jsx
return ( 
    <div className="modalbtn"> 
        {modal} 
    <BootstrapButton onClick={this.openModal} className="btn-default"> 
        Open modal 
    </BootstrapButton> 
    </div> 
); 

```

这是我们在做了一些小改动后`ReactBootstrapModalDialog`组件的样子：

```jsx
var ReactBootstrapModalDialog = React.createClass({ 
    handleCancel: function() { 
        if (confirm('Are you sure you want to cancel?')) { 
            this.refs.modal.close(); 
        } 
    }, 
    render: function() { 
        var modal = null; 
        modal = ( 
            <BootstrapModal 
                ref="modal" 
                confirm="OK" 
                cancel="Cancel" 
                onCancel={this.handleCancel} 
                onConfirm={this.closeModal} 
                onHidden={this.handleModalDidClose} 
                > 
                This is a React component powered by jQuery and
                Bootstrap! 
            </BootstrapModal> 
        ); 
        return ( 
            <div className="modalbtn"> 
                {modal} 
                <BootstrapButton onClick={this.openModal} 
                className="btn-default"> 
                    Open modal 
                </BootstrapButton> 
            </div> 
        ); 
    }, 
    openModal: function() { 
        this.refs.modal.open(); 
    }, 
    closeModal: function() { 
        this.refs.modal.close(); 
    }, 
    handleModalDidClose: function() { 
        alert("The modal has been dismissed!"); 
    } 
}); 

ReactDOM.render(<ReactBootstrapModalDialog />, document.getElementById('modal')); 

```

让我们再次在浏览器中快速查看我们的组件：

![Bootstrap 模态](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_005.jpg)

现在点击**打开模态**按钮查看模态对话框：

![Bootstrap 模态](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_006.jpg)

如果我们点击**取消**或**确定**按钮，它将显示警报框，如下截图所示：

![Bootstrap 模态](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_007.jpg)

如果我们点击**X**图标，它将显示警报框，如下截图所示：

![Bootstrap 模态](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_008.jpg)

所以，现在我们知道我们可以通过点击(**X**)图标来关闭模态对话框。

当模态对话框关闭时，它会显示警报，**模态已被解除！** 请参见下面的截图：

![Bootstrap 模态](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_05_009.jpg)

这是我们的 HTML 文件的样子：

```jsx
<!DOCTYPE html>
<html>
    <head>
        <meta charset="UTF-8" />
        <title>J-Query Bootstrap Component with React</title>
        <link rel="stylesheet" href="css/bootstrap.min.css">
    </head>
    <body>
        <div class="container">
            <div class="row">
                <div class="col-sm-6">
                    <h2>jQuery Bootstrap Modal with React</h2>
                    <hr/>
                    <div id="modal">
                    </div>
                </div>
            </div>
        </div>
        <script type="text/javascript" src="js/jquery-1.10.2.min.js">
        </script>
        <script type="text/javascript" src="js/bootstrap.min.js">
        </script>
        <script type="text/javascript" src="js/react.min.js"></script>
        <script type="text/javascript" src="js/react-dom.min.js">
        </script>
        <script src="js/browser.min.js"></script>
        <script src="component/modal.js" type="text/babel"></script>
    </body>
</html>

```

# 摘要

我们已经看到了如何在 React 中集成 jQuery Bootstrap 组件以及在集成任何第三方插件（如 jQuery）时生命周期方法的工作方式。

我们能够通过处理事件的 props 来检查组件状态，并显示具有适当内容的对话框。我们还看了生命周期方法如何帮助我们集成其他第三方插件。

我们现在了解了组件的生命周期方法以及它们在 React 中的工作方式。我们已经学会了如何在 React 中集成 jQuery 组件。我们已经看到了事件处理机制以及警报和模态组件的示例。

本章中展示的关键示例将帮助您了解或澄清在 React 中集成 jQuery Bootstrap 组件的概念。

让我们继续阅读第六章，*Redux 架构*，这一章主要讲述在 React 中使用 Redux 架构。


# 第六章：Redux 架构

在之前的章节中，我们学习了如何创建自定义组件，与 React 进行 DOM 交互，以及如何在 React 中使用 JSX，这些都足以让你对 React 及其在不同平台上的变化有足够的了解，例如添加工单表单应用程序的实际示例。现在我们将进入一个高级水平，这将让你进一步了解 JavaScript 应用程序中的状态管理。

# Redux 是什么？

正如我们所知，在**单页面应用程序**（**SPAs**）中，当我们需要处理状态和时间时，很难掌握随时间变化的状态。在这里，Redux 非常有帮助。为什么？因为在 JavaScript 应用程序中，Redux 处理两种状态：一种是数据状态，另一种是 UI 状态，这是 SPAs 的标准选项。此外，请记住，Redux 可以与 AngularJS、jQuery 或 React JS 库或框架一起使用。

Redux 是什么意思？简而言之，Redux 是在开发 JavaScript 应用程序时处理状态的助手。

我们在之前的例子中看到，数据只能从父级流向子级，这被称为*单向数据流*。React 也有相同的数据流方向，从数据到组件，因此在这种情况下，React 中的两个组件之间要进行正确的通信会非常困难。

我们可以在下面的图表中清楚地看到：

![什么是 Redux？](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/B05743_06_01.jpg)

正如我们在前面的图表中所看到的，React 并不遵循两个组件之间的直接通信，尽管它具有提供该策略的功能。然而，这被认为是不良实践，因为它可能导致不准确性，而且这是一种很难理解的古老写法。

但这并不意味着在 React 中无法实现，因为它提供了另一种替代方法，但根据你的逻辑和 React 的标准，你必须加以处理。

要实现两个没有父子关系的组件之间的相同效果，你必须定义一个全局事件系统，让它们进行通信；Flux 可能是最好的例子。

这就是 Redux 的作用，它提供了一种将所有状态存储到一个组件可以访问的地方的方法，这个地方被称为**STORE**。简而言之，每当任何组件发现任何更改时，它必须首先分派到存储中，如果其他组件需要访问，它必须从存储中**订阅**。它不能直接授权与该组件的通信，如下图所示：

![Redux 是什么？](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/B05743_06_02.jpg)

在前面的图表中，我们可以看到**STORE**假装成为应用程序中所有状态修改的*中介*，Redux 通过**STORE**控制两个组件之间的直接通信，只有一个通信点。

你可能认为组件之间的通信可以通过其他策略实现，但不建议这样做，因为这样做要么会导致错误的代码，要么会难以跟踪：

![Redux 是什么？](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/B05743_06_03.jpg)

现在很清楚 Redux 是如何通过将所有状态更改分派到**STORE**而不是在组件内部进行通信来简化生活的。现在组件只需要考虑分派状态更改；所有其他责任将属于**STORE**。

Flux 模式也是这样做的。你可能听说过 Redux 受 Flux 启发，所以让我们看看它们有多相似：

比较 Redux 和 Flux，Redux 是一个工具，而 Flux 只是一个模式，你不能用来即插即用，也不能下载。我不否认 Redux 与 Flux 模式有一些相似之处，但它并不完全与 Flux 相同。

让我们看一些区别。

Redux 遵循三个指导原则，如下面的描述所示，这也将涵盖 Redux 和 Flux 之间的区别。

## 单个存储方法

我们在之前的图表中看到，存储假装成为应用程序中所有状态修改的*中介*，Redux 通过存储控制两个组件之间的直接通信，充当单一的通信点。

这里 Redux 和 Flux 的区别在于：Flux 有多个存储方法，而 Redux 有单个存储方法。

## 只读状态

在 React 应用程序中，组件不能直接更改状态，而必须通过*actions*将更改分派到存储中。

在这里，`store`是一个对象，它有四种方法，如下所示：

+   `store.dispatch` (action)

+   `store.subscribe`（监听器）

+   `store.getState()`

+   `replaceReducer`（下一个 Reducer）

您可能已经了解 JavaScript 中的`get`和`set`属性：`set`属性设置对象，`get`属性获取对象。但是使用`store`方法时，只有`get`方法，因此只有一种方法可以通过*动作*分派更改来设置状态。

以下代码显示了 JavaScript Redux 的示例：

```jsx
var action = { 
    type: 'ADD_USER', 
    user: {name: 'Dan'} 
}; 
// Assuming a store object has been created already 
store.dispatch(action); 

```

在这里，动作意味着`dispatch()`，其中`store`方法将发送一个对象来更新状态。在上述代码片段中，`action`采用`type`数据来更新状态。您可以根据组件的需要设计不同的方式来设置您的动作。

## Reducer 函数用于更改状态

Reducer 函数将处理`dispatch`动作以改变状态，因为 Redux 工具不允许两个组件之间的直接通信，因此它也不会改变状态，而是将`dispatch`动作描述为状态更改。

在下面的代码片段中，您将看到`Reducer`如何通过允许当前状态作为参数并返回新状态来改变`state`：

```jsx
Javscript: 
// Reducer Function 
varsomeReducer = function(state, action) { 
    ... 
    return state; 
} 

```

这里的 Reducer 可以被视为纯函数。以下是编写`Reducer`函数的一些特征：

+   没有外部数据库或网络调用

+   根据其参数返回值

+   参数是*不可变的*

+   相同的参数返回相同的值

Reducer 函数被称为纯函数，因为它们除了根据其设置的参数纯粹返回值之外，什么都不做；它们没有其他后果。

# Redux 的架构

正如我们所讨论的，Redux 受 Flux 模式的启发，因此也遵循其架构。这意味着状态变化将被发送到存储库，并且存储库将处理动作以在组件之间进行通信。

让我们看看数据和逻辑是如何通过以下图表工作的：

![Redux 的架构](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_06_004.jpg)

观察以下要点以了解 Redux 架构：

+   您可以在上图中看到，在右下方，组件触发动作。

+   状态突变将以与 Flux 请求中相同的方式发生，并且可能会有另一个效果作为**API**请求。

+   中间件在这里扮演着重要角色，比如处理监听承诺状态的操作以及采取新的行动。

+   **Reducers**负责作为中间件处理动作。

+   **Reducer**作为中间件获取所有动作请求，它还与数据相关联。它有权通过定义新状态全局更改应用程序存储中的状态。

+   当我们说状态改变时，这涉及重新选择其选择器并转换数据并通过组件传递。

+   当组件获得更改请求时，相应地，它会将 HTML 呈现给 DOM 元素。

在我们继续之前，我们必须了解流程，以确保结构顺畅。

## Redux 的架构优势

与其他框架相比，Redux 具有更多的优势：

+   它可能没有其他副作用

+   正如我们所知，不需要绑定，因为组件不能直接交互

+   状态是全局管理的，因此出现管理不善的可能性较小

+   有时，对于中间件来说，管理其他副作用可能会很困难

从上述观点来看，Redux 的架构非常强大，而且具有可重用性。让我们看一个实际的例子，看看 Redux 如何与 React 一起工作。

我们将在 Redux 中创建我们的 Add Ticket 表单应用程序。

# Redux 设置

让我们从 Redux 中的`UserList`示例开始。首先，创建一个带有应用程序的目录。我们在这个示例中使用 Node.js 服务器和 npm 包，因为 Redux 模块不能独立使用。

## 安装 Node.js

首先，如果我们尚未在系统中安装 Node.js，我们必须下载并安装 Node.js。我们可以从[`nodejs.org`](http://nodejs.org)下载 Node.js。它包括 npm 包管理器。

设置完成后，我们可以检查 Node.js 是否设置正确。打开命令提示窗口并运行以下命令：

```jsx
**node --version**
```

您应该能够看到版本信息，这可以确保安装成功。

### 设置应用程序

首先，我们需要为我们的项目创建一个`package.json`文件，其中包括项目信息和依赖项。现在，打开命令提示符/控制台，并导航到您创建的目录。运行以下命令：

```jsx
**Npm init**
```

这个命令将初始化我们的应用程序，并询问一些问题，以创建一个名为`package.json`的 JSON 文件。该实用程序将询问有关项目名称、描述、入口点、版本、作者名称、依赖项、许可信息等的问题。一旦执行了该命令，它将在项目的根目录中生成一个`package.json`文件：

```jsx
{ 
  "name": "react-redux add ticket form example", 
  "version": "1.0.0", 
  "description": "", 
  "scripts": { 
    "start": "node server.js", 
    "lint": "eslintsrc" 
  }, 
  "keywords": [ 
    "react", 
   "redux", 
   "redux form", 
    "reactjs", 
    "hot", 
    "reload", 
    "live", 
    "webpack" 
  ], 
  "author": "Harmeet Singh <harmeet.singh090@gmail.com>", 
  "license": "MiIT", 
  "devDependencies": { 
    "babel-core": "⁵.8.3", 
    "babel-eslint": "⁴.0.5", 
    "babel-loader": "⁵.3.2", 
    "css-loader": "⁰.15.6", 
    "cssnext-loader": "¹.0.1", 
    "eslint": "⁰.24.1", 
    "eslint-plugin-react": "³.1.0", 
    "extract-text-webpack-plugin": "⁰.8.2", 
    "html-webpack-plugin": "¹.6.1", 
    "react-hot-loader": "¹.2.7", 
    "redux-devtools": "¹.0.2", 
    "style-loader": "⁰.12.3", 
    "webpack": "¹.9.6", 
    "webpack-dev-server": "¹.8.2" 
  }, 
  "dependencies": { 
    "classnames": "².1.3", 
    "lodash": "³.10.1", 
    "react": "⁰.13.0", 
    "react-redux": "⁰.2.2", 
    "redux": "¹.0.0-rc" 
  } 
} 

```

好的，让我在开始之前向您解释一些主要工具：

+   `webpack-dev-server`：这是用于应用程序实时重新加载的服务器。

+   `babel-loader`：这是我们 JavaScript 的编译器。

+   `redux-devtools`：这是 Redux 开发的强大工具。在开发中使用此工具将帮助我们监视 DOM UI 中的更新。

+   `classnames`：这是一个模块，将帮助我们根据条件应用类。

+   `eslint`：这是类似于 JSHint 和 JSLint 用于解析 JavaScript 的工具。

## 开发工具设置

首先，我们需要创建`webpack.config.js`并添加以下代码以启用`redux-devtools`：

```jsx
var path = require('path'); 
varwebpack = require('webpack'); 
varExtractTextPlugin = require('extract-text-webpack-plugin'); 
vardevFlagPlugin = new webpack.DefinePlugin({ 
  __DEV__: JSON.stringify(JSON.parse(process.env.DEBUG || 'true')) 
}); 

module.exports = { 
  devtool: 'eval', 
  entry: [ 
    'webpack-dev-server/client?http://localhost:3000', 
    'webpack/hot/only-dev-server', 
    './src/index' 
  ], 
  output: { 
    path: path.join(__dirname, 'dist'), 
    filename: 'bundle.js', 
    publicPath: '/static/' 
  }, 
  plugins: [ 
    new webpack.HotModuleReplacementPlugin(), 
    new webpack.NoErrorsPlugin(), 
    devFlagPlugin, 
    new ExtractTextPlugin('app.css') 
  ], 
  module: { 
    loaders: [ 
      { 
        test: /\.jsx?$/, 
        loaders: ['react-hot', 'babel'], 
        include: path.join(__dirname, 'src') 
      }, 
      { test: /\.css$/, loader: ExtractTextPlugin.extract
      ('css-loader?module!cssnext-loader') } 
    ] 
  }, 
  resolve: { 
    extensions: ['', '.js', '.json'] 
  } 
}; 

```

现在，创建一个名为`src`的目录。在其中，我们需要创建一些文件夹，如下面的截图所示：

![开发工具设置](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_06_005.jpg)

## Redux 应用程序设置

在每个 Redux 应用程序中，我们都有 actions、reducers、stores 和 components。让我们从为我们的应用程序创建一些 actions 开始。

### Actions

Actions 是从我们的应用程序发送数据到我们的 store 的信息的一部分。

首先，我们需要在 actions 文件夹内创建`UsersActions.js`文件，并将以下代码放入其中：

```jsx
import * as types from '../constants/ActionTypes'; 

export function addUser(name) { 
  return { 
    type: types.ADD_USER, 
    name 
  }; 
} 

export function deleteUser(id) { 
  return { 
    type: types.DELETE_USER, 
    id 
  }; 
} 

```

在上面的代码中，我们创建了两个动作：`addUser`和`deleteUser`。现在我们需要在`constants`文件夹内创建`ActionTypes.js`，定义`type`：

```jsx
export constADD_USER = 'ADD_USER'; 
export constDELETE_USER = 'DELETE_USER';  

```

### Reducers

Reducers 处理描述发生了什么事情的 actions，但管理应用程序状态是 reducers 的责任。它们存储先前的`state`和`action`，并`return`下一个`state`：

```jsx
export default function users(state = initialState, action) { 
  switch (action.type) { 
    case types.ADD_USER: 
    constnewId = state.users[state.users.length-1] + 1; 
      return { 
        ...state, 
        users: state.users.concat(newId), 
        usersById: { 
          ...state.usersById, 
          [newId]: { 
            id: newId, 
            name: action.name 
          } 
        }, 
      } 

     case types.DELETE_USER: 
     return { 
       ...state, 
       users: state.users.filter(id => id !== action.id), 
       usersById: omit(state.usersById, action.id) 
     } 

     default: 
     return state; 
  } 
} 

```

### Store

我们已经定义了 actions 和 reducers，它们代表了关于*发生了什么*的事实，以及何时需要根据这些 actions 更新状态。

`store`是将 actions 和 reducers 结合在一起的对象。store 有以下职责：

+   保存应用程序状态

+   通过`getState()`和`dispatch`（action）允许访问和更新状态。

+   通过`subscribe`（监听器）注册和取消注册监听器

以下是 container 文件夹中`UserListApp.js`的代码：

```jsx
constinitialState = { 
  users: [1, 2, 3], 
  usersById: { 
    1: { 
      id: 1, 
      name: 'Harmeet Singh' 
    }, 
    2: { 
      id: 2, 
      name: 'Mehul Bhatt' 
    }, 
    3: { 
      id: 3, 
      name: 'NayanJyotiTalukdar' 
    } 
  } 
}; 
import React, { Component, PropTypes } from 'react'; 
import { bindActionCreators } from 'redux'; 
import { connect } from 'react-redux'; 

import * as UsersActions from '../actions/UsersActions'; 
import { UserList, AddUserInput } from '../components'; 

@connect(state => ({ 
userlist: state.userlist 
})) 
export default class UserListApp extends Component { 

  static propTypes = { 
    usersById: PropTypes.object.isRequired, 
    dispatch: PropTypes.func.isRequired 
  } 

  render () { 
    const { userlist: { usersById }, dispatch } = this.props; 
    const actions = bindActionCreators(UsersActions, dispatch); 

    return ( 
      <div> 
        <h1>UserList</h1> 
        <AddUserInputaddUser={actions.addUser} /> 
        <UserList users={usersById} actions={actions} /> 
      </div> 
    ); 
  } 
} 

```

在上面的代码中，我们使用`UserList`的静态 JSON 数据初始化组件的状态，并使用`getstate`、`dispatch`（action），然后更新 store 信息。

### 提示

在 Redux 应用程序中，我们只会有一个单一的 store。当我们需要拆分我们的数据处理逻辑时，我们将使用 reducer 组合而不是多个 store。

### Components

这些都是普通的 React JSX 组件，所以我们不需要详细介绍它们。我们已经添加了一些功能状态组件，除非我们需要使用本地状态或生命周期方法，否则我们将使用它们：

在这个（`AddUserInput.js`）文件中，我们正在创建一个 JSX 输入组件，从中获取用户输入：

```jsx
export default class AddUserInput extends Component { 
  static propTypes = { 
    addUser: PropTypes.func.isRequired 
  } 

  render () { 
    return ( 
      <input 
      type="text" 
      autoFocus="true" 
      className={classnames('form-control')} 
        placeholder="Type the name of the user to add" 
        value={this.state.name} 
        onChange={this.handleChange.bind(this)} 
        onKeyDown={this.handleSubmit.bind(this)} /> 
    ); 
  } 

  constructor (props, context) { 
    super(props, context); 
      this.state = { 
        name: this.props.name || '', 
      }; 
  } 
} 

```

在`UserList.js`中，我们正在创建一个列表组件，其中我们迭代`Input`组件的值：

```jsx
export default class UserList extends Component { 
  static propTypes = { 
    users: PropTypes.object.isRequired, 
    actions: PropTypes.object.isRequired 
  } 

  render () { 
    return ( 
      <div className="media"> 
        { 
          mapValues(this.props.users, (users) => { 
            return (<UsersListItem 
              key={users.id} 
              id={users.id} 
              name={users.name} 
               src={users.src} 
              {...this.props.actions} />); 
          }) 
        } 
      </div> 
    ); 
  } 
}

```

在`UserList`组件中迭代值后，我们将在 Bootstrap 的`media`布局中显示该列表：

```jsx
export default class UserListItem extends Component { 
  static propTypes = { 
    id: PropTypes.number.isRequired, 
    name: PropTypes.string.isRequired, 
    onTrashClick: PropTypes.func.isRequired 
  } 

  render () { 
    return ( 
      <div> 
      <div className="clearfix"> 
            <a href="#" className="pull-left"> 
            <img className="media-object img-thumbnail" 
            src={"http://placehold.it/64x64"}/> 
            </a> 
            <div className={`media-body ${styles.paddng10}`}> 
                  <h3className="media-heading"> 
                  <strong><a href="#">{this.props.name}</a></strong> 
                  </h3> 
            <p> 
                  Loremipsum dolor sit amet, consecteturadipiscingelit. 
                  Praesentgravidaeuismod ligula,
                  vel semper nuncblandit sit amet.  
            </p> 

            <div className={`pull-right ${styles.userActions}`}> 
            <button className={`btnbtn-default ${styles.btnAction}`} 
            onClick={()=>this.props.deleteUser(this.props.id)} 
            > 
            Delete the user <iclassName="fafa-trash" /> 
            </button> 
            </div> 
          </div> 
        </div> 
      </div> 
    ); 
  } 
}  

```

现在，我们需要将我们的组件包装在容器文件夹中的`UserListApp.js`中：

```jsx
import { UserList, AddUserInput } from '../components'; 
@connect(state => ({ 
  userlist: state.userlist 
})) 
export default class UserListApp extends Component {  
  static propTypes = { 
    usersById: PropTypes.object.isRequired, 
    dispatch: PropTypes.func.isRequired 
  } 

  render () { 
    const { userlist: { usersById }, dispatch } = this.props; 
    const actions = bindActionCreators(UsersActions, dispatch); 

    return ( 
      <div> 
        <h1>UserList</h1> 
        <AddUserInput addUser={actions.addUser} /> 
        <UserList users={usersById} actions={actions} /> 
      </div> 
    ); 
  } 
}
```

现在，让我们将`UserListApp`组件包装到容器文件夹中的`App.js`中的 Redux 存储中：

```jsx
import UserListApp from './UserListApp'; 
import * as reducers from '../reducers'; 

const reducer = combineReducers(reducers); 
const store = createStore(reducer); 

export default class App extends Component { 
  render() { 
    return ( 
      <div> 
        <Provider store={store}> 
          {() => <UserListApp /> } 
        </Provider> 

        {renderDevTools(store)} 
      </div> 
    ); 
  } 
} 

```

现在转到根目录，打开 CMD，并运行以下命令：

要安装此应用程序所需的软件包，请运行以下命令：

```jsx
**Npm install**
```

完成后，运行以下命令：

```jsx
**Npm start**
```

观察以下屏幕截图：

![Components](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_06_006.jpg)

看起来很棒。右侧面板是 Redux DevTool，它提供了 UI 的更新。我们可以轻松地看到在此列表中删除或添加用户的更新。

以下屏幕截图显示了从`UserList`中删除用户：

![Components](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_06_007.jpg)

以下屏幕截图显示了添加用户的过程：

![Components](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_06_008.jpg)

### 注意

请参阅第六章的源代码，*Redux 架构*，以便更好地理解应用程序的流程。

# 总结

我们现在可以看到 Redux 架构的重要性及其在 React 应用程序中的作用。我们还在本章中学习了状态管理，看看存储如何全局处理状态更改请求，Redux 有助于避免组件之间的直接交互。

本章主要讨论 Redux 架构及其细节。为了澄清，我们已经看到了提供对 Redux 架构中数据和逻辑流程理解的图表。Redux 架构受 Flux 的启发，但它有自己的特点和优势。我们希望图表和实际示例有助于让您了解 Redux 架构。

现在，我们将继续进行下一章，讨论如何在 React 中进行路由。


# 第七章：使用 React 进行路由

在之前的章节中，我们已经了解了 Redux 架构以及如何处理两种状态，即数据状态和 UI 状态，以创建单页面应用程序或组件。目前，如果需要，我们的应用程序 UI 将与 URL 同步，我们需要使用 React 路由器使我们的应用程序 UI 同步。

# React 路由器的优势

让我们看一下 React 路由器的一些优势：

+   以标准化结构查看声明有助于我们立即了解我们的应用视图

+   延迟加载代码

+   使用 React 路由器，我们可以轻松处理嵌套视图和渐进式视图分辨率

+   使用浏览历史功能，用户可以向后/向前导航并恢复视图的状态

+   动态路由匹配

+   导航时视图上的 CSS 过渡

+   标准化的应用程序结构和行为，在团队合作时非常有用

### 注意

React 路由器不提供任何处理数据获取的方式；我们需要使用`asyncProps`或另一种 React 数据获取机制。

在本章中，我们将看看如何创建路由，以及包含参数的路由。在开始之前，让我们计划一下我们的**员工信息系统**（**EIS**）需要哪些路由。请查看以下屏幕截图：

![React 路由器的优势](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_001.jpg)

上述屏幕截图来自第二章 *使用 React-Bootstrap 和 React 构建响应式主题*供您参考。

在第二章 *使用 React-Bootstrap 和 React 构建响应式主题*中，我们为我们的应用程序创建了响应式主题布局。现在我们将在其中添加路由以导航到每个页面。

+   **主页**：这将是我们的主页，将显示员工的个人资料信息

+   **编辑个人资料**：在这里，我们将能够编辑员工的信息

+   **查看工单**：在这个页面，员工将能够查看他提交的工单

+   **新工单**：在这里，员工可以提交工单

这些都是我们必要的路由；让我们看看如何创建它们。

# 安装路由器

React 路由器已经作为 React 库之外的不同模块打包。我们可以在 React 路由器 CDN 上使用 React 路由器 CDN：[`cdnjs.cloudflare.com/ajax/libs/react-router/4.0.0-0/react-router.min.js`](https://cdnjs.cloudflare.com/ajax/libs/react-router/4.0.0-0/react-router.min.js)。

我们可以像这样将其包含在我们的项目中：

```jsx
var { Router, Route, IndexRoute, Link, browserHistory } = ReactRouter 

```

或者我们可以使用 React 的`npm`包：

```jsx
**$ npm install --save react-router**
```

使用 ES6 转译器，比如 Babel：

```jsx
import { Router, Route, Link } from 'react-router'
```

不使用 ES6 转译器：

```jsx
var Router = require('react-router').Router 
var Route = require('react-router').Route 
var Link = require('react-router').Link 

```

好的，现在让我们设置我们的项目并包括 React 路由器。

# 应用程序设置

React 路由器看起来与其他 JS 路由器不同。它使用 JSX 语法，这使得它与其他路由器不同。首先，我们将创建一个示例应用程序，而不使用`npm`包，以更好地理解路由器的概念。

按照以下说明进行设置：

1.  将`第二章`目录结构和文件复制到`第七章`中。

1.  删除现有的 HTML 文件并创建一个新的`index.html`。

1.  在您的 HTML 中复制此样板代码：

```jsx
        <!doctype html>
        <html lang="en">
            <head>
                <meta charset="utf-8">
                <title>React Router - Sample application with 
                bootstrap</title>
                <link rel="stylesheet" href="css/bootstrap.min.css">
                <link rel="stylesheet" href="css/font-awesome.min.css">
                <link rel="stylesheet" href="css/custom.css">
                <script type="text/javascript" src="js/react.js"></script>
                <script type="text/javascript" src="js/react-dom.min.js">
                </script>
                <script src="js/browser.min.js"></script>
                <script src="js/jquery-1.10.2.min.js"></script>
                <script src="js/bootstrap.min.js"></script>
                <script src="https://unpkg.com/react-router/umd/
                ReactRouter.min.js"></script>
                <script src="components/bootstrap-navbar.js" type=
                "text/babel"></script>
                <script src="components/sidebar.js" type="text/babel">
                </script>
                <script src="components/sidebar.js" type="text/babel">
                </script>
            </head>
            <body>
                <div id="nav"></div>
                <div class="container">
                    <h1>Welcome to EIS</h1>
                    <hr>
                    <div class="row">
                        <div class="col-sm-3" id="sidebar">
                            <!--left col-->
                        </div>
                        <!--/col-3-->
                        <div class="col-sm-9 profile-desc" id="main">
                        </div>
                        <!--/col-9-->
                    </div>
                </div>
                <!--/row-->
            </body>
        </html> 

```

1.  在浏览器中打开`index.html`。确保输出不显示控制台中的任何错误。

# 创建路由

由于我们已经创建了 HTML，现在我们需要在之前创建的`bootstrap-navbar.js`中添加一个 Bootstrap `navbar`组件。

为了配置路由，让我们在`routing.js`中创建一个组件，它将与 URL 同步：

```jsx
var homePage = React.createClass({ 
    render: function() { 
        return (<h1>Home Page</h1>); 
    } 
}); 
ReactDOM.render(( 
    <homePage /> 
), document.getElementById('main')); 

```

在浏览器中打开它，看起来是这样的：

![创建路由](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_002.jpg)

让我们添加`Router`来渲染我们的`homePage`组件与 URL：

```jsx
ReactDOM.render(( 
    <Router> 
        <Route path="/" component={homePage} /> 
    </Router> 
), document.getElementById('main'));  

```

在前面的例子中，使用`<Route>`标签定义了一个规则，访问首页将把`homePage`组件渲染到`'main'`中。正如我们已经知道的那样，React 路由器使用 JSX 来配置路由。`<Router>`和`<Route>`是不同的东西。`<Router>`标签应该始终是包裹多个 URL 的主要父标签，而`<Route>`标签。我们可以声明多个带有属性组件的`<Route>`标签，使您的 UI 同步。当历史记录发生变化时，`<Router>`将使用匹配的 URL 渲染组件：

```jsx
ReactDOM.render(( 
    <Router> 
        <Route path="/" component={homePage} /> 
        <Route path="/edit" component={Edit} /> 
        <Route path="/alltickets" component={allTickets} /> 
        <Route path="/newticket" component={addNewTicket} /> 
    </Router> 
), document.getElementById('main'));
```

看起来非常简单和清晰，路由器将在视图之间切换路由，而不会向服务器发出请求并将它们渲染到 DOM 中。

# 页面布局

让我们假设如果我们需要为每个组件都需要不同的布局，比如首页应该有两列，其他页面应该有一列，但它们都共享头部和页脚等公共资产。

这是我们应用程序的布局草图：

![页面布局](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_003.jpg)

好的，现在让我们创建我们的主要布局：

```jsx
var PageLayout = React.createClass({
    render: function() {
        return ( 
            <div className="container">
                <h1>Welcome to EIS</h1>
                <hr/>
                <div className="row">
                    <div className="col-md-12 col-lg-12">
                        {this.props.children}
                    </div>
                </div>
            </div>
        )
    }
}) 

```

在上面的代码中，我们已经为我们的应用程序创建了主要布局，它使用`this.props.children`来处理子布局组件，而不是硬编码的组件。现在我们将创建在我们的主要布局组件中呈现的子组件：

```jsx
var RightSection = React.createClass({
    render: function() {
        return (
            <div className="col-sm-9 profile-desc" id="main">
                <div className="results">
                    <PageTitle/>
                    <HomePageContent/>
                </div>
            </div>
        )
    }
})
var ColumnLeft = React.createClass({
    render: function() {
        return (
            <div className="col-sm-3" id="sidebar">
                <div className="results">
                    <LeftSection/>
                </div>
            </div>
        )
    }
})

```

在上面的代码中，我们创建了两个组件，`RightSection`和`ColumnLeft`，来包装和分割我们的组件在不同的部分。

所以在响应式设计中，我们应该很容易管理布局：

```jsx
var LeftSection = React.createClass({ 
    render: function() { 
        return ( 
            React.DOM.ul({ className: 'list-group' }, 
            React.DOM.li({className:'list-group-item 
            text-muted'},'Profile'), 
            React.DOM.li({className:'list-group-item'}, 
            React.DOM.a({className:'center-block 
            text-center',href:'#'},'Image') 
        ), 
        React.DOM.li({className:'list-group-item text-right'},'2.13.2014', 
        React.DOM.span({className:'pull-left'}, 
        React.DOM.strong({className:'pull-left'},'Joining Date') 
        ), 
        React.DOM.div({className:'clearfix'}) 
        ))                                                             
      ) 
    } 
}) 
var TwoColumnLayout = React.createClass({ 
    render: function() { 
        return ( 
            <div> 
                <ColumnLeft/> 
                <RightSection/> 
            </div> 
        ) 
    } 
}) 
var PageTitle = React.createClass({ 
    render: function() { 
        return ( 
            <h2>Home</h2> 
        ); 
    } 
}); 

```

在上面的代码中，我们将组件分成了两个部分：`<ColumnLeft/>`和`<RightSection/>`。我们在`<TwoColumnLayout/>`组件中给出了这两个组件的引用。在父组件中，我们有`this.props.children`作为一个 prop，但只有当组件是嵌套的时候才起作用，React 会自动负责填充这个 prop。如果组件不是父组件，`this.props.children`将为 null。

# 嵌套路由

好的，我们已经创建了特定布局组件，但我们仍然需要看看如何为它们创建嵌套路由，以便将组件传递给具有 props 的父组件。这很重要，以便在我们的 EIS 应用程序中实现一定程度的动态性。这是我们的 HTML，显示当前的样子：

```jsx
<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <title>React Router - Sample application with bootstrap</title>
        <link rel="stylesheet" href="css/bootstrap.min.css">
        <link rel="stylesheet" href="css/font-awesome.min.css">
        <link rel="stylesheet" href="css/custom.css">
    </head>
    <body>
        <div id="nav"></div>
        <div id="reactapp"></div>
        <script type="text/javascript" src="js/react.js"></script>
        <script type="text/javascript" src="js/react-dom.min.js"></script>
        <script src="js/browser.min.js"></script>
        <script src="js/jquery-1.10.2.min.js"></script>
        <script src="js/bootstrap.min.js"></script>
        <script src="https://unpkg.com/react-router/umd/
        ReactRouter.min.js"></script>
        <script src="components/bootstrap-navbar.js" 
        type="text/babel"></script>
        <script src="components/router.js" type="text/babel"></script>    
    </body>
</html>  

```

让我们再次看一下我们之前创建的路由器：

```jsx
ReactDOM.render((
    <Router>
        <Route path="/" component={PageLayout}>
            <IndexRoute component={TwoColumnLayout}/>
            <Route path="/edit" component={Edit} />
            <Route path="/alltickets" component={allTickets} />
            <Route path="/newticket" component={addNewTicket} />
        </Route>
    </Router>
), document.getElementById('reactapp'));

```

现在我们已经在与父级的映射中添加了额外的元素`<IndexRoute />`，将其视图设置为我们的`{TwoColumnLayout}`组件。`IndexRoute`元素负责在应用程序初始加载时显示哪个组件。

不要忘记在`{PageLayout}`组件中包装。我们还可以在`<indexRoute>`上定义路径规则，与`<Route>`相同：

```jsx
ReactDOM.render((
<Router>
    <Route component={PageLayout}>
        <IndexRoute path="/" component={TwoColumnLayout}/>
        <Route path="/edit" component={Edit} />
        <Route path="/alltickets" component={allTickets} />
        <Route path="/newticket" component={addNewTicket} />
    </Route>
</Router>
), document.getElementById('reactapp'));

```

观察以下截图：

![嵌套路由](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_004.jpg)

看起来不错。如我们在`<IndexRoute>`中提到的，它总是在第一次加载页面时加载`<TwoColumnLayout>`。现在让我们导航并查看一些其他页面。

React 还为我们提供了一种使用`<IndexRedirect>`组件重定向路由的方法：

```jsx
<Route path="/" component={App}> 
    <IndexRedirect to="/welcome" /> 
    <Route path="welcome" component={Welcome} /> 
    <Route path="profile" component={profile} /> 
</Route> 

```

观察以下截图：

![嵌套路由](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_005.jpg)

您可能已经注意到，我点击了**编辑个人资料**页面，它呈现了编辑页面组件，但没有在当前活动链接上添加活动类。为此，我们需要用 React 的`<Link>`标签替换`<a>`标签。

## React 路由

React 路由使用了`<link>`组件，而不是我们在`nav`中使用的`<a>`元素。如果我们使用 React 路由，则必须使用这个。让我们在导航中添加`<link>`而不是`<a>`标签，并替换`href`属性为两个。

`<a>`标签：

```jsx
<li className="active"><a href="#/">Home</a></li> 

```

用这个替换：

```jsx
<li className="active"><Link to="#/">Home</Link></li> 

```

让我们在浏览器中查看`<link>`的行为：

![React router](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_006.jpg)

它在控制台中显示错误，因为我们没有在`ReactRouter`对象中添加`Link`组件引用：

```jsx
var { Router, Route, IndexRoute, IndexLink, Link, browserHistory } = ReactRouter 

```

我们还添加了`browserHistory`对象，稍后我们会解释。

这是我们的`PageLayout`组件的样子：

```jsx
var PageLayout = React.createClass({
render: function() {
return ( 
<main>
    <div className="navbar navbar-default navbar-static-top"
    role="navigation">
        <div className="container">
            <div className="navbar-header">
                <button type="button" className="navbar-toggle"
                data-toggle="collapse"
                data-target=".navbar-collapse">
                <span className="sr-only">Toggle navigation</span>
                <span className="icon-bar"></span>
                <span className="icon-bar"></span>
                <span className="icon-bar"></span>
                </button>
                <Link className="navbar-brand" to="/">
                EIS</Link>
            </div>
            <div className="navbar-collapse collapse">
                <ul className="nav navbar-nav">
                    <li className="active">
                        <IndexLink activeClassName="active" to="/">
                        Home</IndexLink>
                    </li>
                    <li>
                        <Link to="/edit" activeClassName="active">
                        Edit Profile</Link>
                    </li>
                    <li className="dropdown">
                        <Link to="#" className="dropdown-toggle"
                        data-toggle="dropdown">
                        Help Desk <b className="caret"></b></Link>
                        <ul className="dropdown-menu">
                            <li>
                                <Link to="/alltickets">
                                View Tickets</Link>
                            </li>
                            <li>
                                <Link to="/newticket">
                                New Ticket</Link>
                            </li>
                        </ul>
                    </li>
                </ul>
            </div>
        </div>
    </div>
    <div className="container">
        <h1>Welcome to EIS</h1>
        <hr/>
        <div className="row">
            <div className="col-md-12 col-lg-12">
                {this.props.children}
            </div>
        </div>
    </div>
</main>
)
}
})
```

为了激活默认链接，我们使用了`<IndexRoute>`。这会自动定义默认链接的活动类。`activeClassName`属性将 URL 与`to`值匹配并将活动类添加到其中。如果我们不使用`activeClassName`，则无法自动在活动链接上添加类。让我们快速看一下浏览器：

![React router](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_007.jpg)

它按预期工作。让我们在控制台中查看 DOM HTML：

![React router](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_008.jpg)

我们只需要覆盖`<li> .active`上的 Bootstrap 默认样式为`<a>`：

```jsx
.navbar-default .navbar-nav li>.active, .navbar-default
.navbar-nav li>.active:hover, .navbar-default 
.navbar-nav li>.active:focus { 
    color: #555; 
    background-color: #e7e7e7; 
}  

```

我们还可以在路由中传递参数来匹配、验证和渲染 UI：

```jsx
<Link to={`/tickets/${ticket.id}`}>View Tickets</Link>
```

在路由器中，我们需要添加：

```jsx
<Route path="tickets/:ticketId" component={ticketDetail} /> 

```

我们可以添加尽可能多的参数，并且很容易在我们的组件中提取这些参数。我们将以对象的形式访问所有`route`参数。

React 路由支持 IE9+浏览器版本，但对于 IE8，您可以使用 Node `npm`包`react-router-ie8`

### NotFoundRoute

React 路由还提供了一种在客户端显示 404 错误的方法，如果路径与路由不匹配：

```jsx
var NoMatch = React.createClass({ 
   render: function() { 
       return (<h1>URL not Found</h1>); 
   } 
}); 

<Route path="*" component={NoMatch}/>
```

观察以下截图：

![NotFoundRoute](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_009.jpg)

我们可以很容易地处理不匹配的 URL，这太棒了。

这是我们的路由器的样子：

```jsx
ReactDOM.render(( 
    <Router> 
        <Route path="/" component={PageLayout}> 
            <IndexRoute component={TwoColumnLayout}/> 
                <Route path="/edit" component={Edit} /> 
                <Route path="/alltickets" component={allTickets} /> 
                <Route path="/newticket" component={addNewTicket} /> 
                </Route> 
        <Route path="*" component={NoMatch}/> 
    </Router> 
), document.getElementById('reactapp')); 

```

以下是我们可以使用的其他`link`属性列表：

+   `activeStyle`：我们可以用这个来自定义内联样式。例如：

```jsx
        <Link activeStyle={{color:'#53acff'}} to='/'>Home</Link>
```

+   `onlyActiveOnIndex`：当我们使用`activeStyle`属性添加自定义内联样式时，我们可以使用这个属性。它只在我们在精确链接上时应用。例如：

```jsx
        <Link onlyActiveOnIndex activeStyle={{color:'#53acff'}} 
        to='/'>Home</Link>
```

### 浏览器历史

React 路由的另一个很酷的功能是它使用`browserHistory` API 来操作 URL 并创建干净的 URL。

使用默认的`hashHistory`：

```jsx
  http://localhost:9090/react/chapter7/#/?_k=j8dlzv
  http://localhost:9090/react/chapter7/#/edit?_k=yqdzh0 http://localhost:9090/react/chapter7/#/alltickets?_k=0zc49r
  http://localhost:9090/react/chapter7/#/newticket?_k=vx8e8c
```

当我们在我们的应用程序中使用`browserHistory`时，URL 看起来很干净：

```jsx
 http://localhost:9090/react/chapter7/
 http://localhost:9090/react/chapter7/edit
 http://localhost:9090/react/chapter7/alltickets
 http://localhost:9090/react/chapter7/newticket
```

现在 URL 看起来干净且用户友好。

### 查询字符串参数

我们还可以将查询字符串作为`props`传递给将在特定路由上呈现的任何组件。要访问这些 prop 参数，我们需要在我们的组件中添加`props.location.query`属性。

要查看这是如何工作的，让我们创建一个名为`RouteQueryString`的新组件：

```jsx
var QueryRoute = React.createClass({ 
    render: function(props) { 
        return (<h2>{this.props.location.query.message}</h2>); 
        // Using this we can read the parameters from the 
        request which are visible in the URL's
    } 
}); 
<IndexLink activeClassName='active' to= 
     {{ pathname: '/query', query: { message: 'Hello from Route Query' } }}> 
         Route Query 
</IndexLink> 

```

在路由器中包含此路由路径：

```jsx
<Route path='/query' component={QueryRoute} /> 

```

让我们在浏览器中看看输出：

![查询字符串参数](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/lrn-web-dev-react-bts/img/image_07_010.jpg)

很好，它的工作正常。

现在我们的`Router`配置看起来是这样的：

```jsx
ReactDOM.render((
    <Router>
        <Route path="/" component={PageLayout}>
            <IndexRoute component={TwoColumnLayout}/>
            <Route path="/edit" component={Edit} />
            <Route path="/alltickets" component={allTickets} />
            <Route path="/newticket" component={addNewTicket} />
            <Route path='/query' component={QueryRoute} />
        </Route>
        <Route path="*" component={NoMatch}/>
    </Router>
), document.getElementById('reactapp'));

```

## 进一步定制您的历史记录

如果我们想要定制历史选项或使用历史记录中的其他增强器，那么我们需要使用 React 的`useRouterHistory`组件。

`useRouterHistory`已经使用`useQueries`和`useBasename`从历史工厂预增强。示例包括：

```jsx
import { useRouterHistory } from 'react-router' 
import { createHistory } from 'history' 
const history = useRouterHistory(createHistory)({ 
    basename: '/base-path' 
}) 

```

使用`useBeforeUnload`增强器：

```jsx
import { useRouterHistory } from 'react-router' 
import { createHistory,useBeforeUnload } from 'history' 
const history = useRouterHistory(useBeforeUnload(createHistory))() 
history.listenBeforeUnload(function () { 
    return 'Are you sure you want to reload this page?' 
}) 

```

在使用 React 路由之前，我们必须了解 React 路由版本更新。

请访问此链接[`github.com/ReactTraining/react-router/blob/master/upgrade-guides/v2.0.0.md`](https://github.com/ReactTraining/react-router/blob/master/upgrade-guides/v2.0.0.md)以获取更新。

以下是路由器中不推荐使用的语法的简短列表：

```jsx
<Route name="" /> is deprecated. Use <Route path="" /> instead. 
<Route handler="" /> is deprecated. Use <Route component="" /> instead. 
<NotFoundRoute /> is deprecated. See Alternative 
<RouteHandler /> is deprecated. 
willTransitionTo is deprecated. See onEnter 
willTransitionFrom is deprecated. See onLeave 
query={{ the: 'query' }} is deprecated. Use to={{ pathname: '/foo', query: { the: 'query' } }} 

```

`history.isActive`被替换为`router.isActive`。

`RoutingContext`被重命名为`RouterContext`。

# 摘要

在本章中，我们将我们的应用程序从单个页面转换为多个页面和多路由应用程序，我们可以在其上构建我们的 EIS 应用程序。我们首先规划了应用程序中的主要路由，然后创建了一个组件。

然后，我们看了如何使用`<Router>`和`<Route>`方法设置我们的路由。这是通过`var { Router, Route, IndexRoute,IndexLink, Link, browserHistory } = ReactRouter`完成的。我们还看了其他方法：`<Link>`、`<IndexLink>`和`<IndexRoute>`。

这使我们能够设置包含参数的静态和动态路由，使我们的应用程序 UI 与 URL 完美同步。

在下一章中，我们将讨论如何将其他 API 与 React 集成。
