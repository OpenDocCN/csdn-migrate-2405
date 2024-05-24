# MobX 快速启动指南（二）

> 原文：[`zh.annas-archive.org/md5/ac898efa7699227dc4bedcb64bab44d7`](https://zh.annas-archive.org/md5/ac898efa7699227dc4bedcb64bab44d7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：派生、操作和反应

现在，MobX 的基础已经奠定了*可观察*、*操作*和*反应*这三大支柱，是时候深入了解更精妙的细节了。在本章中，我们将探索 MobX API 的核心理念和微妙之处，以及一些特殊的 API 来简化 MobX 中的异步编程。

本章涵盖的主题包括：

+   计算属性（也称为派生）及其各种选项

+   操作，特别关注异步操作

+   反应和规则，控制 MobX 反应的时机

# 技术要求

您需要在系统上安装 Node.js。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/MobX-Quick-Start-Guide/tree/master/src/Chapter05`](https://github.com/PacktPublishing/MobX-Quick-Start-Guide/tree/master/src/Chapter05)

查看以下视频，了解代码的运行情况：

[`bit.ly/2mAvXk9`](http://bit.ly/2mAvXk9)

# 派生（计算属性）

*派生*是 MobX 术语中经常使用的一个词。在客户端状态建模中特别强调。正如我们在上一章中看到的，可观察状态可以由*核心可变状态*和*派生只读状态*的组合确定：

*可观察状态 = (核心可变状态) + (派生只读状态)*

尽量保持核心状态尽可能精简。这部分预计在应用程序的生命周期内保持稳定并缓慢增长。只有核心状态实际上是可变的，*操作*总是只改变*核心状态*。派生状态取决于核心状态，并由 MobX 反应性系统保持最新。我们知道 *计算属性* 在 MobX 中充当派生状态。它们不仅可以依赖于*核心状态*，还可以依赖于其他派生状态，从而创建一个由 MobX 保持活跃的依赖树：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00026.jpeg)

派生状态的一个关键特征是它是*只读*的。它的工作是生成一个*计算值*（使用*核心状态*），但永远不会改变*核心状态*。MobX 很聪明地缓存这些计算值，并且在没有*计算值*的观察者时不执行任何不必要的计算。强烈建议尽可能利用计算属性，并不用担心性能影响。

让我们举一个例子，你可以拥有一个最小的核心状态和一个派生状态来满足 UI 的需求。考虑一下`Todo`，`TodoList`和`TodoManager`。你可能猜到这些类是做什么的。它们构成了*Todos*应用程序的可观察状态：

```jsx
import { computed, decorate, observable, autorun, action } from 'mobx';

class Todo {
    @observable title = '';
    @observable done = false;

    constructor(title) {
        this.title = title;
    }
}

class TodoList {
    @observable.shallow todos = [];

    **@computed**
  get pendingTodos() {
        return this.todos.filter(x => x.done === false);
    }

    **@computed**
  get completedTodos() {
        return this.todos.filter(x => x.done);
    }

 @computed
    get pendingTodosDescription() {
        const count = this.pendingTodos.length; return `${count} ${count === 1 ? 'todo' : 'todos'} remaining`;
    }

 @action  addTodo(title) {
 const todo = new Todo(title);
 this.todos.push(todo);
    }
}

class TodoManager {
    list = null;

    @observable filter = 'all'; // all, pending, completed
  @observable title = ''; // user-editable title when creating a new 
    todo

    constructor(list) {
        this.list = list;

        autorun(() => {
            console.log(this.list.pendingTodos.length);
        });
    }

    **@computed**
  get visibleTodos() {
        switch (this.filter) {
            case 'pending':
                return this.list.pendingTodos;
            case 'completed':
                return this.list.completedTodos;
            default:
                return this.list.todos;
        }
    }
}
```

从上面的代码中可以看出，核心状态由使用`@observable`标记的属性定义。它们是这些类的可变属性。对于*Todos*应用程序，核心状态主要是`Todo`项目的列表。

派生状态主要是为了满足 UI 的过滤需求，其中包括使用`@computed`标记的属性。特别感兴趣的是`TodoList`类，它只有一个`@observable`：一个`todos`数组。其余的是由`@computed`标记的`pendingTodos`，`pendingTodosDescription`和`completedTodos`组成的派生状态。

通过保持精简的核心状态，我们可以根据 UI 的需要产生许多派生状态的变化。这样的派生状态也有助于保持语义模型的清晰和简单。这也给了你一个机会来*强制执行领域的词汇*，而不是直接暴露原始的核心状态。

# 这是一个副作用吗？

在第一章 *状态管理简介*中，我们谈到了副作用的作用。这些是应用程序的响应性方面，根据状态（也称为数据）的变化产生*外部效果*。如果我们现在通过副作用的角度来看*computed 属性*，你会发现它与 MobX 中的反应非常相似。毕竟，在 MobX 中，反应会查看可观察对象并产生副作用。计算属性也是这样做的！它依赖于可观察对象并产生可观察值作为副作用。那么，*computed 属性*应该被视为副作用吗？

确实是一个非常有力的论点。它可能会出现作为它派生的一种副作用，但它生成*可观察值*的事实将其带回到*客户端状态*的世界，而不是成为外部影响。实际上，计算属性是 UI 和其他状态管理方面的数据。与 MobX 引起副作用的函数（如`autorun()`、`reaction()`和`when()`）不同，计算属性不会引起任何*外部*副作用，并且保持在客户端状态的范围内。

MobX 反应和计算属性之间的另一个明显区别是，*计算属性有一个隐含的期望会返回一个值*，而反应是*即时反应*，没有期望得到一个值。此外，对于计算属性，重新评估（计算属性的*副作用*部分）可以在没有更多观察者时停止。然而，对于反应，何时停止它们并不总是清楚。例如，何时停止记录或网络请求并不总是清楚。

因此，让我们通过说*计算属性*只是*部分副作用*而不是 MobX 的全面、即时反应来结束这个案例。

# computed()还有更多内容

到目前为止，我们已经看到了`@computed`装饰器与`@computed.struct`的使用，其中结构相等非常重要。当然，`computed`函数还有更多内容，还可以采用多个选项进行精细的定制。在使用`decorate()`函数、`@computed`装饰器或创建*boxed-computed observables*时，这些选项都是可用的。

在下面的片段中，我们看到了在`decorate()`函数中的使用，这更常见：

```jsx
class TodoList {
    @observable.shallow todos = [];
    get pendingTodos() {
        return this.todos.filter(x => x.done === false);
    }

    get completedTodos() {
        return this.todos.filter(x => x.done);
    }

    @action
  addTodo(title) {
        const todo = new Todo(title);
        this.todos.push(todo);
    }
}

decorate(TodoList, {
 pendingTodos: computed({ name: 'pending-todos', /* other options */ }),
});

```

可以将`computed()`的选项作为*对象参数*传递，具有多个属性：

+   `name`：与 MobX DevTools（***mobx-react-devtools*** NPM 包的一部分）结合使用时很有用。在日志中使用此处指定的名称，并且在检查呈现的 React 组件的*observables*时也会使用。

+   `context`：计算函数内部的值*“**this**”*。一般情况下，您不需要指定，因为它将默认为装饰实例。

+   `set`：*计算属性*最常用作*getter*。但是，你也可以提供一个 setter。这不是为了替换计算属性的值，而是作为*反向*。考虑以下示例，其中`fullName`的 setter 将其拆分为`firstName`和`lastName`：

```jsx
class Contact {
    @observable firstName = '';
    @observable lastName = '';

 get fullName() {
 return `${this.firstName} ${this.lastName}`;
 }

}

decorate(Contact, {
    fullName: computed({
        // extract firstName and lastName
 set: function(value) {
 const [firstName, lastName] = value.split(' ');

 this.firstName = firstName;
 this.last = lastName;
 },
    }),
});
```

要在类内部执行相同的操作，而不使用`decorate()`，只需添加一个 setter，如下面的代码所示：

```jsx
class Contact {
    @observable firstName = '';
    @observable lastName = '';

    @computed
  get fullName() {
        return `${this.firstName} ${this.lastName}`;
    }

 set fullName(value) {
 const [firstName, lastName] = value.split(' ');

 this.firstName = firstName;
 this.lastName = lastName;
 }
}

const c = new Contact();

c.firstName = 'Pavan';
c.lastName = 'Podila';

console.log(c.fullName); // Prints: Pavan Podila

c.fullName = 'Michel Weststrate';
console.log(c.firstName, c.lastName); // Prints: Michel Weststrate
```

+   `keepAlive`：有时候你需要一个计算值始终可用，即使没有跟踪观察者。这个选项保持计算值的“热度”并始终更新。但要注意的是，这个选项会始终缓存计算值，可能会导致内存泄漏和昂贵的计算。具有`{ keepAlive: true }`的计算属性的对象只有在所有依赖的观察者都被垃圾回收时才能被垃圾回收。因此，请谨慎使用此选项。

+   `requiresReaction`：这是一个旨在防止*昂贵的计算运行频率超出预期*的属性。默认值设置为`false`，这意味着即使没有观察者（也称为反应），它也会在第一次评估。当设置为`true`时，如果没有观察者，它不会执行计算。相反，它会抛出一个错误，告诉您需要一个观察者。可以通过调用`configure({ computedRequiresReaction: Boolean })`来更改全局行为。

+   `equals`：这设置了计算属性的相等检查器。相等检查确定是否需要发出通知以通知所有观察者（也称为反应）。我们知道，只有当*新计算值*与*先前缓存的值*不同时，才会发出通知。默认值为`comparer.identity`，它执行`===`检查。换句话说，值和引用检查。另一种相等检查是使用`comparer.structural`，它执行值的深度比较以确定它们是否相等。在概念上，它类似于`observable.struct`装饰器。这也是`computed.struct`装饰器使用的比较器：

```jsx
import { observable, computed, decorate, comparer } from 'mobx';

class Contact {
    @observable firstName = '';
    @observable lastName = '';

  get fullName() {
        return `${this.firstName} ${this.lastName}`;
    }

}

decorate(Contact, {
    fullName: computed({
  set: function(value) {
            const [firstName, lastName] = value.split(' ');

            this.firstName = firstName;
            this.last = lastName;
        },
 equals: comparer.identity,
    }),

});
```

# 计算内部的错误处理

计算属性具有在计算过程中捕获错误并从中恢复的特殊能力。它们不会立即退出，而是捕获并保留错误。只有当您尝试从*计算属性*中读取时，它才会重新抛出错误。这使您有机会通过重置一些状态并返回到一些默认状态来恢复。

以下示例直接来自 MobX 文档，并恰当地演示了错误恢复：

```jsx
import { observable, computed } from 'mobx';

const x = observable.box(3);
const y = observable.box(1);

const divided = computed(() => {
    if (y.get() === 0) {
        throw new Error('Division by zero');
    }

    return x.get() / y.get();
});

divided.get(); // returns 3   y.set(0); **// OK**   try {
    divided.get(); // Throws: Division by zero
        } catch (ex) {
    // Recover to a safe state
 y.set(2);
}

divided.get(); // Recovered; Returns 1.5 
```

# 操作

*操作*是改变应用程序核心状态的方式。事实上，MobX 强烈建议您始终使用操作，永远不要在操作之外进行任何变化。如果您使用`configure`配置 MobX 为`{ enforceActions: true }`，它甚至会在整个应用程序中强制执行此要求：

```jsx
import { configure } from 'mobx';

configure({ enforceActions: true });
```

让上述代码行成为您的*MobX 驱动*React 应用程序的起点。显然，对于所有状态变异使用操作有一些好处。但到目前为止，这还不太清楚。让我们深入挖掘一下，揭示这些隐藏的好处。

`configure({ enforceActions: true })`并不是保护状态变异的唯一选项。还有一种更严格的形式，即`{ enforceActions: 'strict' }`。差异微妙但值得注意。当设置为`true`时，仍允许在操作之外进行偶发变异，**如果**没有*观察者*跟踪变异的可观察对象。这可能看起来像是 MobX 的一个疏忽。但是，允许这样做是可以的，因为尚未发生任何副作用，因为没有观察者。这不会对 MobX 反应性系统的一致性造成任何伤害。就像古话说的那样，*如果树倒在森林里，没有人在附近，它会发出声音吗？*也许有点哲学，但要点是：没有观察者，没有人跟踪可观察对象并引起副作用，因此您可以安全地应用变异。

但是，如果您确实想要走纯粹的路线，您可以使用`{ enforceActions: 'strict' }`，即使在没有观察者的情况下也可以进行操作。这真的是个人选择。

# 为什么要使用操作？

当可观察对象发生变化时，MobX 立即发出通知，通知每个观察者发生了变化。因此，如果您改变了 10 个可观察对象，将发送 10 个通知。有时，这只是过多的。您不希望一个过于急切地通知的嘈杂系统。最好将通知批量处理并一次性发送。这样可以节省 CPU 周期，使您移动设备上的电池更加愉快，并且通常会导致一个平衡、更健康的应用程序。

当您将所有的变化放在`action()`中时，这正是`action()`所实现的。它用`untracked()`和`transaction()`包装了变异函数，这两个是 MobX 中的特殊用途的低级实用程序。`untracked()`阻止在变异函数内跟踪可观察对象（也称为创建新的*可观察-观察者*关系）；而`transaction()`批处理通知，强制在同一可观察对象上的通知，然后在***action***结束时发送最小的通知集。

有一个核心实用功能被操作使用，即`allowStateChanges(true)`。这确保状态变化确实发生在可观察对象上，并且它们获得它们的新值。*untracked*、*transaction*和*allowStateChanges*的组合构成了一个动作：

*action = untracked(transaction(allowStateChanges(true, <mutating-function>) ) )*

这种组合具有以下预期效果：

+   减少过多的通知

+   通过批量处理最小的通知来提高效率

+   通过批量处理最小的通知来最小化在*动作*中多次改变的可观察对象的*副作用*执行

事实上，动作可以嵌套在彼此之内，这确保通知只在*最外层动作*执行完成后才发出。

*动作*还有助于展现领域的语义，并使您的应用程序变得更具声明性。通过包装可观察对象如何被改变的细节，您为改变状态的操作赋予了一个*独特的名称*。这强调了您领域的*词汇*，并将其编码为您的*状态管理*的一部分。这是对*领域驱动设计*原则的一种赞同，它将普遍语言（您领域的术语）引入客户端代码。

*动作*有助于弥合领域词汇和实际代码中使用的名称之间的差距。除了效率上的好处，您还可以获得保持代码更可读的语义上的好处。

我们之前在*派生（计算属性）*部分看到，您也可以有设置器。这些设置器会被 MobX 自动包装在`action()`中。计算属性的设置器实际上并不直接改变计算属性。相反，它是改变组成计算属性的依赖可观察对象的逆过程。由于我们正在改变可观察对象，将它们包装在一个动作中是有意义的。MobX 足够聪明，可以为您做到这一点。

# 异步操作

JavaScript 中的异步编程无处不在，MobX 完全拥抱了这个想法，而没有增加太多的仪式感。这里有一个小片段展示了一些异步代码与 MobX 状态变化交织在一起：

```jsx
class ShoppingCart {
    @observable asyncState = '';

    @observable.shallow items = [];

    **@action**
  async submit() {
        this.asyncState = 'pending';
        try {
            const response = **await** this.purchaseItems(this.items);

            this.asyncState = 'completed'; // modified outside of 
            action
        } catch (ex) {
            console.error(ex);
            this.asyncState = 'failed'; // modified outside of action
        }
    }

    purchaseItems(items) {
        /* ... */
  return Promise.resolve({});
    }
}
```

看起来很正常，就像任何其他异步代码一样。这正是重点所在。默认情况下，MobX 简单地让步，让您按预期改变可观察对象。然而，如果您将 MobX 配置为`{ enforceActions: 'strict' }`，您将在控制台上得到一个热烈的**红色**欢迎：

```jsx
Unhandled Rejection (Error): [mobx] Since strict-mode is enabled, changing observed observable values outside actions is not allowed. Please wrap the code in an `action` if this change is intended. Tried to modify: **ShoppingCart@14.asyncState**
```

你可能会问，这里有什么问题？这与我们对`async-await`操作符的使用有关。您看，跟在`await`后面的代码*不会*同步执行。它会在`await`承诺实现之后执行。现在，`action()`装饰器只能保护在其块内同步执行的代码。异步运行的代码不被考虑，因此在`action()`之外运行。因此，跟在`await`后面的代码不再是`action`的一部分，导致 MobX 抱怨。

# 使用 runInAction()进行包装

解决这个问题的方法是使用 MobX 提供的一个实用函数，称为`runInAction()`。这是一个方便的函数，它接受一个*变异函数*并在`action()`内执行它。在下面的代码中，您可以看到使用`runInAction()`来*包装*这些变化：

```jsx
import { action, observable, configure, runInAction } from 'mobx';

configure({ enforceActions: 'strict' });

class ShoppingCart {
    @observable asyncState = '';

    @observable.shallow items = [];

    @action
  async submit() {
        this.asyncState = 'pending';
        try {
            const response = await this.purchaseItems(this.items);

 runInAction(() => {
 this.asyncState = 'completed';
 });
        } catch (ex) {
            console.error(ex);

 runInAction(() => {
 this.asyncState = 'failed';
 });
        }
    }

    purchaseItems(items) {
        /* ... */
  return Promise.resolve({});
    }
}

const cart = new ShoppingCart();

cart.submit();
```

请注意，我们已经在跟在`await`后面的代码中应用了`runInAction()`，无论是在*try 块*还是在*catch 块*中。

`runInAction(fn)`只是一个方便的实用程序，相当于`action(fn)()`。

虽然*async-await*提供了一种美观简洁的语法来编写`async`代码，但要注意那些不是同步的代码部分。`action()`块中代码的共同位置可能会让人产生误解。在运行时，并非所有语句都是同步执行的。跟在`await`后面的代码总是以`async`方式运行，等待的 promise 完成后才会执行。将那些`async`部分用`runInAction()`包装起来，可以让我们重新获得`action()`装饰器的好处。现在，当你配置`({ enforceActions: 'strict' })`时，MobX 不再抱怨了。

# flow()

在之前的简单示例中，我们只需要将代码的两个部分用`runInAction()`包装起来。这是相当直接的，不需要太多的努力。然而，有些情况下你会在一个函数中有多个`await`语句。考虑下面展示的`login()`方法，它执行涉及多个*await*的操作：

```jsx
import { observable, action } from 'mobx';

class AuthStore {
    @observable loginState = '';

    @action.bound
  async login(username, password) {
        this.loginState = 'pending';

        **await** this.initializeEnvironment();

        this.loginState = 'initialized';

        **await** this.serverLogin(username, password);

        this.loginState = 'completed';

        **await** this.sendAnalytics();

        this.loginState = 'reported';
    }

    async initializeEnvironment() {}

    async serverLogin(username, password) {}

    async sendAnalytics() {}
}
```

在每个`await`后用`runInAction()`包装状态变化会很快变得繁琐。如果涉及更多条件或者变化分散在多个函数中，甚至可能会忘记包装一些部分。如果有一种方法可以自动将代码的异步部分包装在`action()`中会怎么样呢？

MobX 也为这种情况提供了解决方案。有一个名为`flow()`的实用函数，它以*生成器函数*作为输入。你可以使用`yield`操作符，而不是`await`。在概念上，它与*async-await*类型的代码非常相似，但是使用*生成器函数*和`yield`语句来实现相同的效果。让我们使用`flow()`实用程序重写前面示例中的代码：

```jsx
import { observable, action, flow, configure } from 'mobx';

configure({ enforceActions: 'strict' });

class AuthStore {
    @observable loginState = '';

    login = flow(function*(username, password) {
        this.loginState = 'pending';

        **yield** this.initializeEnvironment();

        this.loginState = 'initialized';

        **yield** this.serverLogin(username, password);

        this.loginState = 'completed';

        **yield** this.sendAnalytics();

        this.loginState = 'reported';

        **yield** this.delay(3000);
    });

}

new AuthStore().login();
```

注意使用生成器`function*()`而不是传递给`flow()`的常规函数。结构上，它与*async-await*风格的代码没有什么不同，但它有一个额外的好处，就是自动将`yield`后面的代码部分用`action()`包装起来。有了`flow()`，你可以更加声明式地编写异步代码。

`flow()`给你另一个好处。它可以*取消异步代码的执行*。

`flow()`的返回值是一个函数，你可以调用它来执行异步代码。这是前面示例中`AuthStore`的`login`方法。当你调用`new AuthStore().login()`时，你会得到一个由 MobX 增强的带有`cancel()`方法的 promise：

```jsx
const promise = new AuthStore().login2();
promise.cancel(); // prematurely cancel the async code
```

这对于通过给予用户级别的控制来取消长时间运行的操作非常有用。

# 反应

可观察对象和操作使事物保持在 MobX 反应系统的范围内。操作改变可观察对象，并通过通知的力量，MobX 系统的其余部分会调整以保持状态一致。要开始在 MobX 系统之外进行更改，您需要*反应*。它是连接 MobX 世界内部发生的*状态变化*与外部世界的桥梁。

*将反应视为 MobX 和外部世界之间的反应桥梁。这也是您的应用程序的副作用产生者。*

我们知道反应有三种类型：`autorun`，`reaction`和`when`。这三种类型具有不同的特征，可以处理应用程序中的各种情况。

确定选择哪一个时，您可以应用这个简单的决策过程：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00027.jpeg)

每个反应都会返回一个*清除函数*，可以用来提前清除反应，如下所示：

```jsx
import { autorun, reaction, when } from 'mobx';

const disposer1 = autorun(() => {
    /* effect function */ });

const disposer2 = reaction(
    () => {
        /* tracking function returning data */
  },
    data => {
        /* effect function */
  },
);

const disposer3 = when(
    () => {
        /* predicate function */
  },
    predicate => {
        /* effect function */
  },
);

// Dispose pre-maturely
disposer1();
disposer2();
disposer3();
```

回到决策树上的前面图表，我们现在可以定义什么是“长时间运行”：反应在第一次执行后不会自动清除。它会继续存在，直到使用“清除函数”明确清除为止。`autorun()`和`reaction()`属于长时间运行的反应，而`when()`是一次性的。请注意，`when()`也会返回一个“清除函数”，可以提前取消`when()`的效果。然而，“一次性”的行为意味着在效果执行后，`when()`将自动清除自身，无需任何清理。

决策树中涵盖的第二个定义特征是关于*选择要跟踪的可观察对象*。这是执行*效果函数*的保护条件。`reaction()`和`when()`有能力决定要用于跟踪的可观察对象，而`autorun()`隐式选择其*效果函数*中的所有可观察对象。在`reaction()`中，这是*跟踪函数*，而在`when()`中，这是*谓词函数*。这些函数应该产生一个值，当它改变时，*效果函数*就会被执行。

`reaction()`和`when()`的*选择器函数*是可观察跟踪发生的地方。*效果函数*仅用于引起没有跟踪的副作用。`autorun()`隐式地将*选择器函数*和*效果函数*合并为一个函数。

使用决策树，您可以对应用程序中的不同*副作用*进行分类。在第六章中，*处理真实用例*，我们将看一些示例，这将使选择过程更加自然。

# 配置 autorun()和 reaction()

`autorun()`和`reaction()`都提供了一个额外的参数来自定义行为。让我们看看可以作为选项传递的最常见属性。

# autorun()的选项

`autorun()`的第二个参数是一个携带*选项*的对象：

```jsx
autorun(() => { /* side effects */}, options)
```

它具有以下属性：

+   `name`：这对于调试目的非常有用，特别是在 MobX DevTools 的上下文中，其中`name`在日志中打印出来。名称也与 MobX 提供的`spy()`实用程序函数一起使用。这两者将在以后的章节中介绍。

+   `delay`：这充当频繁更改的可观察对象的去抖器。*效果函数*将在`delay`期间（以毫秒为单位指定）等待重新执行。在接下来的示例中，我们要小心，不要在每次更改`profile.couponsUsed`时都发出网络请求。使用`delay`选项是一个简单的防护措施：

```jsx
import { autorun } from 'mobx';

const profile = observable({
    name: 'Pavan Podila',
    id: 123,
    couponsUsed: 3,
});

function sendCouponTrackingAnalytics(id, couponsUsed) {
    /* Make network request */ }

autorun(
    () => {
        sendCouponTrackingAnalytics(profile.id, profile.couponsUsed);
    },
    { delay: 1000 },
);
```

+   `onError`：在*效果函数*执行期间抛出的错误可以通过提供`onError`处理程序来安全处理。错误作为输入提供给`onError`处理程序，然后可以用于恢复，并防止*效果函数*的后续运行出现异常状态。请注意，通过提供此处理程序，MobX 即使在发生错误后也会继续跟踪。这使系统保持运行，并允许其他已安排的*副作用*按预期运行，这些副作用可能是不相关的。

在以下示例中，我们有一个`onError`处理程序，用于处理优惠券数量大于两的情况。通过提供此处理程序，保持`autorun()`的运行，而不会干扰 MobX 反应性系统的其余部分。我们还删除多余的优惠券，以防止再次发生这种情况：

```jsx
autorun(
    () => {
        if (profile.couponsUsed > 2) {
            throw new Error('No more than 2 Coupons allowed');
        }
    },
    {
        onError(ex) {
            console.error(ex);
            removeExcessCoupons(profile.id);
        },
    },
);

function removeExcessCoupons(id) {}
```

# reaction()的选项

与`autorun()`类似，我们可以传递一个额外的参数给`reaction()`，其中包含*选项*：

`*reaction(() => {/* tracking data */}, (data) => { /* side effects */}, options)*`

一些选项如下所示，与*autorun*完全相同，保持一致：

+   `name`

+   `delay`

+   `onError`

但是，特别针对`reaction()`，还有其他选项：

+   `fireImmediately`：这是一个布尔值，指示在*跟踪函数*第一次调用后是否立即触发*效果函数*。请注意，这种行为使我们更接近`autorun()`，它也会立即运行。默认情况下，它被设置为`false`。

+   `equals`：请注意，`reaction()`中的*跟踪函数*返回的`data`将与先前产生的值进行比较。对于原始值，默认的*相等比较*（`comparer.default`）基于值的比较效果很好。但是，您可以自由提供结构比较器（`comparer.structural`）来确保执行更深层次的比较。相等检查很重要，因为只有当值（由*跟踪函数*产生）不同时，*效果函数*才会被调用。

# MobX 何时会做出反应？

MobX 的反应性系统始于*可观察对象*的跟踪或观察。这是构建反应性图的重要方面，因此跟踪正确的可观察对象至关重要。通过遵循一套简单的规则，您可以保证跟踪过程的结果，并确保您的反应正确触发。

我们将使用术语*跟踪函数*来指代以下任何一个：

+   传递给`autorun()`的函数。该函数中使用的可观察对象将被 MobX 跟踪。

+   `reaction()`或`when()`的*选择器函数*（第一个参数）。其中使用的可观察对象也将被跟踪。

+   *observer*-React 组件的`render()`方法。在执行`render()`方法时使用的可观察对象将被跟踪。

# 规则

在以下每条规则中，我们将看一个规则在实际中的例子：

+   在*跟踪函数*的执行过程中始终解引用可观察对象。解引用是建立 MobX 跟踪器的关键。

```jsx
const item = observable({
    name: 'Laptop',
    price: 999,
    quantity: 1,
});

autorun(() => {
 showInfo(item);
});

item.price = 1050;
```

在上面的片段中，由于没有可观察属性被解引用，`autorun()`不会再次被调用。为了让 MobX 对更改做出反应，需要在*跟踪函数*内读取可观察属性。一个可能的修复方法是在`autorun()`内部读取`item.price`，这样每当`item.price`发生变化时就会重新触发：

```jsx
autorun(() => {
    showInfo(item.price);
});
```

+   跟踪仅发生在跟踪函数的同步执行代码中：

+   应该直接在跟踪函数中访问 observable，而不是在异步函数中访问。

+   在以下代码中，MobX 永远不会对`item.quantity`的更改做出反应。尽管我们在`autorun()`中取消引用 observable，但这并不是同步进行的。因此，MobX 永远不会重新执行`autorun()`：

```jsx
autorun(() => {
 setTimeout(() => {
        if (item.quantity > 10) {
            item.price = 899;
        }
    }, 500);
});

item.quantity = 24;
```

要修复，我们可以将代码从`setTimeout()`中取出，并直接放入`autorun()`中。如果使用`setTimeout()`是为了添加一些延迟执行，我们可以使用`autorun()`的`delay`选项来实现。以下代码显示了修复：

```jsx
autorun(
    () => {
        if (item.quantity > 10) {
            item.price = 899;
        }
    },
 { delay: 500 },
);
```

+   只有已经存在的 observable 才会被跟踪：

+   在以下示例中，我们正在取消引用一个 observable（一个计算属性），该属性在`autorun()`执行时并不存在于`item`上。因此，MobX 从不跟踪它。在代码的后面，我们改变了`item.quantity`，导致`item.description`发生变化，但`autorun()`仍然不会执行：

```jsx
autorun(() => {
    console.log(`Item Description: ${item.description}`);
});

extendObservable(item, {
    get description() {
        return `Only ${item.quantity} left at $${item.price}`;
    },
});

item.quantity = 10;
```

一个简单的解决方法是确保在`autorun()`执行之前 observable 实际存在。通过改变语句的顺序，我们可以得到期望的行为，如下面的代码片段所示。在实践中，您应该预先声明所有需要的属性。这有助于 MobX 在需要时正确跟踪属性，有助于类型检查器（例如 TypeScript）确保正确的属性被使用，并且还清楚地表达了代码读者的意图：

```jsx
extendObservable(item, {
 get description() {
 return `Only ${item.quantity} left at $${item.price}`;
 },
});

autorun(() => {
    console.log(`Item Description: ${item.description}`);
});

item.quantity = 10;
```

在修复之前的代码片段中，如果我们在`autorun()`中也读取了`item.quantity`，那么这个*跟踪函数*会在`item.quantity`发生变化时重新执行。这是因为 observable 属性在`autorun()`首次执行时存在。第二次`autorun()`执行（由于`item.quantity`的变化），`item.description`也将可用，MobX 也可以开始跟踪它。

+   前一个规则的一个例外是 Observable Maps，其中还跟踪动态键：

```jsx
const twitterUrls = observable.map({
    John: 'twitter.com/johnny',
});

autorun(() => {
    console.log(twitterUrls.get('Sara'));
});

twitterUrls.set('Sara', 'twitter.com/horsejs');
```

在前面的代码片段中，`autorun()`将重新执行，因为`twitterUrls`是一个`observable.map`，它跟踪新键的添加。因此，即使在`autorun()`执行时它不存在，键`Sara`仍然被跟踪。

在 MobX 5 中，它可以跟踪使用`observable()`API 创建的所有对象的*尚不存在的*属性。

# 总结

MobX 应用的思维模型是针对思考*可观察状态*的。这本身分为*最小核心状态*和*派生状态*。派生是我们如何处理核心状态在 UI 上的各种投影以及需要执行特定于领域的操作的地方。在添加更多核心状态之前，考虑它是否可以作为派生状态进行整合。只有在这种情况下，您才应该引入新的核心状态。

我们看到，*异步操作*与常规*操作*非常相似，没有太多的仪式感。唯一的注意事项是当您配置 MobX 为`enforceActions`时。在这种情况下，您必须在异步代码中的*状态变化*中使用`runInAction()`进行包装。当操作中有几个异步部分时，**`flow()`**是一个更好的选择。它采用一个生成器函数（用`function*(){ }`表示），其中插入了对各种*基于 promise*的调用的`yield`。

`reaction()`和`autorun()`提供了额外的选项来控制它们的行为。它们共享大多数选项，例如*名称*、*延迟*和*onError*。`reaction()`还有两个选项：控制如何对*跟踪函数*产生的数据进行比较（`equals`），以及在*跟踪函数*的第一次运行后是否立即触发*效果函数*（`fireImmediately`）。

在第六章中，*处理真实用例*，我们可以开始探索使用 MobX 解决各种常见情况的方法。如果到目前为止的章节看起来像是*科学*，那么下一章就是*应用科学*！


# 第六章：处理真实用例

当您开始使用 MobX 时，应用 MobX 的原则可能会看起来令人生畏。为了帮助您完成这个过程，我们将解决两个非平凡的使用 MobX 三要素*可观察-操作-反应*的示例。我们将涵盖可观察状态的建模，然后确定跟踪可观察对象的操作和反应。一旦您完成这些示例，您应该能够在使用 MobX 处理状态管理时进行心智转变。

本章我们将涵盖以下示例：

+   表单验证

+   页面路由

# 技术要求

您需要具备 JavaScript 编程语言。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Mobx-Quick-Start-Guide/tree/master/src/Chapter06`](https://github.com/PacktPublishing/Mobx-Quick-Start-Guide/tree/master/src/Chapter06)

查看以下视频，以查看代码的运行情况：

[`bit.ly/2LDliA9`](http://bit.ly/2LDliA9)

# 表单验证

填写表单和验证字段是 Web 的经典用例。因此，我们从这里开始，并看看 MobX 如何帮助我们简化它。在我们的示例中，我们将考虑一个用户注册表单，其中包含一些标准输入，如名字、姓氏、电子邮件和密码。

注册的各种状态如下图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00028.jpeg)

# 交互

从前面的屏幕截图中，我们可以看到一些标准的交互，例如：

+   输入各种字段的输入

+   对这些字段进行验证

+   单击“注册”按钮执行网络操作

这里还有一些其他交互，不会立即引起注意：

+   基于网络的电子邮件验证，以确保我们不会注册已存在的电子邮件地址

+   显示注册操作的进度指示器

许多这些交互将使用 MobX 中的操作和反应进行建模。状态当然将使用可观察对象进行建模。让我们看看在这个示例中 O*bservables-Actions-Reactions*三要素是如何生动起来的。

# 建模可观察状态

示例的视觉设计已经暗示了我们需要的核心状态。这包括`firstName`、`lastName`、`email`和`password`字段。我们可以将这些字段建模为`UserEnrollmentData`类的*可观察属性*。

此外，我们还需要跟踪将发生在电子邮件上的异步验证。我们使用布尔值`validating`属性来实现这一点。在验证过程中发现的任何错误都将使用`errors`进行跟踪。最后，`enrollmentStatus`跟踪了围绕注册的网络操作。它是一个字符串枚举，可以有四个值之一：`none`、`pending`、`completed`或`failed`。

```jsx
class UserEnrollmentData {
    @observable email = '';
    @observable password = '';
    @observable firstName = '';
    @observable lastName = '';
    @observable validating = false;
    @observable.ref errors = null;
    @observable enrollmentStatus = 'none'; // none | pending | completed | failed
}
```

您会注意到`errors`标记为`@observable.ref`，因为它只需要跟踪引用更改。这是因为验证输出是一个*不透明对象*，除了引用更改之外没有任何可观察的东西。只有当`errors`有一个值时，我们才知道有验证错误。

# 进入操作

这里的操作非常简单。我们需要一个操作来根据用户更改*设置字段值*。另一个是在单击 Enroll 按钮时进行*注册*。这两个可以在以下代码中看到。

作为一般惯例，始终从调用`configure({ enforceActions: 'strict' })`开始。这确保您的可观察对象只在操作内部发生突变，为您提供了我们在第五章中讨论的所有好处，*派生、操作和反应*：

```jsx
import { action, configure, flow } from 'mobx';

**configure({ enforceActions: 'strict' });**

class UserEnrollmentData {
    /* ... */

    @action
  setField(field, value) {
        this[field] = value;
    }

    getFields() {
        const { firstName, lastName, password, email } = this;
        return { firstName, lastName, password, email }
    }

    enroll = flow(function*() {
        this.enrollmentStatus = 'pending';
        try {
            // Validation
            const fields = this.getFields();
 yield this.validateFields(fields);
            if (this.errors) {
                throw new Error('Invalid fields');
            }

            // Enrollment
 yield enrollUser(fields);

            this.enrollmentStatus = 'completed';
        } catch (e) {
            this.enrollmentStatus = 'failed';
        }
    });

}
```

对于`enroll`操作使用`flow()`是故意的。我们在内部处理异步操作，因此在操作完成后发生的突变必须包装在`runInAction()`或`action()`中。手动执行这个操作可能很麻烦，也会给代码增加噪音。

使用`flow()`，您可以通过使用带有`yield`语句的生成器函数来获得清晰的代码，用于`promises`。在前面的代码中，我们有两个`yield`点，一个用于`validateFields()`，另一个用于`enroll()`，两者都返回`promises`。请注意，在这些语句之后我们没有包装代码，这样更容易遵循逻辑。

这里隐含的另一个操作是`validateFields()`。验证实际上是一个副作用，每当字段更改时都会触发，但也可以直接作为一个操作调用。在这里，我们再次使用`flow()`来处理异步验证后的突变：

我们使用`validate.js` ([`validatejs.org`](https://validatejs.org)) NPM 包来处理字段验证。

```jsx
**import Validate from 'validate.js';**

class UserEnrollmentData {

    /* ... */

    validateFields = flow(function*(fields) {
        this.validating = true;
        this.errors = null;

        try {
 yield Validate.async(fields, rules);

            this.errors = null;
        } catch (err) {
            this.errors = err;
        } finally {
            this.validating = false;
        }
    });

    /* ... */
}
```

注意`flow()`如何像常规函数一样接受参数（例如：`fields`）。由于电子邮件的验证涉及异步操作，我们将整个验证作为异步操作进行跟踪。我们使用`validating`属性来实现这一点。当操作完成时，我们在`finally`块中将其设置回`false`。

# 用反应完成三角形

当字段发生变化时，我们需要确保输入的值是有效的。因此，验证是输入各个字段的值的副作用。我们知道 MobX 提供了三种处理这种副作用的方法，它们是`autorun()`、`reaction()`和`when()`。由于验证是应该在每次字段更改时执行的效果，一次性效果的`when()`可以被排除。这让我们只剩下了`reaction()`和`autorun()`。通常，表单只会在字段实际更改时进行验证。这意味着效果只需要在更改后触发。

这将我们的选择缩小到`reaction(<tracking-function>, <effect-function>)`，因为这是唯一一种确保`effect`函数在`tracking`函数返回不同值后触发的反应类型。另一方面，`autorun()`立即执行，这对于执行验证来说太早了。有了这个，我们现在可以在`UserEnrollmentData`类中引入*验证*副作用：

从技术上讲，这也可以通过`autorun()`实现，但需要一个额外的布尔标志来确保第一次不执行验证。任何一种解决方案在这种情况下都可以很好地工作。

```jsx
class UserEnrollmentData {

    disposeValidation = null;

    constructor() {
        this.setupValidation();
    }

    setupValidation() {
        this.disposeValidation = reaction(
            () => {
                const { firstName, lastName, password, email } = this;
                return { firstName, lastName, password, email };
            },
            () => {
 this.validateFields(this.getFields());
            },
        );
    }

    /* ... */

 **cleanup**() {
        this.disposeValidation();
    }
}

```

在前述`reaction()`中的`tracking`函数选择要监视的字段。当它们中的任何一个发生变化时，`tracking`函数会产生一个新值，然后触发验证。我们已经看到了`validateFields()`方法，它也是使用`flow()`的动作。`reaction()`设置在`UserEnrollmentData`的构造函数中，因此监视立即开始。

当调用`this.validateFields()`时，它会返回一个`promise`，可以使用其`cancel()`方法提前取消。如果`validateFields()`被频繁调用，先前调用的方法可能仍在进行中。在这种情况下，我们可以`cancel()`先前返回的 promise 以避免不必要的工作。

我们将把这个有趣的用例留给读者来解决。

我们还跟踪`reaction()`返回的`disposer`函数，我们在`cleanup()`中调用它。这是为了清理和避免潜在的内存泄漏，当不再需要`UserEnrollmentData`时。在反应中始终有一个退出点并调用其*disposer*总是很好的。在我们的情况下，我们从根 React 组件中调用`cleanup()`，在其`componentWillUnmount()`挂钩中。我们将在下一节中看到这一点。

现在，验证不是我们示例的唯一副作用。更宏伟的副作用是 React 组件的 UI。

# React 组件

我们知道的 UI 在 MobX 中是一个副作用，并且通过在 React 组件上使用`observer()`装饰器来识别。这些观察者可以在`render()`方法中读取可观察对象，从而设置跟踪。每当这些可观察对象发生变化时，MobX 将重新渲染组件。这种自动行为与最小的仪式非常强大，使我们能够创建对细粒度可观察状态做出反应的细粒度组件。

在我们的示例中，我们确实有一些细粒度的观察者组件，即输入字段、注册按钮和应用程序组件。它们在以下组件树中用橙色框标记：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00029.jpeg)

每个字段输入都分离成一个观察者组件：**InputField**。电子邮件字段有自己的组件**EmailInputField**，因为它的视觉反馈还涉及在验证期间显示进度条并在检查输入的电子邮件是否已注册时禁用它。同样，**EnrollButton**也有一个旋转器来显示注册操作期间的进度。

我们正在使用**Material-UI**（[`material-ui.com`](https://material-ui.com)）作为组件库。这提供了一组优秀的 React 组件，按照 Google 的 Material Design 指南进行了样式设置。

`InputField`只观察它正在渲染的字段，由`field`属性标识，该属性是从`store`属性（使用`store[field]`）解除引用的。这作为`InputField`的`value`：

```jsx
const InputField = observer(({ store, field, label, type }) => {
    const errors = store.errors && store.errors[field];
    const hasError = !!errors;

    return (
        <TextField
  fullWidth
 type={type}  value={store[field]}  label={label}   error={hasError}  onChange={event => store.setField(field, 
            event.target.value)}  margin={'normal'}   helperText={errors ? errors[0] : null}  />
    );
});
```

用户对此输入进行的编辑（`onChange`事件）将通过`store.setField()`操作通知回存储。`InputField`在 React 术语中是一个*受控组件*。

`InputField`组件的关键思想是传递可观察对象（`store`）而不是值（`store[field]`）。这确保了可观察属性的解引用发生在组件的`render()`内部。这对于一个专门用于渲染和跟踪所需内容的细粒度观察者来说非常重要。在创建 MobX 观察者组件时，您可以将其视为*设计模式*。

# UserEnrollmentForm 组件

我们在`UserEnrollmentForm`组件中使用了几个这些`InputFields`。请注意，`UserEnrollmentForm`组件*不是观察者*。它的目的是通过`inject()`装饰器获取存储并将其传递给一些子*观察者组件*。这里的`inject()`使用了*基于函数的*参数，比`inject('store')`的*基于字符串的*参数更安全。

```jsx
import React from 'react';
import { inject  } from 'mobx-react';
import { Grid, TextField, Typography, } from '@material-ui/core';

@inject(stores => ({ store: stores.store }))
class UserEnrollmentForm extends React.Component {
    render() {
        const { store } = this.props;
        return (
            <form>
                <Grid container direction={'column'}>
                    <CenteredGridItem>
                        <Typography variant={'title'}>Enroll 
                        User</Typography>
                    </CenteredGridItem>

                    <CenteredGridItem>
                        <EmailInputField store={store} />
                    </CenteredGridItem>

                    <CenteredGridItem>
                        <**InputField**
  type={'password'}   field={'password'}   label={'Password'}   store={store}  />
                    </CenteredGridItem>

                    <CenteredGridItem>
                        <**InputField**
  type={'text'}   field={'firstName'}   label={'First Name'}   store={store}  />
                    </CenteredGridItem>

                    <CenteredGridItem>
                        <**InputField**
  type={'text'}   field={'lastName'}   label={'Last Name'}   store={store}  />
                    </CenteredGridItem>

                    <CenteredGridItem>
                        <EnrollButton store={store} />
                    </CenteredGridItem>
                </Grid>
            </form>
        );
    }
}
```

`store`，即`UserEnrollmentData`的一个实例，通过在组件树的根部设置的`Provider`组件传递下来。这是在根组件的`constructor`中创建的。

```jsx
import React from 'react';
import { UserEnrollmentData } from './store';
import { Provider } from 'mobx-react';
import { App } from './components';

export class FormValidationExample extends React.Component {
    constructor(props) {
        super(props);

 this.store = new UserEnrollmentData();
    }

    render() {
        return (
 <Provider store={this.store}>
                <App />
            </Provider>
        );
    }

 componentWillUnmount() {
 this.store.cleanup();
 this.store = null;
 }
}
```

通过`Provider`，任何组件现在都可以`inject()` `store`并访问可观察状态。请注意使用`componentWillUnmount()`钩子来调用`this.store.cleanup()`。这在内部处理了验证反应，如前一部分所述（*“使用反应完成三角形”*）。

# 其他观察者组件

在我们的组件树中还有一些更细粒度的观察者。其中最简单的之一是`App`组件，它提供了一个简单的分支逻辑。如果我们仍在注册过程中，将显示`UserEnrollmentForm`。注册后，`App`将显示`EnrollmentComplete`组件。这里跟踪的可观察对象是`store.enrollmentStatus`：

```jsx
@inject('store')
@observer export class App extends React.Component {
    render() {
        const { store } = this.props;
 return store.enrollmentStatus === 'completed' ? (
 <EnrollmentComplete />
 ) : (
 <UserEnrollmentForm />
 );
    }
}
```

`EmailInputField`相当不言自明，并重用了`InputField`组件。它还包括一个进度条来显示异步验证操作：

```jsx
const EmailInputField = observer(({ store }) => {
    const { validating } = store;

    return (
        <Fragment>
            <InputField
  type={'text'}   store={store}   field={'email'}   label={'Email'}  />
            {validating ? <LinearProgress variant={'query'} /> : null}
        </Fragment>
    );
});
```

最后，最后一个观察者组件是`EnrollButton`，它观察`enrollmentStatus`并在`store`上触发`enroll()`动作。在注册过程中，它还显示圆形旋转器：

```jsx
const EnrollButton = observer(({ store }) => {
 const isEnrolling = store.enrollmentStatus === 'pending';
 const failed = store.enrollmentStatus === 'failed';

    return (
        <Fragment>
            <Button
  variant={'raised'}   color={'primary'}   style={{ marginTop: 20 }}   disabled={isEnrolling}   onClick={() => store.enroll()}  >
                Enroll
                {isEnrolling ? (
                    <CircularProgress
  style={{
                            color: 'white',
                            marginLeft: 10,
                        }}   size={20}   variant={'indeterminate'}  />
                ) : null}
            </Button>
            {failed ? (
                <Typography color={'secondary'}  variant={'subheading'}>
                    Failed to enroll
                </Typography>
            ) : null}{' '}
        </Fragment>
    );
});
```

这些细粒度观察者的集合通过加速 React 的协调过程来提高 UI 的效率。由于更改局限于特定组件，React 只需协调该特定观察者组件的虚拟 DOM 更改。MobX 鼓励在组件树中使用这样的细粒度观察者并将它们分散其中。

如果您正在寻找一个专门用于使用 MobX 进行表单验证的库，请查看*mobx-react-form*（[`github.com/foxhound87/mobx-react-form`](https://github.com/foxhound87/mobx-react-form)）。

# 页面路由

**单页应用程序**（**SPA**）已经成为我们今天看到的许多 Web 应用程序中的常见现象。这些应用程序的特点是在单个页面内使用逻辑的客户端路由。您可以通过修改 URL 而无需完整加载页面来导航到应用程序的各个部分（*路由*）。这是由诸如`react-router-dom`之类的库处理的，它与浏览器历史记录一起工作，以实现*URL*驱动的路由更改。

在 MobX 世界中，路由更改或导航可以被视为*副作用*。可观察对象发生了一些状态变化，导致 SPA 中的导航发生。在这个例子中，我们将构建这个可观察状态，它跟踪浏览器中显示的当前页面。使用`react-router-dom`和`history`包的组合，我们将展示如何路由成为可观察状态变化的副作用。

# 购物车结账工作流

让我们看一个用例，我们可以看到路由更改（导航）作为 MobX 驱动的副作用。我们将使用典型的购物车结账工作流作为示例。如下截图所示，我们从*主页路由*开始，这是工作流的入口点。从那里，我们经历剩下的步骤：*查看购物车*，*选择付款选项*，*查看确认*，然后*跟踪订单*：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00030.jpeg)

我们故意保持各个步骤在视觉上简单。这样我们可以更多地关注导航方面，而不是每个步骤内部发生的细节。然而，工作流的这些步骤中有一些*共同的元素*。

如下截图所示，每个步骤都有一个加载操作，用于获取该步骤的详细信息。加载完成后，您可以单击按钮转到下一步。在导航发生之前，会执行一个异步操作。完成后，我们将导航到工作流程的下一步。由于每个步骤都遵循这个模板，我们将在下一节中对其进行建模：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00031.jpeg)

# 建模可观察状态

这个 SPA 的本质是逐步进行结账工作流程，其中每个步骤都是一个路由。由于路由由 URL 驱动，我们需要一种监视 URL 并在步骤之间移动时有能力更改它的方法。步骤之间的导航是可观察状态的某种变化的副作用。我们将使用包含核心可观察状态的`CheckoutWorkflow`类来对这个工作流程进行建模：

```jsx
const routes = {
    shopping: '/',
    cart: '/cart',
    payment: '/payment',
    confirm: '/confirm',
    track: '/track',
};

export class CheckoutWorkflow {
    static steps = [
        { name: 'shopping', stepClass: ShoppingStep },
        { name: 'cart', stepClass: ShowCartStep },
        { name: 'payment', stepClass: PaymentStep },
        { name: 'confirm', stepClass: ConfirmStep },
        { name: 'track', stepClass: TrackStep },
    ];

 tracker = new HistoryTracker();
    nextStepPromise = null;

 @observable currentStep = null;
 @observable.ref step = null;

}
```

如前面的代码所示，我们用`name`和`stepClass`表示每个步骤。`name`也是我们用来识别该步骤对应路由的方式，存储在单例`routes`对象中。`steps`的有序列表存储为`CheckoutWorkflow`类的静态属性。我们也可以从单独的 JavaScript 文件（模块）中加载这些步骤，但为简单起见，我们将其保留在这里。

核心的可观察状态在这里非常简单：一个存储当前步骤的字符串名称的`currentStep`属性和一个`step`属性，作为`observable.ref`属性存储的`stepClass`的实例。当我们在步骤之间导航时，这两个属性会发生变化以反映当前步骤。我们将看到这些属性在处理路由更改时的使用方式。

# 一条路线对应一步，一步对应一条路线

你可能会想为什么我们需要两个单独的属性来跟踪当前步骤。是的，这似乎多余，但有原因。由于我们的工作流将是一组 url 路由，路由的变化也可以通过浏览器的返回按钮或直接输入 URL 来发生。将路由与步骤相关联的一种方法是使用其*名称*，这正是我们在`currentStep`属性中所做的。请注意，步骤的`name`与`routes`对象的键完全匹配。

当路由在外部发生变化时，我们依赖浏览器历史记录来通知我们 URL 的变化。`tracker`属性是`HistoryTracker`的一个实例（我们将创建一个自定义类），其中包含监听*浏览器历史记录*并跟踪浏览器中当前 URL 的逻辑。它公开了一个被`CheckoutWorkflow`跟踪的 observable 属性。我们稍后将在本章中查看它的实现：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00032.jpeg)

`CheckoutWorkflow`中的每个步骤都是`WorkflowStep`类的子类型。`WorkflowStep`捕获了步骤及其异步操作的详细信息。工作流简单地编排步骤的流程，并在每个步骤的异步操作完成后在它们之间进行转换：

```jsx
class ShowCartStep extends WorkflowStep { /* ... */}

// A mock step to simplify the representation of other steps
class MockWorkflowStep extends WorkflowStep { /* ... */ }

class PaymentStep extends MockWorkflowStep { /* ... */ }
class ConfirmStep extends MockWorkflowStep { /* ... */ }
class TrackStep extends MockWorkflowStep { /* ... */ }
```

对于大多数步骤，我们正在扩展`MockWorkflowStep`，它使用一些内置的默认值来创建一个模板`WorkflowStep`。这使得步骤非常简单，因此我们可以专注于步骤之间的路由。请注意下面的代码片段，我们只是模拟了`load`和`main`操作的网络延迟。`delay()`函数只是一个简单的帮助函数，返回一个在给定毫秒间隔后解析的`Promise`。

我们将在下一节中看到`getLoadOperation()`和`getMainOperation()`方法是如何使用的：

```jsx
class MockWorkflowStep extends WorkflowStep {
    getLoadOperation() {
        return delay(1000);
    }

    getMainOperation() {
        return delay(1000);
    }
}

function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
```

# WorkflowStep

`WorkflowStep`充当了工作流中所有步骤的模板。它包含一些 observable 状态，用于跟踪它执行的两个异步操作：*加载详情*和*执行主要工作*。

```jsx
class WorkflowStep {
    workflow = null; // the parent workflow
 @observable loadState = 'none'; // pending | completed | failed
  @observable operationState = 'none'; // pending | completed | 
     failed    async getLoadOperation() {}
    async getMainOperation() {}

    @action.bound
 async load() {
        doAsync(
            () => this.getLoadOperation(),
            state => (this.loadState = state),
        );
    }

    @action.bound
 async perform() {
        doAsync(
            () => this.getMainOperation(),
            state => (this.operationState = state),
        );
    }
}
```

`load()`和`perform()`是`WorkflowStep`执行的两个异步操作。它们的状态分别通过`loadState`和`operationState` observables 进行跟踪。这两个操作中的每一个都调用一个委托方法，子类重写该方法以提供实际的 promise。`load()`调用`getLoadOperation()`，`perform()`调用`getMainOperation()`，每个方法都会产生一个 promise。

`doAsync()`是一个帮助函数，它接受一个*promise 函数*并使用传入的回调(`setState`)通知状态。请注意这里使用`runInAction()`来确保所有变化发生在一个 action 内部。

`load()`和`perform()`使用`doAsync()`函数适当地更新`loadState`和`operationState` observables：

有一种不同的编写`doAsync()`函数的方法。**提示**：我们在早期的章节中已经看到过。我们将把这留给读者作为一个练习。

```jsx
async function doAsync(getPromise, setState) {
 setState('pending');
    try {
        await getPromise();
        runInAction(() => {
 setState('completed');
        });
    } catch (e) {
        runInAction(() => {
 setState('failed');
        });
    }
}
```

现在我们可以看到可观察状态由`CheckoutWorkflow`和`WorkflowStep`实例承载。可能不清楚的一点是`CheckoutWorkflow`如何执行协调。为此，我们必须看一下动作和反应。

# 工作流的动作和反应

我们已经看到`WorkflowStep`有两个***action***方法，`load()`和`perform()`，处理步骤的异步操作：

```jsx
class WorkflowStep {
    workflow = null;
    @observable loadState = 'none'; // pending | completed | failed
  @observable operationState = 'none'; // pending | completed | 
     failed    async getLoadOperation() {}
    async getMainOperation() {}

    @action.bound
 async load() {
        doAsync(
            () => this.getLoadOperation(),
            state => (this.loadState = state),
        );
    }

    @action.bound
 async perform() {
        doAsync(
            () => this.getMainOperation(),
            state => (this.operationState = state),
        );
    }
}
```

`load()`操作由`CheckoutWorkflow`调用，因为它加载工作流的每个步骤。`perform()`是用户调用的操作，当用户点击暴露在 React 组件上的按钮时发生。一旦`perform()`完成，`operationState`将变为`completed`。`CheckoutWorkflow`跟踪这一点，并自动加载序列中的下一个步骤。换句话说，工作流作为对当前步骤的`operationState`变化的反应（或副作用）而进展。让我们在以下一组代码片段中看到所有这些：

```jsx
export class CheckoutWorkflow {
    /* ... */

    tracker = new HistoryTracker();
    nextStepPromise = null;

    @observable currentStep = null;
    @observable.ref step = null;

    constructor() {
        this.tracker.startListening(routes);

 this.currentStep = this.tracker.page;

 autorun(() => {
            const currentStep = this.currentStep;

            const stepIndex = CheckoutWorkflow.steps.findIndex(
                x => x.name === currentStep,
            );

            if (stepIndex !== -1) {
                this.loadStep(stepIndex);

                this.tracker.page = CheckoutWorkflow.steps[stepIndex].name;
            }
        });

 reaction(
            () => this.tracker.page,
            page => {
                this.currentStep = page;
            },
        );
    }

    @action
  async loadStep(stepIndex) {
        /* ... */
    }
}
```

`CheckoutWorkflow`的构造函数设置了核心副作用。我们需要知道的第一件事是浏览器使用`this.tracker.page`提供的当前页面。请记住，我们正在将工作流的`currentStep`与使用共享名称的基于 URL 的路由相关联。

第一个副作用使用`autorun()`执行，我们知道它立即运行，然后在跟踪的可观察对象发生变化时运行。在`autorun()`内部，我们首先确保加载`currentStep`是有效的步骤。由于我们在`autorun()`内部观察`currentStep`，我们必须确保我们保持`this.tracker.page`同步。成功加载当前步骤后，我们这样做。现在，每当`currentStep`发生变化时，`tracker.page`会自动同步，这意味着 URL 和路由会更新以反映当前步骤。稍后我们将看到，`tracker`，即`HistoryTracker`的实例，实际上是如何在内部处理这一点的。

下一个副作用是对`tracker.page`的变化的`reaction()`。这是对先前副作用的对应部分。每当`tracker.page`发生变化时，我们也必须改变`currentStep`。毕竟，这两个可观察对象必须协同工作。因为我们已经通过一个单独的副作用（`autorun()`）来跟踪`currentStep`，当前的`step`加载了`WorkflowStep`的实例。

这里引人注目的一点是，当`currentStep`改变时，`tracker.page`会更新。同样，当`tracker.page`改变时，`currentStep`也会更新。因此，可能会出现一个无限循环：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00033.jpeg)

然而，MobX 会发现一旦变化在一个方向上传播，另一方向就不会发生更新，因为两者是同步的。这意味着这两个相互依赖的值很快就会达到稳定状态，不会出现无限循环。

# 加载步骤

`WorkflowStep`是步骤变得活跃的地方，唯一能创建实例的是`CheckoutWorkflow`。毕竟，它是整个工作流的所有者。它在`loadStep()`动作方法中执行此操作：

```jsx
export class CheckoutWorkflow {
    /* ... */

    @action
  async loadStep(stepIndex) {
        if (this.nextStepPromise) {
            this.nextStepPromise.cancel();
        }

        const StepClass = CheckoutWorkflow.steps[stepIndex].stepClass;
        this.step = new StepClass();
        this.step.workflow = this;
        this.step.load();
        this.nextStepPromise = when(
            () => this.step.operationState === 'completed',
        );

        await this.nextStepPromise;

        const nextStepIndex = stepIndex + 1;
        if (nextStepIndex >= CheckoutWorkflow.steps.length) {
            return;
        }

        this.currentStep = CheckoutWorkflow.steps[nextStepIndex].name;
    }
}
```

上述代码的有趣部分概述如下：

+   我们通过从步骤列表中检索当前步骤索引的`stepClass`来获得当前步骤索引的`stepClass`。我们创建了这个`stepClass`的实例，并将其分配给可观察的`step`属性。

+   然后触发`WorkflowStep`的`load()`。

+   可能最有趣的部分是等待`step`的`operationState`改变。我们从前面知道，`operationState`跟踪步骤的主要异步操作的状态。一旦它变为`completed`，我们就知道是时候转到下一步了。

+   注意使用带有 promise 的`when()`。这为我们提供了一个很好的方法来标记需要在`when()`解析后执行的代码。还要注意，我们在`nextStepPromise`属性中跟踪 promise。这是为了确保在当前步骤完成之前，我们也要`cancel`掉 promise。值得思考这种情况可能会出现的时候。**提示**：步骤的流程并不总是线性的。步骤也可以通过*路由更改*来更改，比如通过单击浏览器的返回按钮！

# 历史跟踪器

*observable state puzzle*的最后一部分是`HistoryTracker`，这是一个专门用于监视浏览器 URL 和历史记录的类。它依赖于`history` NPM 包（[`github.com/ReactTraining/history`](https://github.com/ReactTraining/history)）来完成大部分工作。*history*包还为我们的 React 组件提供动力，我们将使用`react-router-dom`库。

`HistoryTracker`的核心责任是公开一个名为`page`的 observable，用于跟踪浏览器中的当前 URL（路由）。它还会反向操作，使 URL 与当前`page`保持同步：

```jsx
import createHashHistory from 'history/createHashHistory';
import { observable, action, reaction } from 'mobx';

export class HistoryTracker {
    unsubscribe = null;
    history = createHashHistory();

    @observable page = null;

    constructor() {
        reaction(
            () => this.page,
            page => {
                const route = this.routes[page];
                if (route) {
                    this.history.push(route);
                }
            },
        );
    }

    /* ... */
}
```

在构造函数中设置了`reaction()`，路由更改（URL 更改）实际上是`page` observable 变化的副作用。这是通过将路由（URL）推送到浏览器历史记录中实现的。

`HistoryTracker`的另一个重要方面，正如其名称所示，是跟踪浏览器历史记录。这是通过`startListening()`方法完成的，可以由此类的消费者调用。`CheckoutWorkflow`在其构造函数中调用此方法来设置跟踪器。请注意，`startListening()`接收一个路由映射，其中`key`指向 URL 路径：

```jsx
export class HistoryTracker {
    unsubscribe = null;
    history = createHashHistory();

    @observable page = null;

    startListening(routes) {
        this.routes = routes;
        this.unsubscribe = this.history.listen(location => {
            this.identifyRoute(location);
        });

        this.identifyRoute(this.history.location);
    }

    stopListening() {
        this.unsubscribe && this.unsubscribe();
    }

    @action
  setPage(key) {
        if (!this.routes[key]) {
            throw new Error(`Invalid Page: ${key}`);
        }

        this.page = key;
    }

    @action
  identifyRoute(location) {
        const { pathname } = location;
        const routes = this.routes;

        this.page = Object.keys(routes).find(key => {
            const path = routes[key];
            return path.startsWith(pathname);
        });
    }
}
```

当浏览器中的 URL 更改时，`page` observable 会相应地更新。这发生在`identifyRoute()`方法中，该方法从`history.listen()`的回调中调用。我们已经用 action 修饰它，因为它会*改变*`page` observable。在内部，MobX 会通知所有`page`的观察者，例如`CheckoutWorkflow`，它使用`page` observable 来更新其`currentStep`。这保持了整个路由同步，并确保更改是双向的。

以下图表显示了`currentStep`、`page`和*url-route*之间的双向同步。请注意，与`history`包的交互显示为*灰色*箭头，而 observable 之间的依赖关系显示为橙色箭头。这种颜色上的差异是有意的，并表明*基于 url 的路由*实际上是 observable 状态变化的副作用：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00034.jpeg)

# React 组件

在这个例子中，observable 状态的建模比 React UI 组件更有趣。在 React 方面，我们有设置`Provider`的顶层组件，其中`store`是`CheckoutWorkflow`的实例。`Provider`来自`mobx-react`包，并帮助将`store`注入到任何使用`inject()`装饰的 React 组件中：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import { Provider } from 'mobx-react';
import { CheckoutWorkflow } from './CheckoutWorkflow';

const workflow = new CheckoutWorkflow();

export function PageRoutingExample() {
    return (
        <Provider store={workflow}>
            <App />
        </Provider>
    );
}
```

`App`组件只是使用`react-router-dom`包设置所有路由。在`<Route />`组件中使用的路径与我们在`routes`对象中看到的 URL 匹配。请注意，`HistoryTracker`中的`history`用于`Router`。这允许在*react-router*和*mobx*之间共享浏览器历史记录：

```jsx
import React from 'react';
import ReactDOM from 'react-dom';
import { Route, Router, Switch } from 'react-router-dom';
import { CheckoutWorkflow } from './CheckoutWorkflow';
import { Paper } from '@material-ui/core/es/index';
import { ShowCart } from './show-cart';
import {
    ConfirmDescription,
    PaymentDescription,
    ShoppingDescription,
    TemplateStepComponent,
    TrackOrderDescription,
} from './shared';

const workflow = new CheckoutWorkflow();

class App extends React.Component {
    render() {
        return (
            <Paper elevation={2}  style={{ padding: 20 }}>
                <Router history={workflow.tracker.history}>
                    <Switch>
                        <**Route**
  exact
 path={'/'}   component={() => (
                                <TemplateStepComponent
  title={'MobX Shop'}   renderDescription=
                                   {ShoppingDescription}   operationTitle={'View Cart'}  />
                            )}  />
                        <Route exact path={'/cart'}  component=
                            {ShowCart} />
                        <**Route**
  exact
 path={'/payment'}   component={() => (
                                <TemplateStepComponent
  title={'Choose Payment'}   renderDescription=
                                    {PaymentDescription}   operationTitle={'Confirm'}  />
                            )}  />
                        <**Route**
  exact
 path={'/confirm'}   component={() => (
                                <TemplateStepComponent
  title={'Your order is confirmed'}   operationTitle={'Track Order'}   renderDescription=
                                     {ConfirmDescription}  />
                            )}  />
                        <**Route**
  exact
 path={'/track'}   component={() => (
                                <TemplateStepComponent
  title={'Track your order'}   operationTitle={'Continue 
                                      Shopping'}   renderDescription=
                                     {TrackOrderDescription}  />
                            )}  />
                    </Switch>
                </Router>
            </Paper>
        );
    }
}
```

如前所述，我们故意保持了工作流程的各个步骤非常简单。它们都遵循固定的模板，由`WorkflowStep`描述。它的 React 对应物是`TemplateStepComponent`，它呈现步骤并公开按钮，用于导航到下一步。

# TemplateStepComponent

`TemplateStepComponent`为`WorkflowStep`提供了可视化表示。当步骤正在加载时，它会呈现反馈，当主要操作正在执行时也是如此。此外，它会在加载后显示步骤的详细信息。这些细节通过`renderDetails`属性显示，该属性接受一个 React 组件：

```jsx
@inject('store')
export class TemplateStepComponent extends React.Component {
    static defaultProps = {
        title: 'Step Title',
        operationTitle: 'Operation',
        renderDetails: step => 'Some Description', // A render-prop to render details of a step
    };

    render() {
        const { title, operationTitle, renderDetails } = this.props;

        return (
            <Fragment>
                <Typography
  variant={'headline'}   style={{ textAlign: 'center' }}  >
                    {title}
                </Typography>

 <Observer>
 {() => {
 const { step } = this.props.store;

 return (
 <OperationStatus
  state={step.loadState}   render={() => (
 <div style={{ padding: '2rem 0' }}>
 {renderDetails(step)}
 </div>
 )}  />
 );
 }}
 </Observer>

                <Grid justify={'center'}  container>
 <Observer>
                        {() => {
                            const { step } = this.props.store;

                            return (
                                <Button
  variant={'raised'}   color={'primary'}   disabled={step.operationState === 
 'pending'}   onClick={step.perform}>
                                    {operationTitle}
                                    {step.operationState === 'pending'                           
                                         ? (
                                        <CircularProgress
  variant={'indeterminate'}   size={20}   style={{
                                                color: 'black',
                                                marginLeft: 10,
                                            }}  />
                                    ) : null}
                                </Button>
                            );
                        }}
 </Observer>
                </Grid>
            </Fragment>
        );
    }
}
```

`Observer`组件是我们以前没有见过的东西。这是由`mobx-react`包提供的一个特殊组件，简化了粒度观察者的创建。典型的 MobX 观察者组件将要求您创建一个单独的组件，用`observer()`和/或`inject()`装饰它，并确保适当的可观察对象作为 props 传递到该组件中。您可以通过简单地用`<Observer />`包装*虚拟 DOM*的一部分来绕过所有这些仪式。

它接受一个函数作为它唯一的子元素，在其中您可以从周围范围读取可观察对象。MobX 将自动跟踪*函数作为子组件*中使用的可观察对象。仔细观察`Observer`会揭示这些细节：

```jsx
<Observer>
    {() => {
 const { step } = this.props.store;

        return (
            <OperationStatus
  state={step.loadState}   render={() => (
                    <div style={{ padding: '2rem 0' }}>
                        {renderDetails(step)}
                    </div>
                )}  />
        );
    }}
</Observer>
```

在上面的片段中，我们将一个函数作为`<Observer />`的子元素传递。在该函数中，我们使用`step.loadState`可观察对象。当`step.loadState`发生变化时，MobX 会自动呈现*函数作为子组件*。请注意，我们没有将任何 props 传递给`Observer`或子组件。它直接从外部组件的 props 中读取。这是使用`Observer`的优势。您可以轻松创建匿名观察者。

一个微妙的要点是`TemplateStepComponent`本身不是一个观察者。它只是用`inject()`获取`store`，然后在`<Observer />`区域内使用它。

# ShowCart 组件

`ShowCart`是显示购物车中物品列表的组件。在这里，我们正在重用`TemplateStepComponent`和购物车的插件细节，使用`renderDetails`属性。这可以在以下代码中看到。为简单起见，我们不显示`CartItem`和`TotalItem`组件。它们是纯粹的呈现组件，用于呈现单个购物车项目：

```jsx
import React from 'react';
import {
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Typography,
} from '@material-ui/core';
import { Divider } from '@material-ui/core/es/index';
import { TemplateStepComponent } from './shared';

export class ShowCart extends React.Component {
    render() {
        return (
            <**TemplateStepComponent**
  title={'Your Cart'}   operationTitle={'Checkout'}  renderDetails={step => {
 const { items, itemTotal } = step;

 return (
 <List>
 {items.map(item => (
 <CartItem key={item.title}  item={item} />
 ))}

 <Divider />

 <TotalItem total={itemTotal} />
 </List>
 );
 }} />
        );
    }
}

function CartItem({ item }) {
    return (
        /* ... */
    );
}

function TotalItem({ total }) {
    return (
        /* ... */
    );
}
```

# 基于状态的路由器

现在您可以看到，所有`WorkflowStep`实例之间的路由纯粹是通过基于状态的方法实现的。所有导航逻辑都在 MobX 存储中，这种情况下是`CheckoutWorkflow`。通过连接可观察对象（`tracker.page`，`currentStep`和`step`）通过一系列反应，我们创建了更新浏览器历史的*副作用*，并创建了`WorkflowStep`的实例，这些实例由`TemplateStepComponent`使用。

由于我们在`react-router-dom`和 MobX 之间共享浏览器历史（通过`HistoryTracker`），我们可以使可观察对象与 URL 更改保持同步。

这种基于状态的路由方法有助于保持清晰的工作流心智模型。您的功能的所有逻辑都留在 MobX Store 中，提高了可读性。为这种基于状态的解决方案编写单元测试也很简单。事实上，在 MobX 应用程序中，大多数单元测试都围绕存储和反应中心。许多 React 组件成为可观察对象的纯粹观察者，并且可以被视为普通的演示组件。

使用 MobX，您可以专注于领域逻辑，并确保 UI 上有适当的可观察状态。通过将所有领域逻辑和状态封装在存储中，并将所有演示内容放在 React 组件中，可以清晰地分离关注点。这极大地改善了开发者体验（DX），并有助于随着时间的推移更好地扩展。这是 MobX 的真正承诺。

要了解更丰富功能的基于状态的路由解决方案，请查看`mobx-state-router`（[`github.com/nareshbhatia/mobx-state-router`](https://github.com/nareshbhatia/mobx-state-router)）。

# 摘要

在本章中，我们应用了我们在过去几章中学到的各种技术和概念。两个示例，表单验证和页面路由，分别提出了一套建模可观察状态的独特方法。我们还看到了如何创建细粒度的观察者组件，以实现 React 组件的高效渲染。

MobX 的实际应用始终以建模*可观察状态*为起点。毕竟，这就是驱动 UI 的数据。下一步是确定改变可观察状态的*动作*。最后，您需要调用*副作用*，并查看这些效果依赖于哪些可观察状态。这就是应用于现实场景的副作用模型，以 MobX 三元组的形式呈现：*可观察状态-动作-反应*。

根据我们迄今积累的所有知识，我们现在准备深入了解 MobX，从第七章开始，*特殊情况的特殊 API*。


# 第七章：特殊情况的特殊 API

MobX 的 API 表面非常简洁，为处理状态管理逻辑提供了正确的抽象。在大多数情况下，我们已经看到的 API 将足够。然而，总会有一些棘手的边缘情况需要略微偏离常规。正是为了这些特殊情况，MobX 为您提供了一些特殊的 API。我们将在本章中看到其中一些。

本章我们将涵盖以下主题：

+   使用对象 API 进行直接操作

+   使用`inject()`和`observe()`来连接到内部 MobX 事件系统。

+   将有助于调试的特殊实用函数和工具

+   快速提及一些杂项 API

# 技术要求

您需要具备 JavaScript 编程语言。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Mobx-Quick-Start-Guide/tree/master/src/Chapter07`](https://github.com/PacktPublishing/Mobx-Quick-Start-Guide/tree/master/src/Chapter07)

查看以下视频，以查看代码的运行情况：

[`bit.ly/2A1Or6V`](http://bit.ly/2A1Or6V)

# 使用对象 API 进行直接操作

在决定可观察状态的数据结构时，您的自然选择应该是使用`observable.object()`、`observable.array()`、`observable.map()`、`observable.box()`，或者使用方便的`observable()`API。操作这些数据结构就像直接改变属性或根据需要添加和删除元素一样简单。

MobX 为您提供了另一种对数据结构进行手术式更改的方法。它公开了一个细粒度的对象 API，可以在运行时改变这些数据结构。事实上，它为您提供了一些原始数据结构甚至不可能的功能。例如，向可观察对象添加新属性，并保持其响应性。

# 细粒度读取和写入

对象 API 专注于对顶层数据结构（对象、数组和映射）的可观察属性进行细粒度控制。通过这样做，它们继续与 MobX 的响应式系统良好地配合，并确保您所做的细粒度更改被*reactions*捕获。以下 API 适用于可观察的对象/数组/映射：

+   `get(thing, key)`: 检索键下的值。这个键甚至可以不存在。当在反应中使用时，当该键变为可用时，它将触发重新执行。

+   `set(thing, key, value)` 或 `set(thing, { key: value })`: 为键设置一个值。第二种形式更适合一次设置多个*键-值*对。在概念上，它与`Object.assign()`非常相似，但增加了响应性。

+   `has(thing, key)`: 返回一个布尔值，指示键是否存在。

+   `remove(thing, key)`: 删除给定的键及其值。

+   `values(thing)`: 给出一个值数组。

+   `keys(thing)`: 返回包含所有键的数组。请注意，这仅适用于可观察对象和映射。

+   `entries(thing)`: 返回一个键值对数组，其中每对是两个元素的数组（`[key, value]`）。

以下代码片段练习了所有这些 API：

```jsx
import {
    autorun,
    observable,
 set,
 get,
 has,
    toJS,
    runInAction,
 remove,
 values,
 entries,
 keys,
} from 'mobx';

class Todo {
    @observable description = '';
    @observable done = false;

    constructor(description) {
        this.description = description;
    }
}

const firstTodo = new Todo('Write Chapter');
const todos = observable.array([firstTodo]);
const todosMap = observable.map({
    'Write Chapter': firstTodo,
});

// Reactions to track changes autorun(() => {
 console.log(`metadata present: ${has(firstTodo, 'metadata')}`);
 console.log(get(firstTodo, 'metadata'), get(firstTodo, 'user'));
 console.log(keys(firstTodo));
});
autorun(() => {
    // Arrays
 const secondTodo = get(todos, 1);
 console.log('Second Todo:', toJS(secondTodo));
 console.log(values(todos), entries(todos));
});

// Granular changes runInAction(() => {
 set(firstTodo, 'metadata', 'new Metadata');
 set(firstTodo, { metadata: 'meta update', user: 'Pavan Podila' });
 set(todos, 1, new Todo('Get it reviewed'));
});

runInAction(() => {
 remove(firstTodo, 'metadata');
 remove(todos, 1);
});
```

通过使用这些 API，您可以针对可观察对象的特定属性并根据需要进行更新。使用对象 API 读取和写入*不存在*的键被认为是有效的。请注意，我们在`autorun()`中读取`firstTodo`的`metadata`属性，这在调用时并不存在。然而，由于使用了`get()`API，MobX 仍然跟踪这个键。当我们在操作中稍后`set()`了`metadata`时，`autorun()`会重新触发以在控制台上打印出它。

这可以在以下控制台输出中看到。请注意，当移除时，`metadata`检查从`false`变为`true`，然后再变回`false`： 

```jsx
metadata present: false undefined undefined (2) ["description", "done"] Second Todo: undefined  [Todo] [Array(2)]    metadata present: true meta update Pavan Podila (4) ["description", "done", "metadata", "user"] Second Todo: {description: "Get it reviewed", done: false}  (2) [Todo, Todo] (2) [Array(2), Array(2)]    metadata present: false undefined "Pavan Podila" (3) ["description", "done", "user"] Second Todo: undefined  [Todo] [Array(2)] 
```

# 从 MobX 到 JavaScript

所有的可观察类型都是由 MobX 创建的特殊类，它们不仅存储数据，还有一堆用来跟踪变化的杂事。我们将在后面的章节中探讨这些杂事，但就我们现在的讨论而言，这些 MobX 类型并不总是与其他第三方 API 兼容，特别是在使用 MobX 4 时。

当与外部库进行接口时，您可能需要发送原始的 JavaScript 值，而不是 MobX 类型的值。这就是您需要`toJS()`函数的地方。它将 MobX 可观察对象转换为原始的 JavaScript 值：

`toJS(source, options?)`

`source`: 任何可观察的盒子、对象、数组、映射或基元。

`options`: 一个可选参数，用于控制行为，例如：

+   `exportMapsAsObject` (*boolean*): 是否将可观察的映射序列化为对象（当为`true`时）或 JavaScript 映射（当为`false`时）。默认为`true`。

+   `detectCycles` (*boolean*): 默认设置为`true`。它在序列化过程中检测循环引用，并重用已经序列化的对象。在大多数情况下，这是一个很好的默认设置，但出于性能原因，当你确定没有循环引用时，可以将其设置为`false`。

`toJS()`的一个重要注意点是它不会序列化*computed properties*。这是有道理的，因为它纯粹是可以随时重新计算的派生信息。`toJS()`的目的是仅序列化核心 observable 状态。同样，observable 的任何不可枚举属性都不会被序列化，也不会递归到任何非 observable 的数据结构中。

在下面的例子中，你可以看到`toJS()` API 是如何应用于 observables 的：

```jsx
const number = observable.box(10);
const cart = observable({
    items: [{ title: 'milk', quantity: 2 }, { title: 'eggs', quantity: 3 }],
});

console.log(toJS(number));

console.log('MobX type:', cart);
console.log('JS type:', toJS(cart));
```

控制台输出显示了在应用`toJS()` API 之前和之后的`cart` observable。

```jsx
10 **MobX type: Proxy {Symbol(mobx administration): ObservableObjectAdministration$$1}** **JS type: {items: Array(2)}** 
```

# 观察事件流动

我们在前几章中看到的 API 允许你创建 observables 并通过*reactions*对变化做出反应。MobX 还提供了一种方法来连接到内部流动的事件，使得响应式系统能够工作。通过将监听器附加到这些事件，你可以微调一些昂贵资源的使用或控制允许应用于 observables 的更新。

# 连接到可观察性

通常，*reactions*是我们读取*observables*并应用一些副作用的地方。这告诉 MobX 开始跟踪 observable 并在变化时重新触发 reaction。然而，如果我们从 observable 的*角度*来看，它如何知道它何时被 reaction 使用？它如何在被 reaction 读取时进行一次性设置，并在不再被使用时进行清理？

我们需要的是能够知道何时 observable 变为*observed*和何时变为*unobserved*：它在 MobX 响应式系统中变为活动和非活动的两个时间点。为此，我们有以下恰如其名的 APIs：

+   `disposer = onBecomeObserved(observable, property?: string, listener: () => void)`

+   `disposer = onBecomeUnobserved(observable, property?: string, listener: () => void)`

`observable`：可以是一个包装的 observable，一个 observable 对象/数组/映射。

`property:` 可观察对象的可选属性。指定属性与直接引用属性有根本的不同。例如，`onBecomeObserved(cart, 'totalPrice', () => {})`与`onBecomeObserved(cart.totalPrice, () => {})`是不同的。在第一种情况下，MobX 将能够跟踪可观察属性，但在第二种情况下，它不会，因为它只接收值而不是属性。事实上，MobX 将抛出一个`Error`，指示在`cart.totalPrice`的情况下没有东西可跟踪：

```jsx
Error: [mobx] Cannot obtain atom from 0 
```

前面的错误现在可能没有太多意义，特别是原子一词。我们将在第九章 *Mobx Internals*中更详细地了解原子。

`disposer`: 这些处理程序的返回值。这是一个函数，可用于处理这些处理程序并清理事件连接。

以下代码片段展示了这些 API 的使用：

```jsx
import {
    onBecomeObserved,
    onBecomeUnobserved,
    observable,
    autorun,
} from 'mobx';

const obj = observable.box(10);
const cart = observable({
    items: [],
    totalPrice: 0,
});

onBecomeObserved(obj, () => {
 console.log('Started observing obj');
});

onBecomeUnobserved(obj, () => {
 console.log('Stopped observing obj');
});

onBecomeObserved(cart, 'totalPrice', () => {
 console.log('Started observing cart.totalPrice');
});
onBecomeUnobserved(cart, 'totalPrice', () => {
 console.log('Stopped observing cart.totalPrice');
});

const disposer = autorun(() => {
    console.log(obj.get(), `Cart total: ${cart.totalPrice}`);
});
setTimeout(disposer);

obj.set(20);
cart.totalPrice = 100;
```

在前面的代码片段中，当`autorun()`第一次执行时，`onBecomeObserved()`处理程序将被调用。调用`disposer`函数后，将调用`onBecomeUnobserved()`处理程序。这可以在以下控制台输出中看到：

```jsx
Started observing obj Started observing cart.totalPrice 10 "Cart total: 0" 20 "Cart total: 0" 20 "Cart total: 100" Stopped observing cart.totalPrice Stopped observing obj 
```

`onBecomeObserved()`和`onBecomeUnobserved()`是延迟设置（和清除）可观察对象的绝佳钩子，可以在首次使用（和最后一次使用）时进行。这在某些情况下非常有用，例如可能需要执行昂贵的操作来设置可观察对象的初始值。此类操作可以通过推迟执行，直到实际上某处使用它时才执行。

# 延迟加载温度

让我们举一个例子，我们将延迟加载城市的*温度*，但只有在访问时才加载。这可以通过使用`onBecomeObserved()`和`onBecomeUnobserved()`的钩子对可观察属性进行建模来实现。以下代码片段展示了这一点：

```jsx
// A mock service to simulate a network call to a weather API const temperatureService = {
    fetch(location) {
        console.log('Invoked temperature-fetch');

        return new Promise(resolve =>
            setTimeout(resolve(Math.round(Math.random() * 35)), 200),
        );
    },
};

class City {
 @observable temperature;
    @observable location;

    interval;
    disposers;

    constructor(location) {
        this.location = location;
 const disposer1 = onBecomeObserved(
 this,
 'temperature',
 this.onActivated,
 );
 const disposer2 = onBecomeUnobserved(
 this,
 'temperature',
 this.onDeactivated,
 );

        this.disposers = [disposer1, disposer2];
    }

    onActivated = () => {
        this.interval = setInterval(() => this.fetchTemperature(), 5000);
        console.log('Temperature activated');
    };

    onDeactivated = () => {
        console.log('Temperature deactivated');
        this.temperature = undefined;
        clearInterval(this.interval);
    };

    fetchTemperature = flow(function*() {
        this.temperature = yield temperatureService.fetch(this.location);
    });

    cleanup() {
        this.disposers.forEach(disposer => disposer());
        this.disposers = undefined;
    }
}

const city = new City('Bengaluru');
const disposer = autorun(() =>
    console.log(`Temperature in ${city.location} is ${city.temperature}ºC`),
);

setTimeout(disposer, 15000);  
```

前面的控制台输出显示了`temperature`可观察对象的激活和停用。它在`autorun()`中被激活，15 秒后被*停用*。我们在`onBecomeObserved()`处理程序中启动定时器来不断更新*温度*，并在`onBecomeUnobserved()`处理程序中清除它。*定时器*是我们管理的资源，只有在访问`temperature`之后才会创建，而不是之前：

```jsx
Temperature activated Temperature in Bengaluru is undefinedºC   Invoked temperature-fetch Temperature in Bengaluru is 22ºC Invoked temperature-fetch Temperature in Bengaluru is 32ºC Invoked temperature-fetch Temperature in Bengaluru is 4ºC   Temperature deactivated
```

# 变化的守门人

您对 observable 所做的更改不会立即应用于 MobX。相反，它们经过一层拦截器，这些拦截器有能力保留变化、修改变化，甚至完全丢弃变化。这一切都可以通过`intercept()`API 实现。签名与`onBecomeObserved`和`onBecomeUnobserved`非常相似，回调函数（*interceptor*）给出了 change 对象：

`disposer = intercept(observable, property?, interceptor: (change) => change | null )`

`observable`：一个封装的 observable 或 observable 对象/数组/映射。

`property`：要拦截的 observable 的可选字符串名称。就像我们之前在`onBecomeObserved`和`onBecomeUnobserved`中看到的那样，对于`intercept(cart, 'totalPrice', (change) => {})`和`intercept(cart.totalPrice, () => {})`有所不同。对于后者（`cart.totalPrice`），您拦截的是一个值而不是 observable 属性。MobX 将抛出错误，指出您未传递正确的类型。

`interceptor`：一个回调函数，接收 change 对象并期望返回最终的变化；原样应用、修改或丢弃（`null`）。在拦截器中抛出错误也是有效的，以通知异常更新。

`disposer`：返回一个函数，当调用时将取消此拦截器。这与我们在`onBecomeObserved()`、`onBecomeUnobserved()`以及`autorun()`、`reaction()`和`when()`中看到的非常相似。

# 拦截变化

接收到的 change 参数具有一些已知字段，提供了详细信息。其中最重要的是`type`字段，它告诉您*变化的类型*，以及`object`，它给出了*发生变化的对象*。根据`type`，一些其他字段为变化添加了更多的上下文：

+   `type`：可以是 add、delete 或 update 之一

+   `object`：一个封装的 observable 或 observable 对象/数组/映射实例

+   `newValue`：当类型为 add 或 update 时，此字段包含新值

+   `oldValue`：当类型为 delete 或 update 时，此字段携带先前的值

在拦截器回调中，您有机会最终确定您实际想要应用的变化类型。您可以执行以下操作之一：

+   返回 null 并丢弃变化

+   使用不同的值进行更新

+   抛出指示异常值的错误

+   原样返回并应用变化

让我们举一个拦截主题更改并确保只应用有效更新的示例。在下面的片段中，您可以看到我们如何拦截主题可观察对象的`color`属性。颜色可以是*light*或*dark*，也可以是`l`或`d`的简写值。对于任何其他值，我们会抛出错误。我们还防止取消颜色的设置，通过返回`null`并丢弃更改：

```jsx
import { intercept, observable } from 'mobx';

const theme = observable({
    color: 'light',
    shades: [],
});

const disposer = intercept(theme, 'color', change => {
    console.log('Intercepting:', change);

    // Cannot unset value, so discard this change
  if (!change.newValue) {
        return **null**;
    }

    // Handle shorthand values
  const newTheme = change.newValue.toLowerCase();
    if (newTheme === 'l' || newTheme === 'd') {
        change.newValue = newTheme === 'l' ? 'light' : 'dark'; // set 
         the correct value
  return change;
    }

    // check for a valid theme
  const allowedThemes = ['light', 'dark'];
    const isAllowed = allowedThemes.includes(newTheme);
    if (!isAllowed) {
        **throw** new Error(`${change.newValue} is not a valid theme`);
    }

    return change; // Correct value so return as-is });
```

# 观察()变化

作为`intercept()`对应的实用程序是`observe()`。正如其名称所示，`observe()`允许您对可观察对象进行细粒度观察：

`observe(observable, property?, observer: (change) => {})`

签名与`intercept()`完全相同，但行为完全不同。`observe()`在可观察对象被应用更改后被调用。

一个有趣的特点是`observe()`对*事务*是免疫的。这意味着*观察者回调*会在突变后立即被调用，而不是等到事务完成。正如您所知，*actions*是发生突变的地方。MobX 通过触发它们来优化通知，但只有在顶层*action*完成后才会触发。使用`observe()`，您可以在突变发生时获得未经过滤的视图。

建议在感觉需要`observe()`时使用`autorun()`。仅在您认为需要立即通知突变时使用它。

以下示例显示了在突变可观察对象时您可以观察到的各种细节。正如您所看到的，`change`参数与`intercept()`完全相同：

```jsx
import { observe, observable } from 'mobx';

const theme = observable({
    color: 'light',
    shades: [],
});

const disposer = observe(theme, 'color', change => {
    console.log(
        `Observing ${change.type}`,
        change.oldValue,
        '-->',
        change.newValue,
        'on',
        change.object,
    );
});

theme.color = 'dark';
```

# 开发工具

随着应用程序功能的增加，了解 MobX 反应系统的使用方式和时间变得必不可少。MobX 配备了一组调试工具，帮助您监视和跟踪其中发生的各种活动。这些工具为您提供了系统内所有可观察变化、操作和反应的实时视图。

# 使用 spy()跟踪反应性

之前，我们看到了`observe()`函数，它允许您对单个可观察对象发生的变化进行*"观察"*。但是，如果您想观察跨所有可观察对象发生的变化，而不必单独设置`observe()`处理程序，该怎么办？这就是`spy()`发挥作用的地方。它让您了解系统中各种可观察对象随时间变化的情况：

`disposer = spy(listener: (event) => { })`

它接受一个*监听函数*，该函数接收携带所有细节的事件对象。*事件*具有与`observe()`处理程序非常相似的属性。有一个`type`字段告诉您事件的类型。类型可以是以下之一：

+   **update**：对于对象、数组、映射

+   **add**：对于对象、数组、映射

+   **delete**：对于映射

+   **create**：对于包装的可观察对象

+   **action**：当动作触发时

+   **reaction**：在执行`autorun()`、`reaction()`或`when()`时

+   **compute**：对于计算属性

+   **error**：在操作或反应内捕获任何异常的情况下

这是一小段设置`spy()`并将输出打印到控制台的代码片段。我们还将在五秒后取消此间谍：

```jsx
import { spy } from 'mobx';

const disposer = spy(event => console.log(event));

setTimeout(disposer, 5000);
```

```jsx
// Console output
{type: "action", name: "<unnamed action>", object: undefined, arguments: Array(0), **spyReportStart**: true} {type: "update", object: BookSearchStore, oldValue: 0, name: "BookSearchStore@1", newValue: 2179, …} {**spyReportEnd**: true} {object: Proxy, type: "splice", index: 0, removed: Array(0), added: Array(20), …} {spyReportEnd: true} {type: "update", object: BookSearchStore, oldValue: Proxy, name: "BookSearchStore@1", newValue: Proxy, …} {spyReportEnd: true} {type: "update", object: BookSearchStore, oldValue: "pending", name: "BookSearchStore@1", newValue: "completed", …} 
```

一些间谍事件可能伴随着`spyReportStart`或`spyReportEnd`属性。这些标记了一组相关的事件。

在开发过程中直接使用`spy()`可能不是最佳选择。最好依赖于可视化调试器（在下一节中讨论），它利用`spy()`来为您提供更可读的日志。请注意，当您将`NODE_ENV`环境变量设置为*"production"*时，对`spy()`的调用在生产构建中将是*无操作*。

# 跟踪反应

虽然`spy()`可以让您观察 MobX 中发生的所有更改，但`trace()`是一个专门针对计算属性、反应和组件渲染的实用程序。您可以通过简单地在其中放置一个`trace()`语句来找出为什么会调用*计算属性*、*反应*或*组件渲染*：

`trace(thing?, property?, enterDebugger?)`

它有三个*可选*参数：

+   `thing`：一个可观察对象

+   `property`：一个可观察属性

+   `enterDebugger`：一个布尔标志，指示您是否希望自动步入调试器

通常会使用`trace(true)`来调用跟踪，这将在调用时暂停在调试器内。对于书搜索示例（来自第三章，*使用 MobX 的 React 应用*），我们可以直接在`SearchTextField`组件的`render()`内放置一个跟踪语句：

```jsx
import { trace } from 'mobx';

@inject('store')
@observer export class SearchTextField extends React.Component {
    render() {
        trace(true);

        /* ... */
    }

}
```

当调试器暂停时，您将获得为什么执行了此计算属性、反应或渲染的完整根本原因分析。在 Chrome 开发工具中，您可以看到这些细节如下：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/mobx-qk-st-gd/img/00035.jpeg)Chrome 开发工具上的详细信息

# 使用 mobx-react-devtools 进行可视化调试

`spy()`和`trace()`非常适合深入了解 MobX 响应式系统的代码级别。然而，在开始分析性能改进时，可视化调试非常方便。MobX 有一个名为`mobx-react-devtools`的姊妹 NPM 包，它提供了一个简单的`<DevTools />`组件，可以帮助您可视化组件树如何对可观察对象做出反应。通过在应用程序顶部包含此组件，您将在运行时看到一个工具栏：

```jsx
import DevTools from 'mobx-react-devtools';
import React from 'react';

export class MobXBookApp extends React.Component {
    render() {
        return (
            <Fragment>
 <DevTools />
                <RootAppComponent />
            </Fragment>
        );
    }
}
```

下面的屏幕截图显示了 MobX DevTools 工具栏出现在屏幕的*右上角*！[](../images/00036.jpeg)

通过启用按钮，您可以看到哪些组件在可观察值发生变化时进行渲染，查看连接到 DOM 元素的可观察值的依赖树，并在*操作*/*反应*执行时打印控制台日志。组件在渲染时会闪烁一个彩色矩形。矩形的颜色表示渲染所需的时间，*绿色*表示最快，*红色*表示最慢。您可以观察闪烁的矩形，以确保只有您打算更改的部分重新渲染。这是识别不必要渲染的组件并可能创建更精细的观察者的好方法。

`mobx-react-devtools`包依赖于`spy()`来打印执行操作和反应的控制台日志。

# 其他一些 API

MobX 提供了一些不太常用的杂项 API。为了完整起见，这里还是值得一提的。

# 查询响应式系统

在处理 MobX 中的各种抽象（可观察值、操作、反应）时，有时需要知道某个对象、函数或值是否属于某种类型。MobX 有一组*isXXX* API，可以帮助您确定值的类型：

+   `isObservableObject(thing)`, `isObservableArray(thing)`, `isObservableMap(thing)`: 告诉你传入的值是否是可观察的对象、数组或映射

+   `isObservable(thing)`和`isObservableProp(thing, property?)`：类似于前面的点，但更一般化地检查可观察值

+   `isBoxedObservable(thing)`: 值是否是一个包装的可观察值

+   `isAction(func)`: 如果函数被操作包装，则返回`true`

+   `isComputed(thing)`和`isComputedProp(thing, property?)`：检查值是否是计算属性

# 深入了解响应式系统

MobX 在内部构建了一个反应性的结构，保持所有的可观察对象和反应都连接在一起。我们将在第九章 *Mobx Internals*中探索这些内部结构，那里我们将看到某些术语的提及，比如*atoms*。现在，让我们快速看一下这些 API，它们为您提供了可观察对象和反应的内部表示。

+   `getAtom(thing, property?)`：在每个可观察对象的核心是一个`Atom`，它跟踪依赖于可观察值的观察者。它的目的是在任何人读取或写入可观察值时报告。通过此 API，您可以获取支持可观察对象的`Atom`的实例。

+   `getDependencyTree(thing, property?)`：这为您提供了给定对象依赖的依赖树。它可用于获取计算属性或反应的依赖关系。

+   `getObserverTree(thing, property?)`：这是`getDependencyTree()`的对应物，它为您提供了依赖于给定对象的观察者。

# 摘要

尽管 MobX 有一个精简的外层 API，但也有一组 API 用于更精细的观察和变化。我们看到了如何使用 Object API 来对可观察树进行非常精确的更改。通过`observe()`和`intercept()`，您可以跟踪可观察对象中发生的更改，并拦截以修改更改。

`spy()`和`trace()`在调试期间是您的朋友，并与***mobx-react-devtools***配合使用，您可以获得一个用于识别和改进渲染性能的可视化调试器。这些工具和实用程序为您提供了丰富的开发人员体验（DX），在使用 MobX 时非常有用。

在第八章 *探索 mobx-utils 和 mobx-state-tree*中，我们将提高使用 MobX 与特殊包`mobx-utils`和`mobx-state-tree`的水平。
