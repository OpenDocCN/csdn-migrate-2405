# React 设计模式实用指南（三）

> 原文：[`zh.annas-archive.org/md5/44C916494039D4C1655C3E1D660CD940`](https://zh.annas-archive.org/md5/44C916494039D4C1655C3E1D660CD940)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：JavaScript 和 ECMAScript 模式

在本章中，我们将回到 JavaScript 语言的核心。这里的一些模式可以在许多不同的语言中重复使用，例如 Java、C++ 和 Python。用这样强大的东西填充您的工具箱是至关重要的。这一次，我们将在 JavaScript 中实现众所周知的设计模式，并看看我们如何从中受益，特别是在 React Native 环境中。作为一个小补充，我们将学习一个名为 Ramda 的新库，它以其出色的功能而闻名，可以帮助我们编写更短、更简洁的代码。您还将了解函数式编程的基础知识，这将是下一章的主题。

在本章中，您将学习以下内容：

+   选择器模式

+   柯里化模式

+   Ramda 库

+   函数式编程基础

# JavaScript 和函数式编程

函数式编程基本上意味着以某种方式使用函数来编写逻辑代码。大多数语言允许函数变得非常复杂和难以理解。然而，函数式编程对函数施加了约束，以便能够组合它们并在数学上证明它们的行为。

其中一个约束是规范与外部世界的通信（例如，副作用，如数据获取）。有人断言，无论我们用相同的参数调用函数多少次，它都会返回完全相同的值。所有这些约束都将给我们带来一定的好处。您已经可以列举一些这些好处，比如时间旅行，它使用纯减速器。

在本章中，我们将学习一些有用的函数，这将使我们更容易进入第九章，*函数式编程模式的要素*。我们还将更详细地阐述确切的约束及其好处。

# ES6 的 map、filter 和 reduce

本节旨在刷新我们对 `map`、`filter` 和 `reduce` 函数的了解。

通常，常见的语言函数需要非常高的性能，这是一个超出本书范围的话题。避免重新实现语言中已有的功能。本章中的一些示例仅用于学习目的。

`reduce` 很可能经常被忽视，因此我们将重点关注它。通常，`reduce`（顾名思义）用于将集合的大小减小到更小的集合，甚至是单个变量。

以下是 reduce 函数的声明：

```jsx
reduce(callback, [initialValue])
```

回调函数接受四个参数：`previousValue`、`currentValue`、`index`和`array`。

为了快速提醒一下`reduce`函数的工作原理，让我们看下面的例子：

```jsx
const sumArrayElements = arr => arr.reduce((acc, elem) => acc+elem, 0);
console.log(sumArrayElements([5,15,20])); // 40
```

`reduce`在集合上进行迭代。在每一步，它调用函数来处理它所在的元素迭代器。然后它记住函数的输出并传递给下一个元素。这个记住的输出是第一个函数参数；在前面的例子中，它是累加器（`acc`）变量。它记住了先前运行函数的结果，应用`reducer`函数并传递到下一步。这与 Redux 库在状态上的操作非常相似。

`reduce`函数的第二个参数是累加器的初始值；在前面的例子中，我们从零开始。

让我们提高难度，使用`reduce`来实现一个`average`函数：

```jsx
const numbers = [1, 2, 5, 7, 13]; const average = numbers.reduce(
    (accumulator, currNumber, indexOfElProcessed, arrayWeWorkOn) => {
        // Sum all numbers so far
        const newAcc = accumulator + currNumber;
  if (indexOfElProcessed === arrayWeWorkOn.length - 1) {
            // if this is the last item, return average
            return newAcc / arrayWeWorkOn.length;
  }
        // if not the last item, pass sum
        return newAcc;
  },
  0 ); // average equals 5.6
```

在这个例子中，我们在`if`语句中做了一个小技巧。如果元素是数组中的最后一个元素，那么我们想要计算`average`而不是`sum`。

# 使用 reduce 重新实现 filter 和 map

现在是一个小挑战的时候了。你知道吗，你可以使用`reduce`来实现`map`和`filter`两个函数吗？

在我们开始之前，让我们快速回顾一下`filter`函数的工作原理：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/aaeb5354-b0a9-4851-9e2e-bcb46f67903b.png)

过滤函数在集合上的工作原理

假设我们有一个`task`集合，想要筛选出`type`等于`1`的任务，如下所示：

```jsx
const onlyType1 = task => task.type === 1
```

使用标准的 filter 函数，你只需要写下面的代码：

```jsx
tasks.filter(onlyType1)
```

但是现在，想象一下如果没有`filter`函数，到目前为止，你的工具箱中只有`reduce`。

你可以这样做：

```jsx
tasks.reduce((acc,t) => onlyType1(t) ? [...acc, t] :acc, [])
```

技巧是将累加器变成一个集合。前一个值始终是一个集合，从空数组开始。一步一步地，我们要么将任务添加到累加器中，要么如果任务未能通过筛选，则简单地返回累加器。

那么如何实现`map`函数呢？`map`只是通过应用传递给它的映射函数，将每个元素转换为一个新元素：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/4406e918-8437-4cda-beed-c5d8c4f71a4f.png)

映射函数在集合上的工作原理

让我们使用`reduce`来做，如下所示：

```jsx
const someFunc = x => x+1; const tab = [1, 5, 9, 13]; tab.reduce((acc, elem) => [...acc, someFunc(elem)], []);
// result: [2, 6, 10, 14]
```

在这个例子中，我们只是再次将每个项目收集到相同的集合中，但在将其添加到数组之前，我们对其应用了一个映射函数。在这个例子中，映射函数被定义为`someFunc`。

# 在数组中计算项目数量

我们的下一个例子是关于计算数组中的项数。假设你有一个房屋物品的数组。你需要计算你拥有的每种物品的数量。使用`reduce`函数，预期的结果是一个具有物品作为键和特定物品计数作为值的对象，如下所示：

```jsx
const items = ['fork', 'laptop', 'fork', 'chair', 'bed', 'knife', 'chair']; items.reduce((acc, elem) => ({ ...acc, [elem]: (acc[elem] || 0) + 1 }), {});
// {fork: 2, laptop: 1, chair: 2, bed: 1, knife: 1} 
```

这很棘手：`(acc[elem] || 0)`部分意味着我们要么取`acc[elem]`的值，如果它被定义了，要么取`0`。这样，我们就可以检查其种类的第一个元素。另外，`{ [elem]: something }`是用来定义一个以存储在`elem`变量中的名称为键的语法。

前面的例子在你处理来自外部 API 的序列化数据时很有帮助。有时你需要对其进行转换以进行缓存，以避免不必要的重新渲染。

下一个例子介绍了一个新词—**展开**。当我们展开一个集合时，意味着它是一个嵌套在集合中的集合，我们希望将其变平。

例如，一个集合，比如`[[1, 2, 3], [4, 5, 6], [7, 8, 9]]`在展开后变成了`[1, 2, 3, 4, 5, 6, 7, 8, 9]`。这是通过以下方式完成的：

```jsx
const numCollections = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]; numCollections.reduce((acc, collection) => [...acc, ...collection], []);
// result:[1, 2, 3, 4, 5, 6, 7, 8, 9] 
```

这个例子对于理解我们将在第九章，*函数式编程模式的元素*中使用的更复杂的例子中的展开是至关重要的。

# 迭代器模式

在前面的部分中，我们遍历了许多不同的集合，甚至是嵌套的集合。现在，是时候更多地了解迭代器模式了。如果你打算使用 Redux Saga 库，这种模式尤其闪耀。

如果你直接跳到这一章，我强烈建议你阅读介绍迭代器模式的部分第六章，*数据传输模式*。该章还涵盖了 Redux Saga 库和生成器。

总结一下，在 JavaScript 中，迭代器是一个知道如何逐个遍历集合项的对象。它必须公开`next()`函数，该函数返回集合的下一个项。集合可以是任何想要的东西。它甚至可以是一个无限集合，比如斐波那契数列，就像这里看到的那样：

```jsx
class FibonacciIterator {
    constructor() {
        this.n1 = 1;
  this.n2 = 1;
  }
    next() {
        var current = this.n2;
  this.n2 = this.n1;
  this.n1 = this.n1 + current;
  return current;
  }
}
```

在你使用这个之前，你需要创建一个类的实例：

```jsx
const fibNums = new FibonacciIterator(); fibNums.next(); // 1 fibNums.next(); // 1 fibNums.next(); // 2 fibNums.next(); // 3 fibNums.next(); // 5 
```

这可能很快变得无聊，因为它看起来像一个学术例子。但它并不是。它很有用，可以向你展示我们将使用闭包和`Symbol`迭代器重新创建的算法。

# 定义一个自定义迭代器

快速回顾一下 JavaScript 中的符号：`CallingSymbol()`返回一个唯一的符号值。符号值应该被视为一个 ID，例如，作为一个在对象中用作键的 ID。

要为集合定义一个迭代器，您需要指定特殊的键`Symbol.iterator`。如果定义了这样一个符号，我们说这个集合是可迭代的。看下面的例子：

```jsx
// Array is iterable by default,
// we don't need to create a custom iterator,
// just use the one that is present.
const alpha = ['a','b','c']; const it = alpha[Symbol.iterator]()**;**   it.next(); //{ value: 'a', done: false } it.next(); //{ value: 'b', done: false } it.next(); //{ value: 'c', done: false } it.next(); //{ value: undefined, done: true }
```

现在让我们为斐波那契数列创建一个自定义的`iterator`。斐波那契数列的特点是每个数字都是前两个数字的和（序列的开头是 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, ...）：

```jsx
const fib = {
    [Symbol.iterator]() {
        let n1 = 1;
  let n2 = 1;    return {
            next() {
                const current = n2;
  n2 = n1;
  n1 += current;
  return { value: current, done: false };
  },    return(val) { // this part handles loop break
                // Fibonacci sequence stopped.
  return { value: val, done: true };
  }
        };
  }
};
```

为了轻松遍历可迭代的集合，我们可以使用方便的`for...of`循环：

```jsx
for (const num of fib) {
    console.log(num);
    if (num > 70) break; // We do not want to iterate forever
}
```

# 使用生成器作为迭代器的工厂

我们还需要知道如何使用生成器（例如，对于 Redux Saga），所以我们应该熟练地编写它们。事实证明它们可以像迭代器的工厂一样工作，我们已经学会了如何使用迭代器。

关于生成器的快速回顾——它们是带有`*`和`yield`操作符的函数，比如，`function* minGenExample() { yield "a"; }`。这样的函数执行直到遇到`yield`关键字。然后，函数返回`yield`值。函数可以有多个`yield`，在第一次调用时返回`Generator`。这样的生成器是可迭代的。看下面的例子：

```jsx
const a = function* gen() { yield "a"; }; console.log(a.prototype)
// Generator {}
```

现在我们可以利用这个知识重新实现斐波那契数列作为一个生成器：

```jsx
function* fib() {
    let n1 = 1;
  let n2 = 1;
  while (true) {
        const current = n2;
  n2 = n1;
  n1 += current;    yield current;   }
}
// Pay attention to invocation of fib to get Generator
for (const num of fib()) {
    console.log(num);
  if (num > 70) break; }
```

就是这样。我们使用生成器函数语法来简化自己的事情。生成器函数就像迭代器的工厂。一旦调用，它将为您提供一个新的生成器，您可以像任何其他集合一样对其进行迭代。

处理斐波那契数的代码可以简化。我能写的最简洁的方式如下：

`function* fib() {`

`  let n1 = 1, n2 = 1;`

`  while (true) {`

`    yield n1;`

`    [n1, n2] = [n2, n1 + n2];`

`  }`

`}`

# 使用生成器调用 API 以获取任务详情

我们已经尝试过生成器，并成功使用它们获取了任务。现在，我们将重复这个过程，但目标略有不同：获取单个任务的数据。为了实现这一点，我对代码进行了一些修改，并准备了代码的部分，让你只关注生成器：

```jsx
// src/Chapter 8/Example 1/src/features/tasks/sagas/fetchTask.js
// ^ fully functional example with TaskDetails page
export **function*** fetchTask(action) {
    const task = yield call(apiFetch, `tasks/${action.payload.taskId}`);
  if (task.error) {
        yield put(ActionCreators.fetchTaskError(task.error));
  } else {
        const json = yield call([task.response, 'json']);
  yield put(ActionCreators.fetchTaskComplete(json));
  }
}
```

这个生成器首先处理 API 调用。端点是使用分派的动作的有效负载计算出来的。为了方便起见，使用了字符串模板。然后，根据结果，我们要么分派成功动作，要么分派错误动作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/3c663de8-7432-4a98-8402-c20e521ee25e.png)

这是任务详细信息屏幕的示例。请随意处理样式。

请注意生成器中的许多`yield`。每次`yield`都会停止函数执行。在我们的例子中，执行会在完成的`call`效果上恢复。然后，我们可以继续，知道调用的结果。

但为什么我们要停下来呢？有没有这样的用例？首先，它比简单的承诺和异步/等待更强大（在下一节中将会更多介绍）。其次，停下来等待某些事情发生是很方便的。例如，想象一下，我们想等到创建三个任务后才显示祝贺消息，就像这样：

```jsx
function* watchFirstThreeTasksCreation() {
    for (let i = 0; i < 3; i++) {
        const action = yield take(TasksActionTypes.ADD_TASK)
    }
    yield put({type: 'SHOW__THREE_TASKS_CONGRATULATION'})
}
```

这个例子仅用于游乐场目的。请注意任务创建计数器在生成器函数内。因此，它不会保存在任何后端系统中。在应用程序刷新时，计数器将重置。如果您为应用程序构建任何奖励系统，请考虑这些问题。

# 生成器的替代方案

JavaScript 中多年来一直存在的一个流行的替代方案是承诺。承诺使用了与生成器非常相似的概念。语法糖允许您等待承诺。如果您想要这种语法糖，那么您的函数需要是`async`的。您看到了任何相似之处吗？是的，我愿意说承诺是生成器的一个不太强大的变体。

如果您使用承诺，请看一下名为**`for await of`**的新循环。您可能会发现它很方便。另一个值得检查的功能是**异步迭代器**。

# 选择器

在上一节中，我们再次处理了异步数据。这些数据已被推送到应用程序的 Redux 存储中。我们在`mapStateToProps`函数中多次访问它，例如，在任务列表容器中：

```jsx
const mapStateToProps = state => ({
    tasks: state.tasks.get('entities'),
  isLoading: state.tasks.get('isLoading'),
  hasError: state.tasks.get('hasError'),
  errorMsg: state.tasks.get('errorMsg')
});
```

这个看起来并不是很丑陋，但对于任务详细页面来说，它已经有些失控了。考虑以下内容：

```jsx
// On this page we don't know if tasks are already fetched
const mapStateToProps = (state, ownProps) => ({
    task: state.tasks
  ? state.tasks
  .get('entities')
            .find(task => task.id === ownProps.taskId)
        : null }); 
```

我们进行了许多检查和转换。这个流程在每次重新渲染时都会发生。如果数据没有改变，我们是否可以记住计算结果？是的，我们可以——缓存选择器来拯救我们。

# 从 Redux 存储中选择

面对现实吧，到目前为止我们还没有对访问存储进行任何抽象。这意味着每个`mapStateToProps`函数都是单独访问它的。如果存储结构发生变化，所有`mapStateToProps`函数都可能受到影响。第一步是分离关注点，并提供选择器，而不是直接对象访问：

```jsx
// src/Chapter 8/Example 1/src/features/
//                         ./tasks/containers/TaskListContainer.js
const mapStateToProps = state => ({
    tasks: tasksEntitiesSelector(state),
  isLoading: tasksIsLoadingSelector(state),
  hasError: tasksHasErrorSelector(state),
  errorMsg: tasksErrorMsgSelector(state)
}); 
```

实现与之前完全相同，唯一的例外是我们可以在许多地方重用代码：

```jsx
// src/Chapter 8/Example 2/src/features/
//                      ./tasks/state/selectors/tasks.js  export const tasksSelector = state => state.tasks;   export const tasksEntitiesSelector = state =>
 (tasksSelector(state) ? tasksSelector(state).get('entities') : null);   export const tasksIsLoadingSelector = state =>
 (tasksSelector(state) ? tasksSelector(state).get('isLoading') : null);   export const tasksHasErrorSelector = state =>
 (tasksSelector(state) ? tasksSelector(state).get('hasError') : null);   export const tasksErrorMsgSelector = state =>
 (tasksSelector(state) ? tasksSelector(state).get('errorMsg') : null);

// PS: I have refactored the rest of the app to selectors too. 
```

即使在这个小例子中，我们在每个其他选择器中两次访问`tasksSelector`。如果`tasksSelector`很昂贵，那将会非常低效。然而，现在我们将通过缓存选择器来保护自己免受这种情况的影响。

# 缓存选择器

为了缓存选择器，我们将使用**memoization**函数。这样的函数一旦函数的输入引用发生变化就会重新计算值。为了节省时间，我们将使用一个流行的库来为我们实现这个 memoization 函数。这个库叫做`reselect`。在`reselect`中，引用变化是通过强相等性（**===**）来检查的，但如果需要，你可以更改相等函数。使用以下命令添加这个库：

```jsx
yarn add reselect
```

有了这个，我们就准备好缓存了：

```jsx
// src/Chapter 8/Example 2/src/features/
//                                ./tasks/state/selectors/tasks.js
import { createSelector } from 'reselect';   export const tasksSelector = state => state.tasks;   export const tasksEntitiesSelector = createSelector(
    tasksSelector,
  tasks => (tasks ? tasks.get('entities') : null)
); 
// ... rest of the selectors in similar fashion
```

# 从 Ramda 库学习函数

映射，过滤，减少，迭代器，生成器和选择器。不算太多，对吧？不要太害怕，你能用只有 10 个单词的英语说话吗？不行？好吧，那么我们可以继续学习一些新的单词，这些单词将使我们在 JavaScript 编程中更加流利。

# 组合函数

高阶组件（HOCs）最广告的特性之一是它们的可组合性。例如，`withLogger`，`withAnalytics`和`withRouter` HOCs，我们可以以以下方式组合它们：

```jsx
**withLogger**(**withAnalytics**(**withRouter**(SomeComponent))) 
```

Ramda 库将可组合性提升到了一个新的水平。不幸的是，我发现许多开发人员几乎不理解它。让我们看一个等价的例子：

```jsx
R.compose(withLogger,withAnalytics, withRouter)(SomeComponent)
```

大多数人对 Ramda `compose`的难点在于理解它的工作原理。它通常从右到左应用函数，这意味着它首先评估`withRouter`，然后将结果转发给`withAnalytics`，依此类推。函数的最重要的一点是，只有第一个函数（`withRouter`）可以有多个参数。每个后续函数都需要在前一个函数的结果上操作。

Ramda `compose`函数从右到左组合函数。要从左到右组合函数，可以使用 Ramda `pipe`函数。

这个例子对你的 React 或 React Native 代码库的重要性在于，你不需要`reselect`或任何其他库来组合事物。你可以自己做。这在使用`reselect`库等用例中会很方便，该库希望你组合选择器。花一些时间适应它。

# 对抗混乱的代码

我在熟练使用 Ramda 的用户编写的代码中看到的下一个有趣的模式是所谓的**pointfree**代码。这意味着只有一个地方我们传递所有数据。尽管听起来很美好，但我不建议你对此如此严格。但是，我们可以从这种方法中得到一个好处。

考虑将你的代码从这个重构成：

```jsx
const myHoc = SomeComponent => R.compose(withLogger,withAnalytics, withRouter)(SomeComponent)
```

你可以重构成这样：

```jsx
const myHoc = R.compose(withLogger,withAnalytics, withRouter) 
```

这将隐藏明显的部分。最常见的问题是它开始像一个魔盒，只有我们知道如何向它传递数据。如果你使用像 TypeScript 或 Flow 这样的类型系统，当你完全不知道时，很容易快速查找它。但令人惊讶的是，许多开发人员会在这一点上感到恐慌。他们对`compose`的工作方式了解得越少（特别是右到左的函数应用），他们就越有可能不知道要传递什么给这个函数。

考虑这个：

```jsx
const TaskNamesList  = tasks => tasks
    .map({ name }) => (
        <View><Text>{name}</Text></View>   ))
```

现在将上一个例子与这个`compose`的疯狂版本进行比较：

```jsx
const TaskComponent  = name => (<View><Text>{name}</Text></View>)

const TaskNamesList = compose(
    map(TaskComponent),
  map(prop('name')) // prop function maps object to title key
);
```

在第一个例子中，你可能能在不到 30 秒内理解发生了什么。在第二个例子中，一个初学者可能需要超过一分钟才能理解这段代码。这是不可接受的。

# 柯里化函数

好吧，考虑到上一节的挑战，现在让我们关注另一面。在旧应用程序中，我们可能会遇到这样的问题，即修改我们想以不同方式使用的函数非常危险或耗时。

Brownfield 应用程序是过去开发并且完全功能的应用程序。其中一些应用程序可能是使用旧模式或方法构建的。我们通常无法承担将它们重写为最新趋势，比如 React Native。如果它们经过了实战测试，我们为什么还要费心呢？因此，如果我们决定新趋势会给我们带来足够的好处，我们将需要找到一种方法来连接两个世界，以便切换到它的新功能。

想象一个函数，它希望你传递两个参数，但你想先传一个，然后再传另一个：

```jsx
const oldFunc = (x, y) => { // something }

const expected = x => y => { // something }
```

如果您不想修改函数，这可能有些棘手。但是，我们可以编写一个`util`函数来为我们做这件事：

```jsx
const expected = x => y => oldFunc(x, y)
```

太棒了。但为什么要在每种情况下都写一个辅助函数呢？是时候介绍`curry`了：

```jsx
const notCurriedFunc = (x, y, z) => x + y + z;
  const curriedFunc = R.curry(notCurriedFunc);

// Usage: curriedFunc(a)(b)(c)
// or shorter: R.curry(notCurriedFunc)(a)(b)(c)

// So our case with partial application could be:
const first = R.curry(notCurriedFunc)(a)(b);
// ... <pass it somewhere else where c will be present> ...
const final = first(c)
```

就是这样。我们使它的行为就像我们想要的那样，并且甚至没有改变布朗场应用程序函数（`oldFunc`或`notCurriedFunc`）中的一行代码。

如果您的应用程序中只有一两个地方需要使用`curry`，请三思。将来会有更多的用例吗？如果没有，那么使用它可能是过度的。使用辅助箭头函数，如前所示。

# 翻转

我们可以`curry`一个函数，这很好，但如果我们想以不同的顺序传递参数怎么办？对于前两个参数的更改，有一个方便的函数叫做`flip`，在这里演示：

```jsx
const someFunc = x => y => z => x + y + z;

const someFuncYFirst = R.flip(someFunc);
// equivalent to (y => x => z => x + y + z;)
```

如果我们需要颠倒所有参数，遗憾的是没有这样的函数。但是无论如何，我们可以为我们的用例编写它：

```jsx
const someFuncReverseArgs = z => y => x => someFunc(x, y, z);
```

# 总结

在本章中，我们深入探讨了现代 JavaScript 中常见的不同模式，如迭代器、生成器、有用的 reduce 用例、选择器和函数组合。

您还学习了 Ramda 库中的一些函数。 Ramda 值得比几页简单用例更多的关注。请在空闲时间查看它。

在下一章中，我们将运用在这里学到的知识来探讨函数式编程及其好处。

# 进一步阅读

+   Mozilla 指南中的迭代器和生成器文章：

[`developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators.`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Iterators_and_Generators)

+   Reselect 文档常见问题解答：

[`github.com/reduxjs/reselect#faq`](https://github.com/reduxjs/reselect#faq).

+   不仅在 JavaScript 中使用的老式设计模式：

[`medium.com/@tkssharma/js-design-patterns-quick-look-fbc9ebfaf9aa`](https://medium.com/@tkssharma/js-design-patterns-quick-look-fbc9ebfaf9aa).

+   JavaScript 的异步迭代器的 TC39 提案：

[`github.com/tc39/proposal-async-iteration`](https://github.com/tc39/proposal-async-iteration).


# 第九章：函数式编程模式的元素

这是一个专注于函数式编程范式和设计模式的高级章节，这些设计模式来自函数式编程世界。现在是深入了解为什么我们可以创建无状态和有状态组件的时候了。这归结于理解纯函数是什么，以及不可变对象如何帮助我们预测应用程序的行为。一旦我们搞清楚了这一点，我们将继续讨论高阶函数和高阶组件。你已经多次使用过它们，但这一次我们将从稍微不同的角度来看待它们。

在整本书中，我向你提出了许多概念，在阅读完这一章后，这些概念会变得更加清晰。我希望你能在应用程序中接受它们并明智地使用它们，牢记你的团队的成熟度。这些模式是值得了解的，但对于 React 或 React Native 的开发并非必不可少。然而，当阅读 React 或 React Native 存储库的拉取请求时，你会发现自己经常参考这一章。

在本章中，我们将涵盖以下主题：

+   可变和不可变结构

+   特定函数，如纯函数

+   `Maybe`单子和单子模式

+   函数式编程的好处

+   缓存和记忆

# 可变和不可变对象

这个概念在我的一次编程面试中让我感到惊讶。在我职业生涯的开始，我对可变和不可变对象知之甚少，而这甚至在我没有意识到根本原因的情况下产生了不良后果。

在第五章中，*存储模式*，我解释了可变性和不可变性的基础知识。我们甚至使用了`Immutable.js`库。这部分书重点关注了存储。现在让我们来看看更大的图景。我们为什么需要可变或不可变的对象？

通常，主要原因是能够快速推断我们应用的行为。例如，React 想要快速检查是否应该重新渲染组件。如果你创建了对象*A*并且可以保证它永远不会改变，那么为了确保没有任何更改，你唯一需要做的就是比较对象的引用。如果它与之前相同，那么对象*A*保持不变。如果对象*A*可能会改变，我们需要比较对象*A*中的每个嵌套键，以确保它保持不变。如果对象*A*有嵌套对象，并且我们想知道它们是否没有改变，我们需要为嵌套对象重复这个过程。这是很多工作，特别是当对象*A*增长时。但为什么我们需要以这种方式做呢？

# JavaScript 中的不可变原始数据类型

在 JavaScript 中，原始数据类型（数字、字符串、布尔值、未定义、null 和符号）是不可变的。对象是可变的。此外，JavaScript 是弱类型的；这意味着变量不需要是某种类型。例如，你可以声明变量 A 并将数字 5 赋给它，然后稍后决定将对象赋给它。JavaScript 允许这样做。

为了简化事情，社区创建了两个非常重要的运动：

+   保证对象的不可变性的库

+   JavaScript 的静态类型检查器，如 Flow 或 TypeScript

第一个提供了创建对象的功能，保证它们的不可变性。这意味着，每当你想要改变对象中的某些东西时，它会克隆自身，应用更改，并返回一个全新的不可变对象。

第二个，静态类型检查器，主要解决了开发人员在意外尝试将值分配给与最初预期的不同类型的变量时的人为错误问题。因此，如果你声明`variableA`是一个数字，你永远不能将一个字符串赋给它。对我们来说，这意味着类型的不可变性。如果你想要不同的类型，你需要创建一个新的变量并将`variableA`映射到它。

关于`const`关键字的一个重要说明：`const`在引用级别上运作。它禁止引用更改。常量变量的值不能被重新分配，也不能被重新声明。对于原始的不可变类型，它只是意味着永久冻结它们。你永远不能重新分配一个新值给变量。尝试分配不同的值也会失败，因为原始类型是不可变的，这只是意味着创建一个全新的引用。对于可变类型的对象，它只是意味着冻结对象引用。我们不能将一个新对象重新分配给变量，但我们可以改变对象的内容。这意味着我们可以改变内部的内容。这并不是很有用。

# 不可变性成本解释

当我第一次接触到这个概念时，我开始挠头。这样会更快吗？如果你想修改一个对象，你需要克隆它，这是任何简单改变的严重成本。我认为这是不可接受的。我假设它的成本与我们在每个级别执行相等检查是一样的。我既对也错。

这取决于你使用的工具。特殊的数据结构，比如 Immutable.js，进行了许多优化，以便轻松工作。然而，如果你用`spread`运算符或`Object.assign()`克隆你的对象，那么你会重新创建整个对象，或者在不知不觉中只是克隆一层。

“对于深层克隆，我们需要使用其他替代方案，因为 Object.assign()只会复制属性值。如果源值是对对象的引用，它只会复制该引用值。”

- Mozilla JavaScript 文档

[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/assign`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Object/assign)。“扩展语法在复制数组时有效地进入一层。因此，它可能不适用于复制多维数组[...]（与 Object.assign()和扩展语法相同）。”

- Mozilla JavaScript 文档

[`developer.mozilla.org/pl/docs/Web/JavaScript/Reference/Operators/Spread_syntax`](https://developer.mozilla.org/pl/docs/Web/JavaScript/Reference/Operators/Spread_syntax).

这非常方便，我们在 React 应用程序中经常滥用这一事实。让我们通过一个例子来看看这一点。以下是我们将执行操作的对象：

```jsx
const someObject = {
    x: "1",
  y: 2,
  z: {
        a: 1,
  b: 2,
  c: {
            x1: 1,
  x2: 2
  }
    }
};
```

首先，我们将只克隆一层深，然后在克隆的对象中对两层深的东西进行变异。观察原始对象会发生什么。

```jsx
function naiveSpreadClone(obj) { // objects are passed by reference
    return { ...obj };
    // copy one level deep ( nested z cloned by reference ) }
const someObject2 = naiveSpreadClone(someObject); // invoke func someObject2.z.a = 10; // mutate two levels deep console.log(someObject2.z.a); // logs 10 console.log(someObject.z.a)**; //** **logs 10
// nested object in original someObject mutated too!** 
```

这是变异的一个陷阱。如果您不熟练地理解发生了什么，您可能会产生难以修复的错误。问题是，我们如何克隆两层深？请参见以下内容：

```jsx
function controlledSpreadClone(obj) {
    return { ...obj, z: { ...obj.z } }; // copy 2 levels deep }

const someObject2 = controlledSpreadClone(someObject); someObject2.z.a = 10; // mutation only in copied object console.log(someObject2.z.a); // logs 10 console.log(someObject.z.a)**; // logs 1** 
```

如果需要，您可以使用这种技术来以这种方式复制整个对象。

仅复制一层被称为**浅复制**。

# 读/写操作基准测试

为了更好地理解权衡和决定哪个库适合您的特定用例，请查看读写操作的基准测试。这应该作为一个一般的想法。在最终决定之前，请进行自己的测试。

我使用了由[ImmutableAssign 作者](https://github.com/engineforce/ImmutableAssign/)创建的基准测试。该代码自动比较了许多库和方法来解决 JavaScript 中的不可变性。

首先，让我们看看纯 JavaScript，只使用简单的可变结构。我们不关心任何好处，只是用它们作为基准测试：

| 几乎全新的 MacBook Pro 15''（2018）没有后台任务 | MacBook Pro 15''（2016）有一些后台任务在运行 |
| --- | --- |
| **可变对象和数组** 对象：读取（x500000）：9 毫秒 对象：写入（x100000）：3 毫秒 对象：非常深的读取（x500000）：31 毫秒 对象：非常深的写入（x100000）：9 毫秒 对象：合并（x100000）：17 毫秒 数组：读取（x500000）：4 毫秒 数组：写入（x100000）：3 毫秒 数组：深读（x500000）：5 毫秒 数组：深写（x100000）：2 毫秒 总计经过 49 毫秒（读取）+ **17 毫秒（写入）** + 17 毫秒（合并）= 83 毫秒。 | **可变对象和数组** 对象：读取（x500000）：11 毫秒 对象：写入（x100000）：4 毫秒 对象：非常深的读取（x500000）：42 毫秒 对象：非常深的写入（x100000）：12 毫秒 对象：合并（x100000）：17 毫秒 数组：读取（x500000）：7 毫秒 数组：写入（x100000）：3 毫秒 数组：深读（x500000）：7 毫秒 数组：深写（x100000）：3 毫秒 总计经过 67 毫秒（读取）+ **22 毫秒（写入）** + 17 毫秒（合并）= 106 毫秒。 |

括号中，您可以看到执行的操作次数。这是非常快的。没有不可变的解决方案可以超过这个基准，因为它只使用可变的 JS 对象和数组。

一些要注意的事情是基于我们阅读的深度而产生的差异。例如，读取对象（x500000）需要 11 毫秒，而非常深的对象读取（x500000）需要 42 毫秒，几乎是 4 倍长：

| 几乎全新的 MacBook Pro 15''（2018）没有后台任务 | MacBook Pro 15''（2016）有一些后台任务在运行 |
| --- | --- |
| **不可变对象和数组（Object.assign）** 对象：读取（x500000）：13 毫秒 对象：写入（x100000）：85 毫秒 对象：非常深的读取（x500000）：30 毫秒 对象：非常深的写入（x100000）：220 毫秒 对象：合并（x100000）：91 毫秒 数组：读取（x500000）：7 毫秒 数组：写入（x100000）：402 毫秒 数组：深读（x500000）：9 毫秒 数组：深写（x100000）：400 毫秒 总计经过 59 毫秒（读取）+**1107 毫秒（写入）**+91 毫秒（合并）= 1257 毫秒。 | **不可变对象和数组（Object.assign）** 对象：读取（x500000）：19 毫秒 对象：写入（x100000）：107 毫秒 对象：非常深的读取（x500000）：33 毫秒 对象：非常深的写入（x100000）：255 毫秒 对象：合并（x100000）：136 毫秒 数组：读取（x500000）：11 毫秒 数组：写入（x100000）：547 毫秒 数组：深读（x500000）：14 毫秒 数组：深写（x100000）：504 毫秒 总计经过 77 毫秒（读取）+**1413 毫秒（写入）**+136 毫秒（合并）= 1626 毫秒。 |

`Object.assign`在写操作上创建了一个峰值。现在我们看到了复制不需要的东西的成本。非常深层级的对象写操作接近于比较昂贵。数组深写比可变方式慢 100 到 200 倍：

| 几乎全新的 MacBook Pro 15''（2018）没有后台任务 | MacBook Pro 15''（2016）有一些后台任务在运行 |
| --- | --- |
| **Immutable.js 对象和数组** 对象：读取（x500000）：12 毫秒 对象：写入（x100000）：19 毫秒 对象：非常深的读取（x500000）：111 毫秒 对象：非常深的写入（x100000）：80 毫秒 对象：合并（x100000）：716 毫秒 数组：读取（x500000）：18 毫秒 数组：写入（x100000）：135 毫秒 数组：深读（x500000）：51 毫秒 数组：深写（x100000）：97 毫秒 总计经过 192 毫秒（读取）+**331 毫秒（写入）**+716 毫秒（合并）= 1239 毫秒。 | **Immutable.js 对象和数组** 对象：读取（x500000）：24 毫秒 对象：写入（x100000）：52 毫秒 对象：非常深的读取（x500000）：178 毫秒 对象：非常深的写入（x100000）：125 毫秒 对象：合并（x100000）：1207 毫秒 数组：读取（x500000）：24 毫秒 数组：写入（x100000）：255 毫秒 数组：深读（x500000）：128 毫秒 数组：深写（x100000）：137 毫秒 总计经过 354 毫秒（读取）+**569 毫秒（写入）**+1207 毫秒（合并）= 2130 毫秒。 |

对象写入的速度比可变方式慢 6 倍。非常深的对象写入几乎比可变方式慢 9 倍，并且比`Object.assign()`快 2.75 倍。合并操作，构造作为参数传递的两个对象合并结果的对象，要慢得多（比可变对象慢 42 倍，甚至如果用户正在使用其他程序，可能慢 70 倍）。

请注意所使用的硬件。要么是 2016 年的 MacBook Pro，要么是 2018 年的 MacBook Pro，两者都是速度非常快的机器。将这一点带到移动世界将会使这些基准值更高。本节的目的是让您对数字进行比较有一个大致的了解。在得出结论之前，请在与您的项目相关的特定硬件上运行您自己的测试。

# 纯函数

在本节中，我们将从不同的角度回顾我们已经学过的纯函数。您还记得 Redux 试图尽可能明确吗？这是有原因的。一切隐式的东西通常是麻烦的根源。您还记得数学课上的函数吗？那些是 100%明确的。除了将输入转换为某种输出之外，没有其他事情发生。

然而，在 JavaScript 中，函数可能具有隐式输出。它可能会更改一个值，更改外部系统，以及许多其他事情可能发生在函数范围之外。您已经在第五章 *存储模式*中学到了这一点。所有这些隐式输出通常被称为副作用。

我们需要解决所有不同类型的副作用。不可变性是我们的一种武器，它可以保护我们免受外部对象隐式更改的影响。这就是不可变性的作用——它保证绝对不会发生这种情况。

在 JavaScript 中，我们无法通过引入不可变性等武器来消除所有副作用。有些需要语言级别上的工具，而这些工具在 JavaScript 中是不可用的。在 Haskell 等函数式编程语言中，甚至输入/输出都由称为`IO()`的单独结构控制。然而，在 JavaScript 中，我们需要自己处理这些问题。这意味着我们无法避免一些函数是不纯的——因为这些函数需要处理 API 调用。

另一个例子是随机性。任何使用`Math.random`的函数都不能被认为是纯的，因为这些函数的一部分依赖于随机数生成器，这违背了纯函数的目的。一旦使用特定参数调用函数，就不能保证收到相同的输出。

同样，一切依赖于时间的东西都是不纯的。如果你的函数执行依赖于月份、日期、秒甚至年份，它就不能被认为是一个纯函数。在某个时刻，相同的参数将不会产生相同的输出。

最终，一切都归结为执行链。如果你想说一部分操作是纯净的，那么你需要知道它们每一个都是纯净的。一个最简单的例子是一个消耗另一个函数的函数：

```jsx
const example = someArray => someFunc => someFunc(someArray);
```

在这个例子中，我们不知道`someFunc`会是什么。如果`someFunc`是不纯的，那么`example`函数也将是不纯的。

# Redux 中的纯函数

好消息是我们可以将副作用推到我们应用程序的一个地方，并在真正需要时循环调用它们。这就是 Flux 所做的。Redux 甚至进一步采纯函数作为 reducers。这是可以理解的。当不纯的部分已经完成时，reducers 被调用。从那时起，我们可以保持不可变性，至少在 Redux 存储方面。

有些人可能会质疑这在性能方面是否是一个好选择。相信我，它是的。与状态访问和操作计算状态的选择器相比，我们发生的事件数量非常少（需要被减少，因此影响存储）。

为了保持状态不可变，我们得到了巨大的好处。我们可以知道导致特定状态的函数应用顺序。如果我们真的需要，我们可以追踪它。这是巨大的。我们可以在测试环境中再次应用这些函数，并且我们可以保证输出完全相同。这要归功于函数的纯净性 - 因此不会产生副作用。

# 缓存纯函数

缓存是一种记住计算的技术。如果你可以保证对于某些参数，你的函数总是返回相同的值，你可以安全地计算一次，并且始终返回这些特定参数的计算值。

让我们看看通常用于教学目的的微不足道的实现：

```jsx
const memoize = yourFunction => {
  const cache = {};

  return (...args) => {
    const cacheKey = JSON.stringify(args);
    if (!cache[cacheKey]) {
        cache[cacheKey] = yourFunction(...args);
    }
    return cache[cacheKey];
  };
};
```

这是一种强大的技术，被用于 reselect 库。

# 引用透明度

纯函数是**引用透明**的，这意味着它们的函数调用可以用给定参数的相应结果替换。

现在，看一下引用透明和引用不透明函数的例子：

```jsx
 let globalValue = 0;

 const inc1 = (num) => { // Referentially opaque (has side effects)
   globalValue += 1;
   return num + globalValue;
 }

 const inc2 = (num) => { // Referentially transparent
   return num + 1;
 }
```

让我们想象一个数学表达式：

```jsx
inc(4) + inc(4) * 5

// With referentially transparent function you can simplify to:
inc(4) * ( 1 + 1*5 )
// and even to
inc(4) * 6
```

请注意，如果您的函数不是引用透明的，您需要避免这样的简化。类似前面的表达式或`x() + x() * 0`都是诱人的陷阱。

你是否使用它取决于你自己。另请参阅本章末尾的*进一步阅读*部分。

# 除了单子以外的一切

多年来，术语单子一直臭名昭著。不是因为它是一个非常有用的构造，而是因为它引入的复杂性。人们普遍认为，一旦你理解了单子，你就失去了解释它们的能力。

“为了理解单子，你需要先学习 Haskell 和范畴论。”

我认为这就像说：为了理解墨西哥卷饼，你必须先学习西班牙语。

- Douglas Crockford：单子和性腺体（YUIConf 晚间主题演讲）

[`www.youtube.com/watch?v=dkZFtimgAcM`](https://www.youtube.com/watch?v=dkZFtimgAcM)。

单子是一种组合函数的方式，尽管存在特殊情况，比如可空值、副作用、计算，或者条件执行。这样对单子的定义使它成为一个上下文持有者。这就是为什么 X 的单子不等同于 X。在被视为`monad<X>`之前，这个 X 需要首先被提升，这意味着创建所需的上下文。如果我们不再需要`monad<X>`，我们可以将结构展平为 X，这相当于失去了一个上下文。

这就像打开圣诞礼物一样。你很确定里面有礼物，但这取决于你整年表现如何。在一些罕见的不良行为情况下，你可能最终得到的是一根棍子或一块煤。这就是`Maybe<X>`单子的工作原理。它可能是 X，也可能是空。它与可空 API 值一起使用效果很好。

# 也许给我打电话

我们的代码中有一个地方需要简化。看一下`taskSelector`：

```jsx
export const tasksSelector = state => state.tasks;   export const tasksEntitiesSelector = createSelector(
    tasksSelector,
  tasks => (tasks ? tasks.get('entities') : null)
); 
export const getTaskById = taskId => createSelector(
    tasksEntitiesSelector,
  entities => (entities
        ? entities.find(task => task.id === taskId)
        : null)
);  
```

我们不断担心我们是否收到了某物还是空值。这是一个完美的情况，可以将这样的工作委托给`Maybe`单子。一旦我们实现了`Maybe`，以下代码将是完全功能的：

```jsx
import Maybe from '../../../../utils/Maybe';   export const tasksSelector = state => Maybe(state).map(x => x.tasks);   export const tasksEntitiesSelector = createSelector(
    tasksSelector,
  maybeTasks => maybeTasks.map(tasks => tasks.get('entities'))
);   export const getTaskById = taskId => createSelector(
    tasksEntitiesSelector,
  entities => entities.map(e => e.find(task => task.id === taskId))
);
```

到目前为止，你已经了解了我们需要实现的`Maybe` monad 的一些知识：当`null`/`undefined`时，它需要是 nothing，当`null`或`undefined`时，它需要是`Something`：

```jsx
const Maybe = (value) => {
    const Nothing = {
        // Some trivial implementation   };
  const Something = val => ({
        // Some trivial implementation
    });    return (typeof value === 'undefined' || value === null)
        ? Nothing
        : Something(value); };
```

到目前为止，非常简单。问题是，我们既没有实现`Nothing`也没有实现`Something`。别担心，这很简单，就像我的评论一样。

我们需要它们都对三个函数做出反应：

+   `isNothing`

+   `val`

+   `map`

前两个函数很简单：

+   `isNothing`：`Nothing`返回`true`，`Something`返回`false`

+   `val`：`Nothing`返回`null`，`Something`返回它的值

最后一个是`map`，对于`Nothing`应该什么都不做（返回自身），对于`Something`应该将函数应用于值：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/f293a752-b6fb-44b1-ad84-e1f05ca9d370.png)

在普通字符串类型和`Maybe<string>` monad 上使用 map 函数对 toUpperCase 进行应用

让我们实现这个逻辑：

```jsx
// src / Chapter 9 / Example 1 / src / utils / Maybe.js
const Maybe = (value) => {
    const Nothing = {
        map: () => this,
  isNothing: () => true,
  val: () => null
  };
  const Something = val => ({
        map: fn => Maybe(fn.call(this, val)),
  isNothing: () => false,
  val: () => val
    });    return (typeof value === 'undefined' || value === null)
        ? Nothing
        : Something(value); };   export default Maybe;
```

我们已经完成了，不到 20 行。我们的选择器现在使用`Maybe` monad。我们需要做的最后一件事是修复最终的用法；在选择器调用之后，它应该要求值，就像下面的例子中那样：

```jsx
// src / Chapter 9 / Example 1
//         src/features/tasks/containers/TaskDetailsContainer.js 
const mapStateToProps = (state, ownProps) => ({
 task: getTaskById(ownProps.taskId)(state).val()
});
```

我们的`Maybe`实现是一个很酷的模式，可以避免空检查的负担，但它真的是一个 monad 吗？

# Monad 接口要求

更正式地说，monad 接口应该定义两个基本运算符：

+   Return（`a -> M a`），一个接受`a`类型并将其包装成 monad（`M a`）的操作

+   Bind（`M a ->（a -> M b）-> M b`），一个接受两个参数的操作：a 类型的 monad 和一个在`a`上操作并返回`M b`（`a -> M b`）monad 的函数

在这些条件下，我们的构造函数是`return`函数。然而，我们的 map 函数不符合`bind`的要求。它接受一个将`a`转换为`b`（`a -> b`）的函数，然后我们的`map`函数自动将`b`包装成`M b`。

除此之外，我们的 monad 需要遵守三个 monad 定律：

+   左单位元：

```jsx
// for all x, fn
Maybe(x).map(fn) == Maybe(fn(x))
```

+   右单位元：

```jsx
// for all x
Maybe(x).map(x => x) == Maybe(x)
```

+   结合律：

```jsx
// for all x, fn, gn
Maybe(x).map(fn).map(gn) == Maybe(x).map(x => gn(fn(x)));
```

数学证明超出了本书的范围。然而，我们可以用这些定律来验证一些随机的例子：

```jsx
// Left identity example
Maybe("randomtext")
.map(str => String.prototype.toUpperCase.call(str))
.val() // RANDOMTEXT
 Maybe(String.prototype.toUpperCase.call("randomtext"))
.val()) // RANDOMTEXT

// Right identity example
Maybe("randomtext").map(str => str).val() // randomtext
Maybe("randomtext").val() // randomtext

// Associativity
const f = str => str.replace('1', 'one'); const g = str => str.slice(1); 
Maybe("1 2 3").map(f).map(g).val() // ne 2 3
Maybe("1 2 3").map(str => g(f(str))).val() // ne 2 3
```

# 高阶函数

我们已经了解了高阶组件，本节我们将看一下更一般的概念，称为高阶函数。

看看这个例子。非常简单。你甚至不会注意到你创建了什么特别的东西：

```jsx
const add5 = x => x + 5; // function
const applyTwice = (f, x) => f(f(x)); // higher order function

applyTwice(add5, 7); // 17
```

那么什么是高阶函数呢？

高阶函数是一个做以下操作之一的函数：

+   将一个或多个函数作为参数

+   返回一个函数

就是这样，很简单。

# 高阶函数的例子

有许多高阶函数，你每天都在使用它们：

+   `Array.prototype.map`：

```jsx
someArray.map(function callback(currentValue, index, array){
    // Return new element
});

// or in the shorter form
someArray.map((currentValue, index, array) => { //... });
```

+   `Array.prototype.filter`：

```jsx
someArray.filter(function callback(currentValue, index, array){
    // Returns true or false
});

// or in the shorter form
someArray.filter((currentValue, index, array) => { //... });
```

+   `Array.prototype.reduce`：

```jsx
someArray.reduce(
    function callback(previousValue, currentValue, index, array){
        // Returns whatever
    },
    initialValue
);

// or in the shorter form
someArray.reduce((previousValue, currentValue, index, array) => {
    // ... 
}, initialValue);

// previousValue is usually referred as accumulator or short acc
// reduce callback is also referred as fold function
```

当然，还有`compose`，`call`或`curry`等函数，我们已经学习过了。

一般来说，任何接受回调的函数都是高阶函数。你在各个地方都使用这样的函数。

你还记得它们是如何很好地组合的吗？请看下面：

```jsx
someArray
    .map(...)
    .filter(...)
    .map(...)
    .reduce(...)
```

但有些不行，比如回调。你听说过回调地狱吗？

回调中的回调中的回调，这就是回调地狱。这就是为什么 Promise 被发明的原因。

然后，突然之间，`Promise`地狱开始了，所以聪明的人为 promise 创建了一种语法糖：`async`和`await`。

# 除了函数式语言

首先，请阅读大卫的这个有趣观点。

“等等，等等。持久数据结构的性能与 JavaScript MVC 的未来有什么关系？

很多。

我们将看到，也许不直观的是，不可变数据允许一个新的库 Om，即使没有用户的手动优化，也能胜过像 Backbone.js 这样性能合理的 JavaScript MVC。Om 本身是建立在 Facebook 绝妙的 React 库之上的。

- JavaScript MVC 框架的未来

大卫·诺伦（swannodette），2013 年 12 月 17 日

[`swannodette.github.io/2013/12/17/the-future-of-javascript-mvcs`](http://swannodette.github.io/2013/12/17/the-future-of-javascript-mvcs)。

在撰写本文时（2018 年 9 月），Backbone 已经停止运营。即使 Angular 的流行程度也难以与 React 竞争。React 迅速占领了市场，一旦它最终将许可证更改为 MIT，甚至加速了这一过程。

有趣的是**requestAnimationFrame**（**rAF**）并不像人们曾经认为的那样重要。

“我们在一个事件处理程序中在不同的 setState()之间进行批处理（当您退出时，所有内容都会被刷新）。对于许多情况来说，这足够好用，并且没有使用 rAF 更新的潜在问题。我们还在默认情况下查看异步渲染。但是，如果渲染树很大，rAF 并不会帮助太多。相反，我们希望使用 rIC 将非关键更新分成块，直到它们准备好被刷新。

(...) 我们使用了“过期”概念。来自交互事件的更新具有非常短的过期时间（必须很快刷新），网络事件具有更长的时间（可以等待）。基于此，我们决定刷新和时间切片的内容。

- Dan Abramov 的推文

[`twitter.com/jaffathecake/status/952861127528124417`](https://twitter.com/jaffathecake/status/952861127528124417).

我希望你从这两个引语中学到的教训是：不要想当然，不要过分美化一种方法，要学会在哪些情况下一种方法比另一种更好。函数式编程也是如此；像我曾经想的那样，简单地放弃这一章是愚蠢的。我有这种感觉：这对 React Native 程序员有用吗？是的，它有用。如果它足够流行，以至于在社区中涌现出许多公共 PR，那么你肯定会接触到这些概念，我希望你做好准备。

# 术语

不要被函子、EndoFunctors、CoMonads 和 CoRoutines 吓到——从理论抽象中获取有用的东西。让理论专家来处理它们。数学极客们一直走在前面，通常这是一件好事，但不要太疯狂。业务就是业务。截止日期不能等待你证明范畴论中最伟大的定律。

专注于理解即时的好处，比如本书中概述的好处。如果你发现自己在一个反对函数式编程模式的团队中，不要强制执行它们。毕竟，在 JavaScript 中它并不像在 Haskell 中那样重要。

“使用花哨的词而不是简单、常见的词会使事情更难理解。如果你坚持使用一个小的词汇表，你的写作会更清晰。”

- Sophie Alpert 的推文（Facebook 的 React 工程经理）

[`twitter.com/sophiebits/status/1033450495069761536`](https://twitter.com/sophiebits/status/1033450495069761536).

# 构建抽象

在本章的开始，我们对不可变库进行了基准测试，并比较了它们的性能。和任何事情一样，我强烈建议你在承诺任何库、模式或做事情的方式之前花一些时间。

大多数采用函数式编程模式的库都是为了真正的好处。如果你不确定，就把它留给别人，坚持你熟悉的命令式模式。事实证明，简单的代码通常在引擎层面上得到更好的优化。

# React 并不迷恋纯函数

当你第一次接触 React 生态系统时，你可能会有些惊讶。有很多例子使用纯函数，并谈论时间旅行，使用 Redux，以及一个存储来统治它们所有。

事实上，React 和 Redux 都不仅仅使用纯函数。实际上，这两个库中有很多函数在外部范围中执行变异：

```jsx
// Redux library code
// redux/src/createStore.js

let currentReducer = reducer
let currentState = preloadedState
let currentListeners = []
let nextListeners = currentListeners
let isDispatching = false

// Check yourself:
[`github.com/reduxjs/redux/blob/1448a7c565801029b67a84848582c6e61822f572/src/createStore.js`](https://github.com/reduxjs/redux/blob/1448a7c565801029b67a84848582c6e61822f572/src/createStore.js) [](https://github.com/reduxjs/redux/blob/1448a7c565801029b67a84848582c6e61822f572/src/createStore.js) 
```

这些变量正在被其他函数修改。

现在，看看 React 如何记住库所警告的内容：

```jsx

let didWarnAboutMaps = false; 
// (...)

if (__DEV__) {   if (iteratorFn === children.entries) {
    warning(
      didWarnAboutMaps,
  'Using Maps as children is unsupported (...)'   );
  didWarnAboutMaps = true**;**
  }
}

// Check yourself
https://github.com/facebook/react/blob/f9358c51c8de93abe3cdd0f4720b489befad8c48/packages/react/src/ReactChildren.js
```

这个小的变异取决于环境。

如果你维护一个带有这些检查的库，当前的构建工具，比如 webpack，在构建生产压缩文件时可以删除这些死代码。所谓的死代码，我指的是因为环境（生产）而永远不会被访问的代码路径（如前面的`if`语句）。

一般来说，Facebook 并不羞于展示他们的代码库在某些地方是棘手的：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/0b931c82-9955-4d74-b5ac-cf24732225a9.png)Facebook 代码库截图，由 Dan Abramov 在 Twitter 上发布

# 总结

在这一章中，我们深入研究了 JavaScript 编程中最神秘的分支之一。我们学习了单子，如何为了更大的利益使用它们，以及如果我们真的不需要的话，如何不关心数学定律。然后，我们开始使用词汇，比如纯函数，可变/不可变对象和引用透明度。

我们知道如果需要的话，纯函数有一个缓存模式。这种很好的方法在许多 Flux 应用中都很有用。现在你可以有效地使用选择器，并使用 Maybe monad 使它们变得非常简单，这消除了空值检查的负担。

有了所有这些专业知识，现在是时候学习维护依赖和大型代码库的挑战了。在下一章中，你将面临每个大型代码库的主要挑战，相信我，每个大公司在某个时候都会遇到这个问题——无论他们使用了多少编程模式或依赖了多少库。

# 进一步阅读

+   一个关于 JavaScript 函数式编程的大部分合格指南——一本免费的关于 JavaScript 函数式编程的书：

[`github.com/MostlyAdequate/mostly-adequate-guide`](https://github.com/MostlyAdequate/mostly-adequate-guide)。

+   你可能想要与 Reselect 库一起使用的缓存函数的例子：

[`github.com/reduxjs/reselect#q-the-default-memoization-function-is-no-good-can-i-use-a-different-one`](https://github.com/reduxjs/reselect#q-the-default-memoization-function-is-no-good-can-i-use-a-different-one)。

+   关于引用透明性的信息：

[`softwareengineering.stackexchange.com/questions/254304/what-is-referential-transparency`](https://softwareengineering.stackexchange.com/questions/254304/what-is-referential-transparency)。

+   Eric's Elliott 掌握 JavaScript 面试系列的一集，Pure Functions：

[`medium.com/javascript-scene/master-the-javascript-interview-what-is-a-pure-function-d1c076bec976`](https://medium.com/javascript-scene/master-the-javascript-interview-what-is-a-pure-function-d1c076bec976)。

+   一个预测未来的历史帖子，《JavaScript MVCs 的未来》：

[`swannodette.github.io/2013/12/17/the-future-of-javascript-mvcs`](http://swannodette.github.io/2013/12/17/the-future-of-javascript-mvcs)。

+   这是旧的，但仍然值得一读，《反应性的一般理论》：

[`github.com/kriskowal/gtor`](https://github.com/kriskowal/gtor)。

+   关于 JavaScript 中的函数式编程的以下书籍，《JavaScript Allonge》（可免费在线阅读）：

[`leanpub.com/javascriptallongesix/read#leanpub-auto-about-javascript-allong`](https://leanpub.com/javascriptallongesix/read#leanpub-auto-about-javascript-allong)。

+   Monad laws（Haskell Wiki）：

[`wiki.haskell.org/Monad_laws`](https://wiki.haskell.org/Monad_laws)。

+   Douglas Crockford，Monad 和 Gonads：

[`www.youtube.com/watch?v=dkZFtimgAcM`](https://www.youtube.com/watch?v=dkZFtimgAcM)。

+   Immutable.js 如何使用 Trie 图来优化写操作：

[`medium.com/@dtinth/immutable-js-persistent-data-structures-and-structural-sharing-6d163fbd73d2`](https://medium.com/@dtinth/immutable-js-persistent-data-structures-and-structural-sharing-6d163fbd73d2)。

[`en.wikipedia.org/wiki/Trie`](https://en.wikipedia.org/wiki/Trie)。

+   React 是否应默认使用`requestAnimationFrame`：

[`github.com/facebook/react/issues/11171`](https://github.com/facebook/react/issues/11171)。

+   GitHub 上一个很棒的函数式编程收藏：

[`github.com/xgrommx/awesome-functional-programming/blob/master/README.md`](https://github.com/xgrommx/awesome-functional-programming/blob/master/README.md)。

+   如果你迷恋函数式编程，这是一个非常好的资源，

《Learn You a Haskell for Great Good》（需要了解 Haskell）：

[`learnyouahaskell.com/chapters`](http://learnyouahaskell.com/chapters).


# 第十章：管理依赖关系

本章专门讨论管理依赖关系，即您的移动应用程序所依赖的库。大多数当前的应用程序滥用了单例模式。然而，我坚信，总有一天，JavaScript 开发人员会采用众所周知的**依赖注入**（**DI**）模式。即使他们决定使用单例模式，重构也会更容易。在本章中，我们将重点讨论 React 上下文以及 Redux 等库如何利用 DI 机制。这是您真正想要提升代码并使其易于测试的最安全选择。我们将深入研究 React Redux 库中的代码，该库广泛使用 React 上下文。您还将了解为什么 JavaScript 世界如此迟缓地放弃单例模式。

在本章中，您将学习以下主题：

+   单例模式

+   ECMAScript 中的 DI 模式及其变体

+   storybook 模式，以提高生产力并记录您的组件

+   React 上下文 API

+   如何管理大型代码库

准备好了吗，因为我们将立即开始单例模式。

# 单例模式

单例模式是一个只能有一个实例的类。按照其设计，每当我们尝试创建一个新实例时，它要么首次创建一个实例，要么返回先前创建的实例。

这种模式有什么用？如果我们想要为某些事情有一个单一的管理器，这就很方便，无论是 API 管理器还是缓存管理器。例如，如果您需要授权 API 以获取令牌，您只想这样做一次。第一个实例将启动必要的工作，然后任何其他实例将重用已经完成的工作。这种用例主要被服务器端应用程序滥用，但越来越多的人意识到有更好的选择。

如今，这种用例可以很容易地通过更好的模式来对抗。您可以简单地将令牌存储在缓存中，然后在任何新实例中，验证令牌是否已经在缓存中。如果是，您可以跳过授权并使用令牌。这个技巧利用了一个众所周知的事实，即缓存是存储数据的一个集中的地方。在这种情况下，它为我们提供了一个单例存储。无论是客户端还是云服务器的缓存，它都是完全相同的，唯一的区别是在服务器上调用可能更昂贵。

# 在 ECMAScript 中实现单例模式

尽管如今不鼓励使用单例模式，但学习如何创建这种机制非常有益。在这个代码示例中，我们将使用 ECMAScript 6 类和 ECMAScript 7 静态字段：

```jsx
export default class Singleton {
    static instance;    constructor() {
        if (Singleton.instance) {
            return Singleton.instance;
  }

        this.instance = this;
  }
}
```

我们正在改变构造函数的行为。首先，在返回任何内容之前，我们需要检查实例是否已经被创建。如果是，当前调用将返回该实例。

# 为什么不鼓励使用单例模式

`Singleton`有时被视为`全局`变量。如果您尝试从许多不同的地方导入它，并且您的用例只是共享相同的实例，那么您可能滥用了该模式。这样，您将不同的部分紧密耦合到精确导入的对象上。如果您使用`全局`变量而不是传递它下去，这是**代码异味**的一个重要迹象。

此外，`Singleton`在测试方面非常不可预测。您会收到一个由突变效果产生的东西。它可能是一个新对象，也可能是先前创建的对象。您可能会被诱惑使用它来同步某种状态。例如，让我们看下面的例子：

```jsx
export default class Singleton {
    static instance;    constructor() {
        if (Singleton.instance) {
            return Singleton.instance;
  }

        this.name = 'DEFAULT_NAME';
  this.instance = this;
  }

    getName() {
        return this.name;
  }

    setName(name) {
        this.name = name;
  }
}
```

这使`Singleton`不仅在全局范围内共享，而且在全局范围内可变。如果您想要使其可预测，这是一个可怕的故事。它通常会打败我们在第九章中学到的一切，*函数式编程模式的要素*。

您需要向每个使用单例模式的组件保证它已准备好处理来自单例的任何类型的数据。这需要指数数量的测试，因此会降低生产力。这是不可接受的。

在本章的后面，您将找到一个通过 DI 解决所有这些问题的解决方案。

# JavaScript 中的许多单例模式

说实话，除了之前的实现之外，我们可以看到许多其他变化，以达到相同的目的。让我们讨论一下。

在下面的代码中，单例已经作为`instance`导出：

```jsx
class Singleton {
    static instance;
  constructor() {
        if (Singleton.instance) {
            return Singleton.instance;
  }
   this.instance = this;
  }
}

export default new Singleton();
```

这看起来像是一个很好的改进，除非你的`Singleton`需要参数。如果是这样，`Singleton`被导出的方式也更难测试，并且可能只接受硬编码的依赖项。

有时，你的`Singleton`可能非常小，只需要一个对象就足够了：

```jsx
export default {
    apiRoot: API_URL,
    fetchData() {
        // ...
    },
};
```

重构这种模式可能会导致任何成熟的 JavaScript 开发人员都熟悉的语法：

```jsx
// ./apiSingleton.js
export const apiRoot = API_URL;
export const fetchData = () => {
    // ...
}

// Then import as shown below
import * as API from './apiSingleton'
```

最后一个例子可能会让你开始担心，并且你可能已经开始问自己——我是否在不知不觉中使用单例？我敢打赌你是。但只要你正确地注入它们，这并不是世界末日。让我们来看一下 ECMAScript 和 JavaScript 模块方法的部分。这对于任何 JavaScript 程序员来说都是重要的知识。

要小心，因为一些模块捆绑器不能保证模块只会被实例化一次。像 webpack 这样的工具可能会在内部多次实例化一些模块，以进行优化或兼容性。

# ES6 模块及更高版本

ES6 模块的最大优点之一是导入和导出声明的静态性质。由于这一点，我们可以在编译时检查导入和导出是否正确，执行注入（例如为旧浏览器提供 polyfill），并在必要时将它们捆绑在一起（就像 webpack 一样）。这些都是令人惊叹的积极因素，可以节省我们大量可能会减慢应用程序速度的运行时检查。

然而，有些人滥用了 ES6 模块的工作方式。语法非常简单——你可以在任何地方导入模块并轻松使用它。这是一个陷阱。你可能不想滥用导入。

# DI 模式

在同一文件中导入并使用导入的值会将该文件锁定到具体的实现。例如，看一下以下应用程序代码的实现：

```jsx
import AddTaskContainer from '../path/to/AddTaskContainer'; import TaskListContainer from '../path/to/TaskListContainer';   export const TasksSection = () => (
    <View>
 <AddTaskContainer /> <TaskListContainer /> </View> ); 
```

在这个代码示例中，`TasksSection`组件由两个容器组件`AddTaskContainer`和`TaskListContainer`组成。重要的事实是，如果你是`TasksSection`组件的使用者，你不能修改任何一个容器组件。你需要依赖于导入模块提供的实现。

为了解决这个问题，我们可以使用 DI 模式。我们基本上是将依赖项作为 props 传递给组件。在这个例子中，这将如下所示：

```jsx
export const TasksSection = ({
    AddTaskContainer,
    TaskListContainer
}) => (
    <View>
 <AddTaskContainer /> <TaskListContainer /> </View> );
```

如果有人对传递这些组件不感兴趣，我们可以创建一个容器来提供它们。但是，在我们想要用其他东西替换容器的情况下，这非常方便，例如在测试或 storybook 中！什么是 storybook？继续阅读。

# 使用 DI 模式与 storybook

storybook 是记录您的组件的一种方式。随着应用程序的增长，您可能很快就会拥有数百个组件。如果您构建一个严肃的应用程序，大多数组件都与设计规范对齐，并且所有预期的功能都已实现。诀窍在于知道发送哪些 props 以实现预期的结果。storybook 使这变得简单。当您实现一个组件时，您还为不同的场景创建一个 storybook。查看以下关于“按钮”组件的微不足道的示例：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/a901b7cd-8918-498c-aa7e-6bceacaa1d6b.png)

按钮组件的示例 storybook

通过在左侧面板中选择场景，您可以快速查看组件在不同 props 下的外观。

我已经为您安装了 Storybook，可以在`src/Example 10/Exercise 1`中进行操作。您可以通过从该目录运行`yarn run ios:storybook`或`yarn run android:storybook`来启动 Storybook。

如果您想学习如何自己设置 Storybook，请查看官方文档

[`github.com/storybooks/storybook/tree/master/app/react-native`](https://github.com/storybooks/storybook/tree/master/app/react-native)。

您需要添加的大多数配置文件应该放在项目的`storybook`目录中。

Storybook 提供的安装命令行界面为您设置了游乐场故事。这些是在前面的截图中的那些（带有文本和表情符号的“按钮”）。

是时候添加我们自己的故事了。让我们从一些简单的东西开始 - `TaskList`组件。这个组件非常适合用于故事编写，因为它非常完善。它处理错误，并根据加载状态或错误状态显示各种消息。它可以显示 0 个任务，1 个任务和 2 个或更多任务。有很多故事可以看：

```jsx
// src/Chapter_10/Example_1/src/features/tasks/stories/story.js

storiesOf('TaskList', module)
    .addDecorator(getStory => (  <ScrollView style={generalStyles.content}>{getStory()}</ScrollView>   ))
    .add('with one task', () => (
        <TaskList
  tasks={Immutable.List([exampleData.tasks[0]])}
            hasError={false}
            isLoading={false}
        />
  ))
    .add('with 7 tasks', () => (
        <TaskList
  tasks={Immutable.List(exampleData.tasks)}
            hasError={false}
            isLoading={false}
        />
    ));
```

在前面的代码示例中，我们为`TaskList`组件创建了我们的第一个故事。`storiesOf`函数是 storybook 自带的。然后，在装饰器中，我们用可滚动的视图和一般样式包装了每个故事，这些样式适用于左右的填充。最后，我们使用`add`函数创建了两个故事：只有一个故事的`TaskList`和带有`7`个故事的`TaskList`。

不幸的是，我们的代码出现了以下错误：

```jsx
Invariant Violation: withNavigation can only be used on a view hierarchy of a navigator. The wrapped component is unable to get access to navigation from props or context.
 - Runtime error in application
```

问题出在我们实现的`NavButton`组件上。它使用了`withNavigation` HOC，这实际上需要已经存在的上下文：

```jsx
// src/ Chapter_10/ Example_1/ src/ components/ NavigateButton.js

export default withNavigation(NavigateButton);
```

幸运的是，`withNavigation`已经使用了 DI 模式，这要归功于依赖于 React 上下文。我们需要做的是将所需的上下文（导航）注入到我们的故事书示例中。为此，我们需要使用`react-navigation`中的`NavigationProvider`：

```jsx
// src/ Chapter_10/ Example_1/ src/ features/ tasks/ stories/ story.js
storiesOf('TaskList', module)
    .addDecorator(getStory => (
        <**NavigationProvider**
  value={{
                navigate: action('navigate')
            }}
        >
 <ScrollView style={generalStyles.content}>{getStory()}</ScrollView>
 </**NavigationProvider**>  ))
    .add('with one task', () => (
        // ...   ))
    .add('with 7 tasks', () => (
        // ...   ));
```

最后，我们可以欣赏我们新创建的两个故事：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/bd519bd2-dfbe-4a6e-8f8a-766f61753db8.png)

storybook 中的 TaskList 组件故事

当你选择其中一个时，它将显示在模拟器上：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/a7f76cf9-b2d7-42d4-b4cd-eb749922fec1.png)

在 iPhone X 模拟器上显示的 TaskList 故事

稍微努力一下，我们可以向这个故事书添加更多的故事。例如，让我们尝试加载一个错误情况：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/e53337d0-df47-4b21-a073-47c839445871.png)加载状态和错误状态的 TaskList 故事

我们还可以为组合创建一个故事，就像前面截图中显示的那样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/9501c3c3-a69e-4b5c-b1c8-11a730c51818.png)带有错误和加载状态的 TaskList 故事

# 带有 DI 的嵌套故事

前面的例子已经足够好了。它创建了一个故事书，是可重用的，每个人都很高兴。然而，随着应用程序的增长和我们添加更多的故事，有时候不可能仅通过`Provider`来修复这个问题，或者`Provider`可能已经在太多的故事中使用了。

在本节中，我们将重构我们的代码，以便能够注入我们自己的组件而不是导入`NavButton`容器。由于我们的目标是保留之前的功能，在故事书中我们将注入一个`NavButton`故事，它将解决导航问题。然而，在正常的应用程序中，我们将像以前一样将`NavButton`容器注入到`TaskList`容器中。这里的优势在于我们根本不需要使用`NavigationProvider`：

```jsx
// src/Chapter_10/Example_1/src/features/tasks/views/TaskList.js

const TaskList = ({
    tasks, isLoading, hasError, errorMsg, NavButton
}) => (
    <View style={styles.taskList}>
        // ...  <View style={styles.taskActions}>
 <**NavButton**  data={{ taskId: task.id }}
                        to="Task"
  text="Details"
  />
 </View>
        // ...
    </View> ); 
```

从现在开始，`TaskList`期望在 props 中有`NavButton`组件。我们需要在容器和 storybook 中遵守这些 props 的期望。以下是第一个容器的代码：

```jsx
// src/Chapter_10/Example_1/src/features/tasks/containers/TaskList.js
import NavButton from '../../../components/NavigateButton';    const mapStateToProps = state => ({
    // ...   NavButton
});   const TasksContainer = connect(mapStateToProps)(fetchTasks(TaskListView));
```

到了有趣的部分了。我们需要解决一个 storybook 的问题。为了实现我们的 DI 目标，我们将为`NavButton`创建一个单独的 storybook。为了修复`TaskList` storybook，我们将导入`NavButton` story 并将其注入为`TaskList`视图的`NavButton`组件。

这可能听起来很复杂，但让我们在以下示例中看看。

要创建`NavButton` story，我们需要将`NavButton`重构为视图和容器：

```jsx
// src/Chapter_10/Example_1/src/components/NavigateButton/index.js

// container for NavButtonView

import { withNavigation } from 'react-navigation'; import NavButtonView from './view';   export default withNavigation(NavButtonView); 
```

视图与以前完全相同-我已将代码移动到`NavigateButton`目录中的`view.js`中，紧邻前一个容器。我们现在可以继续创建 storybook：

```jsx
// src/Chapter_10/Example_1/src/components/NavigateButton/story.js

import {
    withBackText,
  withDetailsText,
  withEmojisText } from './examples';
// ... 
storiesOf('**NavButton**', module)
    .addDecorator(scrollViewDecorator)
    .add('with details text', withDetailsText)
    .add('with back text', withBackText)
    .add('with emojis text', withEmojisText); 
// src/Chapter_10/Example_1/src/components/NavigateButton/examples.js
// ...
export const withDetailsText = () => (
    <NavButton
  navigation={{ navigate: () => action('navigate') }}
        text="Details"
  to=""
  data={{}}
    /> );
```

在这个代码示例中，我引入了一个小的改进。关注点分离的示例放在单独的文件中，这样它们可以在除了 storybook 之外的其他领域中重用，例如快照测试。

现在模拟`navigation`非常简单和直接。我们只需替换`navigation`对象和其中的`navigate`函数。

现在我们准备将该示例作为`TaskList` story 中的`NavButton`组件注入：

```jsx
// src/Chapter_10/Example_2/src/features/tasks/stories/story.js

import NavButtonExample from '../../../components/NavigateButton/examples';   storiesOf('TaskList', module)
    .addDecorator(scrollViewDecorator)
    .add('with one task', () => (
        <TaskList
  tasks={Immutable.List([exampleData.tasks[0]])}
            hasError={false}
            isLoading={false}
            NavButton={NavButtonExample}
        />
  ))
    // ... rest of the TaskList stories
```

同时，我们的`scrollViewDecorator`非常简洁：

```jsx
// src/ Chapter_10/ Example_2/ src/ utils/ scrollViewDecorator.js

const scrollViewDecorator = getStory => (
    <ScrollView style={generalStyles.content}>{getStory()}</ScrollView> ); 
```

# 使用 React context 进行 DI

在前一节中，我们通过简单地注入组件来非常直接地使用了 DI。React 自带了自己的 DI 机制。

React context 可以用于将依赖项注入到距离容器组件非常远的组件中。这使得 React context 非常适合在整个应用程序中重用的全局依赖项。

这样的全局依赖的好例子包括主题配置、日志记录器、调度程序、已登录用户对象或语言选项。

# 使用 React Context API

为了了解 React Context API，我们将使用一个简单的语言选择器。我创建了一个组件，允许我们选择两种语言中的一种，英语或波兰语。它将所选语言存储在 Redux 存储中：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/e705491b-1c10-44a5-8c0e-004dd261a186.png)

应用程序标题中的语言选择器，左侧图像显示选择了英语；右侧图像显示选择了波兰语

我们的目标是通过 React 上下文 API 来暴露语言。为此，我们需要使用从 React 导入的`createContext`函数。这个函数将返回一个包含`Provider`和`Consumer`组件的对象：

```jsx
// src/ Chapter_10/ Example_3/ src/ features/ language/ context.js
import { createContext } from 'react'; import { LANG_ENGLISH } from './constants';  // First function argument represents default value const { Provider, Consumer } = createContext(LANG_ENGLISH);   export const LanguageProvider = Provider; export const LanguageConsumer = Consumer;
```

`LanguageConsumer`用于获取遍历组件树的值。它遇到的第一个`LanguageProvider`将提供该值；否则，如果没有`LanguageProvider`，将使用`createContext`调用的默认值。

为了确保每个组件都可以访问语言，我们应该在根组件中添加`LanguageProvider`，最好是在屏幕组件中。为了方便使用已经学习的模式，我创建了一个称为`withLanguageProvider`的高阶组件：

```jsx
src/Chapter_10/Example_3/src/features/language/hocs/withLanguageProvider.js

const withLanguageProvider = WrappedComponent => connect(state => ({
    language: languageSelector(state)
}))(({ language, ...otherProps }) => (
    <LanguageProvider value={language}**>**
 <WrappedComponent {...otherProps} />
 **</LanguageProvider>** ));   export default withLanguageProvider;
```

我们可以使用这个实用程序以以下方式包装屏幕组件：

```jsx
withStoreProvider(withLanguageProvider(createDrawerNavigator({
    Home: TabNavigation,
  Profile: ProfileScreen,
  Settings: SettingsScreen
})));
```

请注意重构 - 我们也以相同的方式提供存储。

有了上下文中的语言，我们可以在任何较低级别的组件中进行消费，例如在`TaskList`组件中：

```jsx
// src/Chapter_10/Example_3/src/features/tasks/views/TaskList.js
// ...

**<LanguageConsumer>**
  {language => (
        <Text style={styles.selectedLanguage}>
  Selected language: {language}
        </Text>
  )}
</LanguageConsumer>
```

结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/6edefca5-8b92-41a6-8081-5d1f2842775a.png)

在 TaskList 组件中使用 LanguageConsumer 的示例用法

请注意，这只是一个例子，目的是学习上下文 API。并没有进行实际的翻译。要向应用程序添加翻译，可以使用 Yahoo!的 React Intl 库。它还为您方便地暴露了`Provider`（[`github.com/yahoo/react-intl`](https://github.com/yahoo/react-intl)）。

# React Redux 之外

如果你仔细注意之前的例子，你可能会发现一个有趣的部分 - `withStoreProvider`。这是我创建的一个高阶组件，用来用`react-redux`存储`Provider`包装根组件：

```jsx
import { Provider } from 'react-redux';
// ... <**Provider** store={store}>
 <WrappedComponent {...props} /> </**Provider**>
```

暴露的`Provider`非常类似于 React 上下文 API。上下文在 React 库中已经存在很长时间，还有一个实验性的 API。然而，最新的上下文 API 是在 React 16 中引入的，你可能会注意到旧的库仍然使用他们自己的自定义提供者。例如，看一下 react-redux `Provider`的实现，如下所示：

```jsx
class Provider extends Component {
    getChildContext() {
        return { [storeKey]: this[storeKey], [subscriptionKey]: null }
    }

    constructor(props, context) {
        super(props, context)
        this[storeKey] = props.store**;**
  }

    render() {
        return Children.only(this.props.children)
    }
}

// Full implementation available in react-redux source files
// https://github.com/reduxjs/react-redux/blob/73691e5a8d016ef9490bb20feae8671f3b8f32eb/src/components/Provider.js
```

这就是 react-redux `connect`函数如何访问你的 Redux 存储。与`Consumer` API 不同，这里有`connect`函数，我们用它来访问存储。你可能已经习惯了。把这当作如何使用暴露的提供者或消费者的指南。

# 管理代码库

我们的代码库已经开始增长。我们已经迈出了解决庞大架构问题的第一步，到目前为止，我们的文件结构相当不错：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/d10fb327-4630-4fae-954a-403e2a60b131.png)

当前 src/目录结构

尽管现在还可以，但如果我们想要扩大这个项目，我们应该重新考虑我们的方法并制定规则。

# 快速成功

当新的开发人员加入项目时，他们可能会对我们的代码库感到有些挑战。让我们解决一些简单的问题。

首先，我们的应用程序的入口文件在哪里？在根目录中。然而，在源代码（`src/`）目录中没有明确的入口点。这没关系，但将它放在靠近故事和示例的地方会很方便。一眼就可以看到示例、故事书和应用程序的根目录。

此外，我们可以重构当前的`ScreenRoot`组件。它作为`AppRoot`，并被包裹在两个 HOC 中。如你所知，这样的耦合不是一件好事。我进行了一点重构。看看新的结构：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/aa2e4e2a-923a-4f62-90c2-59f141b9160c.png)

应用程序的入口点现在清晰可见（index.js）

我们已经取得了一个非常快速的成功；现在找到根组件要容易得多。现在，让我们来看看`components`和`features`目录：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/6d248313-16ac-4508-9d0f-4d3b7302dcb5.png)组件和特性目录

组件文件夹最初是用来收集无状态组件的。随着应用程序的增长，我们很快意识到仅仅为无状态组件创建一个共享目录是不够的。我们也想要重用有状态的组件。因此，我们应该将`components`目录重命名为`common`。这更好地代表了这个目录的内容：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/e908a4cc-3ecf-4206-830c-6a790af89d9b.png)

组件目录已重命名为 common

我们很快会注意到的另一个问题是特性下的语言目录只会造成混淆。这主要是`LanguageSwitcher`，而不是一般的`language`。我们把这个放在特性下，只是因为我们想在应用程序特性组件中使用语言。语言上下文是一个特性吗？实际上不是；它是某种特性，但不是在用户体验的上下文中。这会造成混淆。

我们应该做两件事：

1.  将上下文移到 common 目录，因为我们计划在整个应用程序中重用`LanguageConsumer`。

1.  承认我们不会重用`LanguageSwitcher`组件，并将其放在布局目录中，因为它不打算在布局组件之外的任何地方使用。

一旦我们这样做了，我们的应用结构就会再次变得更清晰：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/3e9c3f03-f0dd-4a3b-bddb-6ac07d3a18f2.png)

语言目录已分为 LanguageSwitcher 和 LanguageContext

现在很容易找到`LanguageContext`。同样，我们在不改变布局的情况下不需要担心`LanguageSwitcher`的实现。

util 目录创建了类似的混乱，就像最初的语言目录一样。我们可以将其安全地移动到`common`目录：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/eb0c5fb6-d2c5-4d95-82e4-d67d08135745.png)

重构后的目录结构

现在，任何新加入项目的开发人员都可以快速了解清楚。`screens`、`layout`、`flux`、`features`和`common`都是非常自解释的名称。

# 建立惯例

每当你构建一个大型项目时，依赖开发者自己的判断，就像在前面的部分中一样，可能是不够的。不同技术负责人采取的方法的不一致可能会迅速升级，并导致在探索代码迷宫上浪费数十个开发小时。

如果这对你来说听起来像一个外国问题，我可以承诺，在每天有数百名开发人员同时工作的代码库中，建立清晰的指南和惯例是非常重要的模式。

让我们看一些例子：

+   **Linter**：负责代码外观指南并自动强制执行它们。它还可以强制执行某些使用模式，并在有备选项列表时偏爱某些选项。

+   **Flux 架构**：连接和构造 JavaScript 代码以解决常见使用模式的一般架构。不会自动强制执行。

+   **纯净的 reducers**：Reducers 需要像 Redux 库的架构决定一样纯净。这在经典的 Flux 架构中并不是强制执行的。这可能会自动执行，也可能不会。

+   **在 JavaScript 中定义的样式**：这是 React Native 默认提供的解决方案。

清单还在继续。我希望这足以说服你，建立惯例是一件好事。它确实会稍微限制可用的功能，但可以让你更快地交付客户价值。React Native 本身就是一个很好的例子，它连接了许多不同的生态系统，提供了一种统一的开发移动应用程序的方式。它已被证明可以显著提高移动开发人员的生产力。

所有大型软件公司都面临类似的惯例问题。其中一些问题是如此普遍，以至于公司投资资金将它们开源，以树立自己的声誉。多亏了这一点，我们有了以下内容：

+   React 和 React Native 来自 Facebook

+   TypeScript，微软的 ECMAScript 上的类型化语言

+   来自 Airbnb 的 eslint 配置

+   来自 Yahoo 的 React 国际化库！

+   来自 Mozilla 的 JavaScript 文档

+   来自 Google 的 Material 设计指南，以及许多其他内容

这正在改变软件世界变得更好。

我希望您将这些智慧应用于未来的项目中。请用它来提高团队和组织的生产力。如果现在过度了，这也是一个很好的迹象，表明您已经发现了这一点。

# 总结

本章解决了应用程序中依赖项的常见问题。当您努力交付牢固的应用程序时，您会发现这些模式在测试中非常有用。除此之外，您还了解了 storybook 是什么，即记录组件用例的东西。现在您可以轻松地组合组件和 storybook。

生态系统也采纳了这些模式，我们已经使用了 React Context API 来将语言上下文传递到组件链中。您还可以一窥`Provider`的 react-redux 实现。

准备好迎接最后一章，介绍如何将类型引入您的应用程序。我们最终将确保传递的变量与消费者函数的期望相匹配。这将使我们能够在应用程序中对所有内容进行类型化，而不仅仅是为 React 视图使用`PropTypes`。

# 进一步阅读

+   由 Atlaskit 开发人员提供的目录结构指南：

这个指南将教你如何维护一个大型的代码库。这是关于如何处理由多个开发人员每天维护的前端代码库的可扩展性的许多例子之一。

（[`atlaskit.atlassian.com/docs/guides/directory-structure`](https://atlaskit.atlassian.com/docs/guides/directory-structure)）。

+   Airbnb 如何使用 React Native：

关于 Airbnb 技术堆栈的技术讨论，需要将其部署到三个不同的平台：浏览器、Android 和 iOS。了解 Airbnb 开发人员所面临的挑战。

（[`www.youtube.com/watch?v=8qCociUB6aQ`](https://www.youtube.com/watch?v=8qCociUB6aQ)）。

+   Rafael de Oleza - 为 React Native 构建 JavaScript 捆绑包：

Rafael 解释了 React Native 中的 metro 捆绑器是如何工作的。

（[`www.youtube.com/watch?v=tX2lg59Wm7g`](https://www.youtube.com/watch?v=tX2lg59Wm7g)）。


# 第十一章：类型检查模式

为了能够让你的应用程序正常工作并忘记任何麻烦，你需要一种方法来确保应用程序的所有部分相互匹配。建立在 JavaScript 或 ECMAScript 之上的语言，如 Flow 或 TypeScript，为你的应用程序引入了类型系统。由于这些，你将知道没有人会向你的函数或组件发送错误的数据。我们已经在组件中使用了`PropTypes`进行断言。现在我们将把这个概念应用到任何 JavaScript 变量上。

在本章中，您将学习以下内容：

+   类型系统的基础

+   如何为函数和变量分配类型

+   契约测试是什么；例如，Pact 测试

+   泛型和联合类型

+   解决类型问题的技巧

+   类型系统如何使用名义和结构化类型

# 类型介绍

在 ECMAScript 中，我们有七种隐式类型。其中六种是原始类型。

六种原始数据类型如下：

+   布尔值。

+   数字。

+   字符串。

+   空值。

+   未定义。

+   符号——ECMAScript 中引入的唯一标识符。其目的是确保唯一性。这通常用作对象中的唯一键。

第七种类型是对象。

函数和数组也是对象。通常，任何不是原始类型的东西都是对象。

每当你给一个变量赋值时，类型会自动确定。根据类型，会有一些规则适用。

原始函数参数是按值传递的。对象是按引用传递的。

每个变量都以零和一的形式存储在内存中。按值传递意味着被调用的函数参数将被复制。这意味着创建一个具有新引用的新对象。按引用传递意味着只传递对象的引用——如果有人对引用的内存进行更改，那么会影响使用这个引用的所有人。

让我们看一下按值传递机制的例子：

```jsx
// Passing by value

function increase(x) {
    x = x + 1;
    return x;
}

var num = 5;
increase(num);
console.log(num); // prints 5
```

`num`变量没有被改变，因为在函数调用时，该值被复制了。`x`变量引用了内存中的一个全新变量。现在让我们看一个类似的例子，但是使用对象：

```jsx
// Passing by reference

function increase(obj) {
    obj.x = obj.x + 1;
    return obj;
}

var numObj = { x: 5 };
increase(numObj);
console.log(numObj); // prints { x: 6 }
```

这次，我们将`numObj`对象传递给了函数。它是按引用传递的，所以没有被复制。当我们改变`obj`变量时，它会对`numObj`产生外部影响。

然而，当我们调用前面的函数时，我们没有检查类型。默认情况下，我们可以传递任何东西。如果我们的函数无法处理传递的变量，那么它将以某种错误中断。

让我们来看看在使用`increase`函数时可能发生的隐藏和意外行为：

```jsx
function increase(obj) {
    obj.x = obj.x + 1;
    return obj;
}

var numObj = { x: "5" };
increase(numObj);
console.log(numObj); // prints { x: "51" }
```

当我们将`"5"`和`1`相加时，`increase`函数计算出`51`。这就是 JavaScript 的工作原理——它进行隐式类型转换以执行操作。

我们有办法防止这种情况并避免开发人员的意外错误吗？是的，我们可以进行运行时检查，以重新评估变量是否属于某种类型：

```jsx
// Runtime checking if obj.x is a number

function increase(obj) {
 if (**typeof obj.x === 'number'**) {
        obj.x = obj.x + 1;
        return obj;
    } else {
        throw new Error("Obj.x must be a number");
    }
}

var numObj = { x: "5" };
increase(numObj);
console.log(numObj); // do not print, an Error message is shown
// Uncaught Error: Obj.x must be a number
```

运行时检查是在代码评估时执行的检查。它是代码执行阶段的一部分，会影响应用程序的速度。我们将在本章后面更仔细地研究运行时检查，在运行时验证问题解决部分。

当抛出`Error`消息时，我们还需要为组件替换使用错误边界或一些`try{}catch(){}`语法来处理异步代码错误。

如果您没有从头开始阅读本书，那么您可能会发现回到第二章，*查看模式*，以了解有关 React 中错误边界的更多信息。

然而，我们没有检查`obj`变量是否是`Object`类型！可以添加此类运行时检查，但让我们看看更方便的东西——TypeScript，这是建立在 JavaScript 之上的类型检查语言。

# TypeScript 简介

TypeScript 为我们的代码带来了类型。我们可以明确表达函数只接受特定变量类型的要求。让我们看看如何在 TypeScript 的类型中使用上一节的示例：

```jsx
type ObjXType = {
 x: number
}

function increase(obj: ObjXType) {
    obj.x = obj.x + 1;
    return obj;
}

var numObj = { x: "5" };
increase(numObj);
console.log(numObj);
```

这段代码将无法编译。静态检查将以错误退出，因为类型不匹配导致代码库损坏。

将显示以下错误：

```jsx
Argument of type '{ x: string; }' is not assignable to parameter of type 'ObjXType'.
 Types of property 'x' are incompatible.
 **Type 'string' is not assignable to type 'number'.**
```

TypeScript 已经抓住了我们的错误。我们需要修复错误。除非开发人员修复错误，否则这样的代码永远不会到达最终用户。

# 配置 TypeScript

为了您的方便，我已经在我们的存储库中配置了 TypeScript。您可以在代码文件的`src/Chapter 11/Example 1`下查看它。

有几件事我希望您能理解。

TypeScript 有自己的配置文件，称为`tsconfig.json`。在这个文件中，您会发现多个配置属性，控制着 TypeScript 编译器的严格程度。您可以在官方文档中找到属性和解释的详细列表[`www.typescriptlang.org/docs/handbook/compiler-options.html`](https://www.typescriptlang.org/docs/handbook/compiler-options.html)。

在选项中，您可以找到`outDir`。这指定了编译器输出应该保存在哪里。在我们的存储库中，它设置为`"outDir": "build/dist"`。从现在开始，我们的应用程序将从`build/dist`目录运行编译后的代码。因此，我已经将根`App.js`文件更改如下：

```jsx
// src/ Chapter_11/ Example_1_TypeScript_support/ App.js

import StandaloneApp from './build/dist/Root'; import StoryBookApp from './build/dist/storybook';   // ... export default process.env['REACT_NATIVE_IS_STORY_BOOK'] ? StoryBookApp : StandaloneApp; 
```

现在您了解了配置更改，我们现在可以继续学习基本类型。

# 学习基本类型

要充分利用 TypeScript，您应该尽可能多地为代码添加类型。然而，在我们的应用之前并没有类型。对于大型应用程序，显然不能突然在所有地方添加类型。因此，我们将逐渐增加应用程序类型覆盖范围。

TypeScript 的基本类型列表相当长 - 布尔、数字、字符串、数组、元组、枚举、any、void、null、undefined、never 和对象。如果您对其中任何一个不熟悉，请查看以下页面：

[`www.typescriptlang.org/docs/handbook/basic-types.html`](https://www.typescriptlang.org/docs/handbook/basic-types.html)。

首先，让我们看一下我们使用的组件之一：

```jsx
import PropTypes from 'prop-types';   export const NavigateButton = ({
    navigation, to, data, text
}) => (
    // ...  );   NavigateButton.propTypes = {
    // ...
};  
```

我们现在将切换到 TypeScript。让我们从`Prop`类型开始：

```jsx
import {
    NavigationParams, NavigationScreenProp, NavigationState
} from 'react-navigation';   type NavigateButtonProps = {
 to: string,
 data: any,
 text: string,
 **navigation: NavigationScreenProp<NavigationState, NavigationParams>** }; 
```

在这些小例子中，我们已经定义了`NavigationButton` props 的结构。`data` prop 是`any`类型，因为我们无法控制传递的数据是什么类型。

`navigation` prop 使用了`react-navigation`库定义的类型。这对于重用已经暴露的类型至关重要。在项目文件中，我使用`yarn add @types/react-navigation`命令安装了`react-navigation`类型。

我们可以继续为`NavigationButton`添加类型：

```jsx
export const NavigateButton:React.SFC<NavigateButtonProps> = ({
    navigation, to, data, text }) => (
    // ...  );

// Full example available at
// src/ Chapter_11/ Example_1/ src/ common/ NavigateButton/ view.tsx
```

`SFC`类型由 React 库导出。它是一个通用类型，可以接受任何可能的 prop 类型定义。因此，我们需要指定它是什么样的 prop 类型：`SFC<NavigateButtonProps>`。

就是这样 - 我们还需要删除底部的旧`NavigateButton.propTypes`定义。从现在开始，TypeScript 将验证传递给`NavigateButton`函数的类型。

# 枚举和常量模式

在我看到的任何代码库中，都有一个长期受到赞扬的概念：常量。它们节省了很多价值，几乎每个人都同意定义保存特定常量值的变量是必须的。如果我们将它复制到需要它们的每个地方，更新值将会更加困难。

一些常量需要灵活，因此，聪明的开发人员将它们提取到配置文件中。这些文件存储在代码库中，有时以许多不同的风格存储（例如，用于测试：`dev`，质量保证和生产环境）。

在许多情况下，我们定义的常量只允许一组常量有效值。例如，如果我们要定义可用环境，那么我们可以创建一个列表：

```jsx
const ENV_TEST = 'environment_test';
// ...

const availableEnvironments = [ENV_TEST, ENV_DEV, ENV_QA, ENV_PROD]
```

在旧式的 JavaScript 编程中，你可以简单地使用`switch-case`来切换环境，并将相关信息传播给应用程序中的特定对象。如果环境无法识别，那么它会进入一个默认子句，通常会抛出一个错误，说“无法识别的环境”，然后关闭应用程序。

如果你认为在 TypeScript 中，你不需要检查这些东西，那么你是错的。你从外部获取的任何东西都需要运行时验证。你不能允许 JavaScript 自行失败并以不可预测的方式使应用程序崩溃。这是一个经常被忽视的巨大“陷阱”。

你可能遇到的最常见问题之一是 API 的更改。如果你期望`http://XYZ`端点返回带有`tasks`键的 JSON，并且你没有验证实际返回给你的内容，那么你就会遇到麻烦。例如，如果另一个团队决定将键更改为`projectTasks`，并且不知道你对`tasks`的依赖，那么肯定会导致问题。我们该如何解决这个问题？

对 API 的预期返回值很容易强制执行。很久以前，就出现了术语合同测试。这意味着在前端和后端系统中创建合同。合同不能更改，而不确定两个代码库是否准备好。这通常由一些自动化工具强制执行，其中之一可能是 Pact 测试。

“**Pact**（名词）：

个人或团体之间的正式协议。“该国与美国谈判达成了一项贸易协定。

同义词：协议，协议，协议，合同”

- [牛津词典（https://en.oxforddictionaries.com/definition/pact）](https://en.oxforddictionaries.com/definition/pact)。

如果您正在寻找一种以编程方式强制执行此操作的方法，请查看[`github.com/pact-foundation/pact-js`](https://github.com/pact-foundation/pact-js)。这个主题很难，也需要对后端语言有所了解，因此超出了本书的范围。

一旦我们 100%确定外部世界的数据已经得到验证，我们可能希望确保我们自己的计算永远不会导致变量的改变（例如通过不可变性，参见第九章 *函数式编程模式的元素*），或者如果变化是预期的，它将始终保留允许集合的值。

这就是 TypeScript 派上用场的时候。您可以确保您的计算将始终导致允许的状态之一。您将不需要任何运行时验证。TypeScript 将帮助您避免不必要的检查，大量的检查可能会导致您的应用程序减慢几毫秒。让我们看看我们可以如何做到这一点：

```jsx
// src/ Chapter_11/
// Example_2/ src/ features/ tasks/ actions/ TasksActionTypes.ts

enum TasksActionType {
    ADD_TASK = 'ADD_TASK',
  TASKS_FETCH_START = 'TASKS_FETCH_START',
  TASKS_FETCH_COMPLETE = 'TASKS_FETCH_COMPLETE',
  TASKS_FETCH_ERROR = 'TASKS_FETCH_ERROR',
  TASK_FETCH_START = 'TASK_FETCH_START',
  TASK_FETCH_COMPLETE = 'TASK_FETCH_COMPLETE',
  TASK_FETCH_ERROR = 'TASK_FETCH_ERROR' }
```

我们已经定义了一个`enum`类型。如果变量预期是`TasksActionType`类型，它只能被赋予前面`enum TasksActionType`中的值。

现在我们可以定义`AddTaskActionType`：

```jsx
export type TaskAddFormData = {
    name: string,
  description: string }

export type AddTaskActionType = {
 type: TasksActionType.ADD_TASK,
 task: TaskAddFormData
};
```

它将用于`addTask`动作创建者：

```jsx
// src/ Chapter_11/
// Example_2/ src/ features/ tasks/ actions/ TaskActions.ts

const addTask = (task:TaskAddFormData): AddTaskActionType => ({
    type: TasksActionType.ADD_TASK,
  task
});
```

现在我们的动作创建者经过了很好的类型检查。如果任何开发人员错误地将`type`对象键更改为其他任何值，例如`TasksActionType.TASK_FETCH_COMPLETE`，那么 TypeScript 将检测到并显示不兼容错误。

我们有`AddTaskActionType`，但是我们如何将其与我们的 reducer 可能接受的其他动作类型组合起来？我们可以使用联合类型。

# 创建联合类型和交集

联合类型描述了可以是多种类型之一的值。这非常适合我们的`Tasks` reducer 类型：

```jsx
export type TaskReduxActionType =
    AddTaskActionType |
    TasksFetchActionType |
    TasksFetchCompleteActionType |
    TasksFetchErrorActionType |
    TaskFetchActionType |
    TaskFetchCompleteActionType |
    TaskFetchErrorActionType;
```

联合类型是使用`**|**`运算符创建的。它的工作方式就像`|`是`或`。一个类型或另一个类型。

现在我们可以在`Reducer`函数中使用之前的类型：

```jsx
// src/ Chapter_11/ 
// Example_3/ src/ features/ tasks/ state/ reducers/ tasksReducer.ts

const tasksReducer = (
    state = Immutable.Map<string, any>({
        entities: Immutable.List<TaskType>([]),
  isLoading: false,
  hasError: false,
  errorMsg: ''
  }),
  action:TaskReduxActionType
) => {
    // ...
}
```

为了让 TypeScript 满意，我们需要为所有参数添加类型。因此，我已经添加了其余的类型。其中一个仍然缺失：`TaskType`。

在前面的代码示例中，您可能会对`Immutable.List<TaskType>`的表示法感到惊讶，特别是`< >`符号。这些需要使用，因为`List`是一种通用类型。我们将在下一节讨论通用类型。

要创建`TaskType`，我们可以将其类型写成如下形式：

```jsx
type TaskType = {
    name: string,
    description: string
    likes: number,
  id: number }
```

然而，这并不是重用我们已经创建的类型：`TaskAddFormData`。是否要这样做是另一个讨论的话题。让我们假设我们想要这样做。

为了重用现有类型并声明或创建所需形状的`TaskType`，我们需要使用交集：

```jsx

export type TaskAddFormData = {
    name: string,
  description: string }

export type TaskType = TaskAddFormData & {
    likes: number,
  id: number }
```

在这个例子中，我们使用`&`交集运算符创建了一个新类型。创建的类型是`&`运算符左侧和右侧类型的交集：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/hsn-dsn-ptn-rn/img/7683edab-1560-4008-9969-33e9e76d8ef9.png)

交集图，其中交集是既在圆 A 中又在圆 B 中的空间。

**A**和**B**的交集具有**A**和**B**的属性。因此，由类型**A**和类型**B**的交集创建的类型必须同时具有类型**A**和类型**B**的类型。总结一下，`TaskType`现在必须具有以下形状：

```jsx
{
    name: string,
    description: string
    likes: number,
  id: number
}
```

如您所见，交集可能很方便。有时，当我们依赖外部库时，我们不希望像前面的例子中那样硬编码键类型。让我们再看一遍：

```jsx
type NavigateButtonProps = {
    to: string,
  data: any,
  text: string,
  navigation: NavigationScreenProp<NavigationState, NavigationParams>
};
```

导航键在我们的类型中是硬编码的。我们可以使用交集来符合外部库形状可能发生的未来变化：

```jsx
// src/ Chapter_11/ 
// Example_3/ src/ common/ NavigateButton/ view.tsx

import { NavigationInjectedProps, NavigationParams } from 'react-navigation';   type NavigateButtonProps = {
    to: string,
  data: any,
  text: string, } & NavigationInjectedProps<NavigationParams>;
```

在这个例子中，我们再次使用`<>`符号。这是因为`NavigationInjectedProps`是一种泛型类型。让我们学习一下泛型类型是什么。

# 泛型类型

泛型允许您编写能够处理任何类型对象的代码。例如，您知道列表是一种泛型类型。您可以创建任何类型的列表。因此，当我们使用`Immutable.List`时，我们必须指定列表将包含哪种类型的对象：

```jsx
Immutable.List<TaskType>
```

任务列表。现在让我们创建我们自己的泛型类型。

在我们的代码库中，有一个工具应该能够处理任何类型。它是一个`Maybe`单子。

如果您已经跳转到本章，则可能会发现在第九章中阅读有关单子模式的信息很有用，*函数式编程模式的元素*。

`Maybe`单子要么是`Nothing`，当变量恰好是`null`、`undefined`时，要么是该类型的`Something`。这非常适合泛型类型：

```jsx
export type MaybeType<T> = Something<T> | Nothing; 
const Maybe = <T>(value: T):MaybeType<T> => {
    // ...  }; 
```

棘手的部分是实现`Something<T>`和`Nothing`。让我们从`Nothing`开始，因为它要容易得多。它应该在值检查时返回`null`，并始终映射到自身：

```jsx
export type Nothing = {
    map: (args: any) => Nothing,
  isNothing: () => true,
  val: () => **null** }
```

`Something<T>`应该映射到`Something<MappingResult>`或`Nothing`。值检查应该返回`T`：

```jsx
export type Something<T> = {
    map: <Z>(fn: ((a:T) => Z)) => MaybeType<Z>,
  isNothing: () => false,
  val: () => T
}
```

通过在`map`函数签名中引入的`Z`泛型类型来保存结果类型的映射。

然而，如果我们尝试使用我们新定义的类型，它们将不起作用。不幸的是，TypeScript 并不总是正确地推断联合类型。当类型的联合导致特定键的不同调用签名时，就会出现这个问题。在我们的情况下，这发生在`map`函数上。它的类型是`(args: any) => Nothing`或`<Z>(fn: ((a:T) => Z)) => MaybeType<Z>`。因此，`map`没有兼容的调用签名。

这个问题的快速解决方法是定义一个独立的`MaybeType`，满足两个冲突的类型定义：

```jsx
export type MaybeType<T> = {
    map: <Z>(fn: ((a:T) => Z)) => (MaybeType<Z> | Nothing),
  isNothing: () => boolean,
  val: () => (T | null)
}
```

有了这样的类型定义，我们可以继续使用新的泛型类型：

```jsx
// src/ Chapter_11/ 
// Example_4/ src/ features/ tasks/ state/ selectors/ tasks.ts

export const tasksSelector =
    (state: TasksState):MaybeType<Immutable.Map<string, any>> =>
        Maybe<TasksState>(state).map((x:TasksState) => x.tasks);
```

选择器函数以`TasksState`作为参数，并且期望返回一个分配给状态中`tasks`键的映射。这可能看起来有点难以理解，因此，我强烈建议你打开前面的文件，仔细看一看。如果你有困难，在本章末尾的“进一步阅读”部分中，我已经包含了一个在 GitHub 上讨论这个问题的参考链接。

# 理解 TypeScript

在前面的部分中，我们遇到了一个问题，如果你从未使用过类型系统，可能很难理解。让我们稍微了解一下 TypeScript 本身，以更好地理解这个问题。

# 类型推断

我想让你明白的第一件事是类型推断。你不需要输入所有的类型。一些类型可以被 TypeScript 推断出来。

想象一种情况，我告诉你，“我只在你桌子上的盒子里放了巧克力甜甜圈。”在这个例子中，我假装是计算机，你可以相信我。因此，当你到达你的桌子时，你百分之百确定这个盒子是`Box<ChocolateDonut[]>`类型。你知道这一点，而不需要打开盒子或者在上面贴上写着“装满巧克力甜甜圈的盒子”的标签。

在实际代码中，它的工作方式非常相似。让我们看下面的最小示例：

```jsx
const someVar = 123; // someVar type is number
```

这很琐碎。现在我们可以看一些我更喜欢的东西，`ChocolateDonuts`，如下：

```jsx
enum FLAVOURS {
    CHOCOLATE = 'Chocolate',
    VANILLA = 'Vanilla',
}
type ChocolateDonut = { flavour: FLAVOURS.CHOCOLATE }

const clone = <T>(sth:T):T => JSON.parse(JSON.stringify(sth));

const produceBox: <T>(recipe: T) => T[] = <T>(recipe: T) => [
    clone(recipe), clone(recipe), clone(recipe)
];

// box type is inferred
const box = produceBox<ChocolateDonut>({ flavour: flavours.CHOCOLATE });

// inferred type correctly contains flavor key within donut object
for (const donut of box) {
    console.log(donut.flavour);
} // compiles and when run prints "Chocolate" three times
```

在这个例子中，我们同时使用了`enum`和泛型类型。`clone`简单地将任何类型克隆成一个全新的类型，并委托给 JSON 函数：`stringify`和`parse`。`ProduceBox`函数简单地接受一个配方，并根据该配方创建一个克隆数组。最后，我们创建了一个巧克力甜甜圈盒子。类型被正确地推断，因为我们为`produceBox`指定了一个泛型类型。

# 结构类型

TypeScript 使用结构类型。为了理解这意味着什么，让我们看下面的例子：

```jsx
interface Donut {
    flavour: FLAVOURS;
}

class ChocolateDonut {
    flavour: FLAVOURS.CHOCOLATE;
}

let p: Donut;

// OK, because of structural typing
p = new ChocolateDonut();
```

在这个例子中，我们首先声明了变量`p`，然后将`ChocolateDonut`的一个新实例赋给它。这在 TypeScript 中是有效的。在 Java 中是行不通的。为什么呢？

我们从未明确指出`ChocolateDonut`实现了`Donut`接口。如果 TypeScript 没有使用结构类型，你需要将前面的代码部分重构为以下内容：

```jsx
class ChocolateDonut implements Donut {
    flavour: FLAVOURS.CHOCOLATE;
}
```

使用结构类型的原因通常被称为鸭子类型：

如果它走起来像鸭子，叫起来像鸭子，那么它一定是鸭子。

因此，在 TypeScript 中不需要`implements Donut`，因为`ChocolateDonut`已经表现得像一个甜甜圈，所以它一定是一个甜甜圈。万岁！

# TypeScript 中的不可变性

在这一部分，我想重申一下不可变性的观点。这个话题在 JavaScript 中非常重要，在某些情况下，TypeScript 可能是比其他任何不可变性路径更好的解决方案。

TypeScript 带有特殊的`readonly`关键字，它强制某个变量是只读的。你不能改变这样的变量。这在编译时强制执行。因此，你没有不可变性的运行时检查。如果这对你来说是一个巨大的胜利，那么你甚至可能不需要任何 API，比如 Immutable.js。当你需要克隆大对象以避免变异时，Immutable.js 就会发光。如果你可以自己使用扩展操作来解决问题，那么这意味着你的对象可能还不够大，不需要 Immutable.js。

# readonly

由于我们的应用程序目前还不是很大，因此作为一个练习，让我们用 TypeScript 的`readonly`来替换 Immutable.js：

```jsx
export type TasksReducerState = {
    readonly entities: TaskType[],
 readonly isLoading: boolean,
 readonly hasError: boolean,
 readonly errorMsg: string }
```

这看起来有很多重复。我们可以使用`Readonly< T >`代替：

```jsx
export type TasksReducerState = Readonly<{
    entities: TaskType[],
  isLoading: boolean,
  hasError: boolean,
  errorMsg: string }>
```

这看起来干净多了。然而，它并不完全不可变。你仍然可以改变`entities`数组。为了防止这种情况，我们需要使用`ReadonlyArray<TaskType>`：

```jsx
export type TasksReducerState = Readonly<{
    entities: ReadonlyArray<TaskType>,
 // ...  }>
```

剩下的工作是在整个应用程序中用`ReadonlyArray<TaskType>`替换每个`TaskType[]`。然后，您需要将 Immutable.js 对象更改为标准的 JavaScript 数组。这样的重构很长，不适合这些书页，但我已经在代码文件中进行了重构。如果您想查看已更改的内容，请转到`src/Chapter_11/Example_5`的代码文件目录。

# 使用 linter 来强制不可变性

您可以使用 TypeScript linter 在 TypeScript 文件中强制使用`readonly`关键字。允许您执行此操作的开源解决方案之一是`tslint-immutable`。

它向`tslint.json`配置文件添加了额外的规则：

```jsx
"no-var-keyword": true,  "no-let": true,  "no-object-mutation": true, "no-delete": true,  "no-parameter-reassignment": true,  "readonly-keyword": true, "readonly-array": true,
```

从现在开始，当您运行 linter 时，如果违反了前述规则，您将看到错误。我已经重构了代码以符合这些规则。在`src/Chapter_11/Example_6`的代码文件目录中检查完整示例。要运行 linter，您可以在终端中使用以下命令：

```jsx
  yarn run lint
```

# 摘要

在本章中，您已经了解了一个非常强大的工具：建立在 JavaScript 之上的类型化语言。类型检查对于任何代码库都有无数的优势。它可以防止您部署违反预期的破坏性更改。您已经学会了如何告诉 TypeScript 什么是允许的。您知道什么是泛型类型，以及如何在类型文件中使用它们以减少代码重复。

新工具带来了新知识，因此您还学会了类型推断和结构类型的基础知识。TypeScript 的这一部分绝对需要反复试验。练习以更好地理解它。

这是本书的最后一章。我希望你已经学到了许多有趣的概念和模式。我在整本书中都在向你挑战；现在是你挑战你的代码库的时候了。看看哪些适合你的应用程序，也许重新思考你和你的团队之前所做的选择。

如果您不理解某些模式，不要担心。并非所有模式都是必需的。有些是通过经验获得的，有些仅适用于大型代码库，有些是偏好问题。

选择能够保证应用程序正确性的模式，以及能够更快地为客户增加价值的模式。祝你好运！

# 进一步阅读

+   *精通 TypeScript（第二版）*，Nathan Rozentals：这是一本深入学习 TypeScript 的好书。它演示了如何对一些非常高级的用例进行类型化。这是我的个人推荐，而不是出版商的。

+   TypeScript 的官方文档可以在[www.typescriptlang.org](http://www.typescriptlang.org)找到。

+   在本章前面提到的调用签名问题的讨论可以在 TypeScript GitHub 存储库的[`github.com/Microsoft/TypeScript/issues/7294`](https://github.com/Microsoft/TypeScript/issues/7294)找到。
