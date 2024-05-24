# 现代化遗留的 PHP 应用（三）

> 原文：[`zh.annas-archive.org/md5/06777b89258a8f4db4e497a7883acfb3`](https://zh.annas-archive.org/md5/06777b89258a8f4db4e497a7883acfb3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：将动作逻辑提取到控制器中

到目前为止，我们已经提取了我们的模型领域逻辑和视图呈现逻辑。我们的页面脚本中只剩下两种逻辑：

+   使用应用程序设置创建对象的依赖逻辑

+   使用这些对象执行页面动作的动作逻辑（有时称为业务逻辑）

在本章中，我们将从我们的页面脚本中提取出一层`Controller`类。这些类将单独处理我们遗留应用程序中的剩余动作逻辑，与我们的依赖创建逻辑分开。

# 嵌入式动作逻辑

作为嵌入式动作逻辑与依赖逻辑混合的示例，我们可以查看上一章末尾的示例代码，在附录 G 中可以找到，*响应视图文件后的代码*。在其中，我们做了一些设置工作，然后检查一些条件并调用我们领域`Transactions`的不同部分，最后我们组合了一个`Response`对象来将我们的响应发送给客户端。

与混合呈现逻辑的问题一样，我们无法单独测试动作逻辑，而无法轻松更改依赖创建逻辑以使页面脚本更易于测试。

我们解决了嵌入式动作逻辑的问题，就像解决嵌入式呈现逻辑一样。我们必须将动作代码提取到自己的类中，以将页面脚本的各种剩余关注点分开。这也将使我们能够独立于应用程序的其余部分测试动作逻辑。

## 提取过程

现在，从我们的页面脚本中提取动作逻辑应该对我们来说是一个相对容易的任务。因为领域层已经被提取出来，以及呈现层，动作逻辑应该是显而易见的。工作本身仍然需要注意细节，因为主要问题将是从动作逻辑本身中分离出依赖设置部分。

一般来说，流程如下：

1.  找到一个页面脚本，其中动作逻辑仍然与其余代码混合在一起。

1.  在该页面脚本中，重新排列代码，使所有动作逻辑位于其自己的中心块中。抽查重新排列的代码，确保它仍然正常工作。

1.  将动作逻辑的中心块提取到一个新的`Controller`类中，并修改页面脚本以使用新的`Controller`。使用*Controller*对页面脚本进行抽查。

1.  为新的`Controller`类编写单元测试，并再次进行抽查。

1.  提交新代码和测试，将它们推送到共享存储库，并通知质量保证团队。

1.  查找另一个包含嵌入式动作逻辑的页面脚本，并重新开始；当所有页面脚本都使用`Controller`对象时，我们就完成了。

## 搜索嵌入式动作逻辑

此时，我们应该能够找到动作逻辑，而无需使用项目范围的搜索功能。我们遗留应用程序中的每个页面脚本可能都至少有一点动作逻辑。

## 重新排列页面脚本并进行抽查

当我们有一个候选页面脚本时，我们继续重新排列代码，使所有设置和依赖创建工作位于顶部，所有动作逻辑位于中间，`$response->send()`调用位于底部。在这里，我们将使用上一章末尾的代码作为起始示例，该代码可以在附录 G 中找到，*响应视图文件后的代码*。

### 识别代码块

首先，我们转到脚本的顶部，在第一行（或者在包含设置脚本之后）放置一个`/* 依赖 */`注释。然后我们转到脚本的最末尾，到`$response->send()`行，并在其上方放置一个`/* 完成 */`注释。

现在我们达到了一个必须使用我们的专业判断的时刻。在页面脚本中设置和依赖工作之后的某一行，我们会发现代码开始执行某种动作逻辑。我们对这个转变发生的确切位置的评估可能有些随意，因为动作逻辑和设置逻辑很可能仍然交织在一起。即便如此，我们必须选择一个我们认为动作逻辑真正开始的时间点，并在那里放置一个`/* 控制器 */`注释。

### 将代码移动到相关块

一旦我们在页面脚本中确定了这三个块，我们就开始重新排列代码，以便只有设置和依赖创建工作发生在`/* 依赖 */`和`/* 控制器 */`之间，只有动作逻辑发生在`/* 控制器 */`和`/* 完成 */`之间。

一般来说，我们应该避免在依赖块中使用条件或循环，并且避免在控制器块中创建对象。依赖块中的代码应该只创建对象，控制器块中的代码应该只操作在依赖块中创建的对象。

鉴于我们在附录 G 中的起始代码，*响应视图文件后的代码*，我们可以在附录 H 中看到一个示例重新排列的结果，*控制器重新排列后的代码*。值得注意的是，我们将`$user_id`声明移到了控制器块，将`Response`对象创建移到了依赖块。中央控制器块中的原始动作逻辑在其他方面保持不变。

### 抽查重新排列后的代码

最后，在重新排列页面脚本之后，我们需要抽查我们的更改，以确保一切仍然正常工作。如果我们有特征测试，我们应该运行这些测试。否则，我们应该浏览或以其他方式调用页面脚本。如果它没有正确工作，我们需要撤消并重新进行重新排列，以修复我们引入的任何错误。

当我们的抽查运行成功时，我们可能希望提交到目前为止的更改。这将给我们一个已知工作的状态，如果将来的更改出现问题，我们可以回滚到这个状态。

### 提取一个控制器类

现在我们有一个正确工作的重新排列页面脚本，我们可以将中央控制器块提取到一个独立的类中。这并不困难，但我们将分几个子步骤来确保一切顺利进行。

### 选择一个类名

在我们可以提取到一个类之前，我们需要为我们将要提取到的类选择一个名称。

对于我们的领域层类，我们选择了顶层命名空间*Domain*。因为这是一个控制器层，我们将使用顶层命名空间*Controller*。我们使用的命名空间并不像一致地为所有控制器使用相同的命名空间那样重要。就个人而言，我更喜欢*Controller*，因为它足够广泛，可以包含不同类型的控制器，比如应用控制器。

该命名空间中的类名应该反映页面脚本在 URL 层次结构中的位置，其中在路径中有目录分隔符的地方使用命名空间分隔符。这种方法可以清楚地显示原始页面脚本目录路径，并且可以在类结构中很好地组织子目录。我们还在类名后缀加上`Page`以表明它是一个页面控制器。

例如，如果页面脚本位于`/foo/bar/baz.php`，那么类名应该是`Controller\Foo\Bar\BazPage`。然后，类文件本身将被放置在我们的中央类目录下的`classes/Controller/Foo/Bar/BazPage.php`。

### 创建一个骨架类文件

一旦我们有了一个类名，我们就可以为其创建一个骨架类文件。我们添加两个空方法作为以后的占位符：`__invoke()`方法将接收页面脚本的动作逻辑，构造函数最终将接收类的依赖项。

```php
**classes/Controller/Foo/Bar/BazPage.php**
1 <?php
2 namespace Controller\Foo\Bar;
3
4 class BazPage
5 {
6 public function __construct()
7 {
8 }
9
10 public function __invoke()
11 {
12 }
13 }
14 ?>
```

### 注意

**为什么是 __invoke()?**

就我个人而言，我喜欢利用`__invoke()`魔术方法来实现这个目的，但您可能希望使用`exec()`或其他适当的术语来指示我们正在执行或以其他方式运行控制器。无论我们选择什么方法名，我们都应该保持一致使用。

## 移动动作逻辑并进行抽查

现在我们准备将动作逻辑提取到我们的新`Controller`类中。

首先，我们从页面脚本中剪切控制器块，并将其原样粘贴到`__invoke()`方法中。我们在动作逻辑的末尾添加一行`return $response`，将*Response*对象发送回调用代码。

接下来，我们回到页面脚本。在提取的动作逻辑的位置，我们创建一个新的`Controller`实例并调用其`__invoke()`方法，得到一个*Response*对象。

我们应该在所有页面脚本中`始终`使用相同的变量名来表示*Controller*对象。这里的所有示例都将使用名称`$controller`。这不是因为名称`$controller`很特别，而是因为在后面的章节中，这种一致性将非常重要。

在这一点上，我们已经成功地将动作逻辑与页面脚本解耦。然而，这种解耦基本上破坏了动作逻辑，因为*Controller*依赖于页面脚本中的变量。

考虑到这一点，我们开始进行抽查和修改循环。我们浏览或以其他方式调用页面脚本，发现特定变量对*Controller*不可用。我们将其添加到`__invoke()`方法签名中，并再次进行抽查。我们继续向`__invoke()`方法添加变量，直到*Controller*拥有所需的一切，我们的抽查运行完全成功。

### 注意

在这个过程的这一部分，最好设置`error_reporting(E_ALL)`。这样我们将得到每个动作逻辑中未初始化变量的 PHP 通知。

在附录 H 中给出了我们重新排列的页面脚本，*Controller 重排后的代码*，我们初始提取到*Controller*的结果可以在附录 I 中看到，*Controller 提取后的代码*。原来提取的动作逻辑需要四个变量：`$request`、`$response`、`$user`和`$article_transactions`。

## 将 Controller 转换为依赖注入并进行抽查。

一旦我们在`__invoke()`方法中有一个可用的动作逻辑块，我们将把方法参数转换为构造函数参数，以便*Controller*可以使用依赖注入。

首先，我们剪切`__invoke()`参数，并将它们整体粘贴到`__construct()`参数中。然后编辑类定义和`__construct()`方法以将参数保留为属性。

接下来，我们修改`__invoke()`方法，使用类属性而不是方法参数。这意味着在每个所需变量前加上`$this->`。

然后，我们回到页面脚本。我们剪切`__invoke()`调用的参数，并将它们粘贴到*Controller*的实例化中。

现在我们已经将*Controller*转换为依赖注入，我们需要再次抽查页面脚本，确保一切正常运行。如果不正常，我们需要撤销并重新进行转换，直到测试通过。

在这一点上，我们可以删除`/* DEPENDENCY */`、`/* CONTROLLER */`和`/* FINISHED */`注释。它们已经达到了它们的目的，不再需要。

鉴于附录 I 中对`__invoke()`的使用，我们可以看到在附录 J 中将*Controller*转换为依赖注入的样子。我们将*Controller*的`__invoke()`参数移到`__construct()`中，将它们保留为属性，在`__invoke()`方法体中使用新属性，并修改页面脚本以在`new`时而不是`__invoke()`时传递所需的变量。

一旦我们有一个可工作的页面脚本，我们可能希望再次提交我们的工作，以便我们有一个已知正确的状态，以便以后可以恢复。

### 编写 Controller 测试

即使我们已经测试了我们的页面脚本，我们仍需要为我们提取的*Controller*逻辑编写单元测试。当我们编写测试时，我们需要将所有所需的依赖项注入到我们的*Controller*中，最好是作为测试替身，如伪造对象或模拟对象，这样我们就可以将*Controller*与系统的其余部分隔离开来。

当我们进行断言时，它们可能应该针对从`__invoke()`方法返回的*Response*对象。我们可以使用`getView()`来确保设置了正确的视图文件，使用`getVars()`来检查要在视图中使用的变量，使用`getLastCall()`来查看最终可调用的（如果有的话）是否已经正确设置。

### 提交，推送，通知 QA

一旦我们通过了单元测试，并且我们对原始页面脚本的测试也通过了，我们就可以提交我们的新代码和测试。然后我们推送到公共存储库，并通知质量保证团队，让他们审查我们的工作。

### Do ... While

现在我们继续下一个包含嵌入式动作逻辑的页面脚本，并重新开始提取过程。当我们所有的页面脚本都使用依赖注入的*Controller*对象时，我们就完成了。

## 常见问题

### 我们可以向 Controller 方法传递参数吗？

在这些示例中，我们从`__invoke()`方法中删除了所有参数。但是，有时我们希望将参数作为最后一刻的信息传递给控制器逻辑。

一般来说，在我们的现代化过程中，我们应该避免这样做。这不是因为这是一种不好的做法，而是因为我们需要在稍后的现代化步骤中对我们的控制器调用具有非常高的一致性水平。最一致的做法是`__invoke()`根本不带参数。

如果我们需要向*Controller*传递额外的信息，我们应该通过构造函数来实现。特别是当我们要传递请求值时。

例如，而不是这样：

```php
**page_script.php**
1 <?php
2 /* DEPENDENCY */
3 // ...
4 $response = new \Mlaphp\Response('/path/to/app/views');
5 $foo_transactions = new \Domain\Foo\FooTransactions(...);
6 $controller = new \Controller\Foo(
7 $response,
8 $foo_transactions
9 );
10
11 /* CONTROLLER */
12 $response = $controller->__invoke('update', $_POST['user_id']);
13
14 /* FINISHED */
15 $response->send();
16 ?>
```

我们可以这样做：

```php
**page_script.php**
1 <?php
2 /* DEPENDENCY */
3 // ...
4 $response = new \Mlaphp\Response('/path/to/app/views');
5 $foo_transactions = new \Domain\Foo\FooTransactions(...);
6 $request = new \Mlaphp\Request($GLOBALS);
7 $controller = new \Controller\Foo(
8 $response,
9 $foo_transactions,
10 $request
11 );
12
13 /* CONTROLLER */
14 $response = $controller->__invoke();
15
16 /* FINISHED */
17 $response->send();
18 ?>
```

`__invoke()`方法体将使用`$this->request->get['item_id']`。

## 一个 Controller 可以有多个动作吗？

在这些示例中，我们的*Controller*对象执行单个动作。但是，通常情况下，页面控制器可能包含多个动作，例如插入和更新数据库记录。

我们首次提取页面脚本中的动作逻辑应该保持代码基本完整，允许使用属性而不是局部变量等。但是，一旦代码在类中，将逻辑拆分为单独的动作方法是完全合理的。然后`__invoke()`方法可以变得不过是一个选择正确动作方法的`switch`语句。如果我们这样做，我们应该确保更新我们的*Controller*测试，并继续抽查页面脚本，以确保我们的更改不会破坏任何东西。

请注意，如果我们创建额外的*Controller*动作方法，我们需要避免从我们的页面脚本中调用它们。为了在稍后的现代化步骤中需要的一致性，`__invoke()`方法应该是页面脚本在其控制器块中调用的唯一*Controller*方法。

## 如果 Controller 包含 include 调用怎么办？

不幸的是，当我们重新排列页面脚本时，我们可能会发现我们的控制器块中仍然有几个`include`调用。（为设置和依赖目的而进行的`include`调用并不是什么大问题，特别是如果它们在每个页面脚本中都是相同的。）

在控制器块中使用`include`调用是我们遗留应用开始时采用的基于包含的架构的遗留物。这是一个特别难以解决的问题。我们希望将动作逻辑封装在类中，而不是在我们`include`它们时立即执行行为的文件中。

目前，我们必须接受在页面脚本的控制器块中使用`include`调用是丑陋但必要的想法。如果需要的话，我们应该避开视线，并将它们与页面脚本中的其余控制器代码一起复制到`Controller`类中。

作为安慰，我们将在下一章解决这些嵌入的`include`调用的问题。

# 回顾和下一步

将动作逻辑提取到*Controllers*层完成了我们遗留应用的一个巨大的现代化目标。现在我们已经建立了一个完整的模型视图控制器系统：模型的领域层，视图的表示层，以及连接两者的控制器层。

我们应该对我们的现代化进展感到非常满意。每个页面脚本中剩下的代码都是其原始形式的阴影。大部分逻辑是创建带有其依赖关系的*Controller*的连接代码。剩下的逻辑在所有页面脚本中都是相同的；它调用*Controller*并发送返回的*Response*对象。

然而，我们需要处理一个重要的遗留物件。为了完成对控制器逻辑的完全提取和封装，我们需要移除在我们的*Controller*类中嵌入的任何剩余的`include`调用。


# 第十二章：替换类中的包含

即使现在我们已经有了模型视图控制器分离，我们的类中可能仍然有许多包含调用。我们希望我们的遗留应用程序摆脱其包含导向遗产的痕迹，仅仅包含一个文件就会导致逻辑被执行。为了做到这一点，我们需要在整个类中用方法调用替换包含调用。

### 注意

在本章的目的是，我们将使用术语包含来覆盖不仅仅是`include`，还包括`require`，`include_once`和`require_once`。

# 嵌入式包含调用

假设我们提取了一些嵌入式`include`的动作逻辑到一个*Controller*方法中。代码接收一个新用户的信息，调用一个`include`来执行一些常见的验证功能，然后处理验证的成功或失败：

```php
**classes/Controller/NewUserPage.php**
1 <?php
2 public function __invoke()
3 {
4 // ...
5 $user = $this->request->post['user'];
6 include 'includes/validators/validate_new_user.php';
7 if ($user_is_valid) {
8 $this->user_transactions->addNewUser($user);
9 $this->response->setVars('success' => true);
10 } else {
11 $this->response->setVars(array(
12 'success' => false,
13 'user_messages' => $user_messages
14 ));
15 }
16
17 return $this->response;
18 }
19 ?>
```

以下是包含文件可能的示例：

```php
includes/validators/validate_new_user.php
1 <?php
2 $user_messages = array();
3 $user_is_valid = true;
4
5 if (! Validate::email($user['email'])) {
6 $user_messages[] = 'Email is not valid.';
7 $user_is_valid = false;
8 }
9
10 if (! Validate::strlen($foo['username'], 6, 8)) {
11 $user_messages[] = 'Username must be 6-8 characters long.';
12 $user_is_valid = false;
13 }
14
15 if ($user['password'] !== $user['confirm_password']) {
16 $user_messages[] = 'Passwords do not match.';
17 $user_is_valid = false;
18 }
19 ?>
```

暂时忽略验证代码的具体内容。这里的重点是`include`文件和使用它的任何代码都紧密耦合在一起。使用该文件的任何代码都必须在包含它之前初始化一个`$user`变量。使用该文件的任何代码也都期望在其范围内引入两个新变量（`$user_messages`和`$user_is_valid`）。

我们希望解耦这个逻辑，使得`include`文件中的逻辑不会侵入其使用的类方法的范围。我们通过将`include`文件的逻辑提取到一个独立的类中来实现这一点。

# 替换过程

提取包含到它们自己的类中的难度取决于我们的类文件中剩余的`include`调用的数量和复杂性。如果包含很少，并且相对简单，那么这个过程将很容易完成。如果有许多复杂的相互依赖的包含，那么这个过程将相对难以完成。

总的来说，这个过程如下：

1.  在一个类中搜索`classes/`目录中的`include`调用。

1.  对于该`include`调用，搜索整个代码库，找出包含的文件被使用的次数。

1.  如果包含的文件只被使用一次，并且只在一个类中使用：

1.  将包含文件的内容直接复制到`include`调用上。

1.  测试修改后的类，并删除包含文件。

1.  重构复制的代码，使其遵循我们现有的所有规则：没有全局变量，没有`new`，注入依赖项，返回而不是输出，没有`include`调用。

1.  如果包含的文件被使用多次：

1.  将包含文件的内容直接复制到一个新的类方法中。

1.  用新类的内联实例化和新方法的调用替换发现的`include`调用。

1.  测试替换了`include`的类，找到耦合的变量；通过引用将这些变量添加到新方法的签名中。

1.  搜索整个代码库，查找对同一文件的`include`调用，并用内联实例化和调用替换每个调用；抽查修改后的文件并测试修改后的类。

1.  删除原始的`include`文件；对整个遗留应用程序进行单元测试和抽查。

1.  为新类编写单元测试，并重构新类，使其遵循我们现有的所有规则：没有全局变量，没有超全局变量，没有`new`，注入依赖项，返回而不是输出，没有包含。 

1.  最后，在我们的每个类文件中，用依赖注入替换新类的每个内联实例化，并在此过程中进行测试。

1.  提交，推送，通知 QA。

1.  重复，直到我们的任何类中都没有`include`调用。

## 搜索包含调用

首先，就像我们在更早的章节中所做的那样，使用我们的项目范围搜索工具来查找`include`调用。在这种情况下，只在`classes/`目录中搜索以下正则表达式：

```php
**^[ \t]*(include|include_once|require|require_once)**

```

这应该给我们一个`classes/`目录中候选`include`调用的列表。

我们选择一个要处理的单个`include`文件，然后搜索整个代码库，查找同一文件的其他包含。例如，如果我们找到了这个候选`include`...

```php
1 <?php
2 require 'foo/bar/baz.php';
3 ?>
```

我们将搜索整个代码库，查找文件名为`baz.php`的`include`调用：

```php
**^[ \t]*(include|include_once|require|require_once).*baz\.php**

```

我们只搜索文件名，因为根据`include`调用的位置不同，相对目录路径可能会指向同一个文件。我们需要确定这些`include`调用中哪些引用了同一个文件。

一旦我们有了我们知道指向同一文件的`include`调用列表，我们就计算包含该文件的调用次数。如果只有一个调用，我们的工作相对简单。如果有多个调用，我们的工作就更复杂了。

## 替换单个 include 调用

如果一个文件作为`include`调用的目标仅被调用一次，删除`include`相对容易。

首先，我们复制整个`include`文件的内容。然后，我们返回到包含`include`的类中，删除`include`调用，并将整个`include`文件的内容粘贴到其位置。

接下来，我们运行该类的单元测试，以确保它仍然正常工作。如果测试失败，我们会感到高兴！我们发现了需要在继续之前纠正的错误。如果测试通过，我们同样会感到高兴，并继续前进。

现在`include`调用已经被替换，文件内容已经成功移植到类中，我们删除`include`文件。它不再需要了。

最后，我们可以返回到包含新移植代码的类文件中。我们根据迄今为止学到的所有规则进行重构：不使用全局变量或超全局变量，不在工厂之外使用`new`关键字，注入所有需要的依赖项，返回值而不是生成输出，以及（递归地）不使用`include`调用。我们一路上运行单元测试，以确保我们不会破坏任何预先存在的功能。

## 替换多个 include 调用

如果一个文件作为多个`include`调用的目标，替换它们将需要更多的工作。

## 将 include 文件复制到类方法中

首先，我们将`include`代码复制到一个独立的类方法中。为此，我们需要选择一个与包含文件目的相适应的类名。或者，我们可以根据包含文件的路径命名类，以便跟踪代码的原始来源。

至于方法名，我们再次选择与`include`代码目的相适应的内容。就个人而言，如果类只包含一个方法，我喜欢将`__invoke()`方法用于此目的。但是，如果最终有多个方法，我们需要为每个方法选择一个合理的名称。

一旦我们选择了一个类名和方法，我们就在正确的文件位置创建新的类，并将`include`代码直接复制到新的方法中。（我们暂时不删除包含文件本身。）

## 替换原始 include 调用

现在我们有了一个要处理的类，我们回到我们在搜索中发现的`include`调用，用新类的内联实例化替换它，并调用新方法。

例如，假设原始调用代码如下：

```php
**Calling Code**
1 <?php
2 // ...
3 include 'includes/validators/validate_new_user.php';
4 // ...
5 ?>
```

如果我们将`include`代码提取到`Validator\NewUserValidator`类作为其`__invoke()`方法体，我们可以用以下代码替换`include`调用：

```php
**Calling Code**
1 <?php
2 // ...
3 $validator = new \Validator\NewUserValidator;
4 $validator->__invoke();
5 // ...
6 ?>
```

### 注意

在类中使用内联实例化违反了我们关于依赖注入的规则之一。我们不希望在工厂类之外使用`new`关键字。我们在这里这样做只是为了便于重构过程。稍后，我们将用注入替换这种内联实例化。

## 通过测试发现耦合的变量

现在我们已经成功地将调用代码与`include`文件解耦，但这给我们留下了一个问题。因为调用代码内联执行了`include`代码，新提取的代码所需的变量不再可用。我们需要将新类方法所需的所有变量传递进去，并在方法完成时使其变量对调用代码可用。

为了做到这一点，我们运行调用`include`的类的单元测试。测试将向我们展示新方法需要哪些变量。然后我们可以通过引用将这些变量传递给方法。使用引用可以确保两个代码块操作的是完全相同的变量，就好像`include`仍然在内联执行一样。这最大程度地减少了我们需要对调用代码和新提取的代码进行的更改数量。

例如，假设我们已经将代码从一个`include`文件提取到了这个类和方法中：

```php
**classes/Validator/NewUserValidator.php**
1 <?php
2 namespace Validator;
3
4 class NewUserValidator
5 {
6 public function __invoke()
7 {
8 $user_messages = array();
9 $user_is_valid = true;
10
11 if (! Validate::email($user['email'])) {
12 $user_messages[] = 'Email is not valid.';
13 $user_is_valid = false;
14 }
15
16 if (! Validate::strlen($foo['username'], 6, 8)) {
17 $user_messages[] = 'Username must be 6-8 characters long.';
18 $user_is_valid = false;
19 }
20
21 if ($user['password'] !== $user['confirm_password']) {
22 $user_messages[] = 'Passwords do not match.';
23 $user_is_valid = false;
24 }
25 }
26 }
27 ?>
```

当我们测试调用这段代码的类时，测试将失败，因为新方法中的`$user`值不可用，并且调用代码中的`$user_messages`和`$user_is_valid`变量也不可用。我们为失败而欢欣鼓舞，因为它告诉我们接下来需要做什么！我们通过引用将每个缺失的变量添加到方法签名中：

```php
**classes/Validator/NewUserValidator.php**
1 <?php
2 public function __invoke(&$user, &$user_messages, &$user_is_valid)
3 ?>
```

然后我们从调用代码将变量传递给方法：

```php
**classes/Validator/NewUserValidator.php**
1 <?php
2 $validator->__invoke($user, $user_messages, $user_is_valid);
3 ?>
```

我们继续运行单元测试，直到它们全部通过，根据需要添加变量。当所有测试都通过时，我们欢呼！所有需要的变量现在在两个范围内都可用，并且代码本身将保持解耦和可测试。

### 注意

提取的代码中并非所有变量都可能被调用代码需要，反之亦然。我们应该让单元测试的失败指导我们哪些变量需要作为引用传递。

## 替换其他包括调用和测试

现在我们已经将原始调用代码与`include`文件解耦，我们需要将所有其他剩余的代码也从同一个文件中解耦。根据我们之前的搜索结果，我们去每个文件，用新类的内联实例化替换相关的`include`调用。然后我们添加一行调用新方法并传入所需的变量。

请注意，我们可能正在替换类中的代码，也可能在视图文件等非类文件中替换代码。如果我们在一个类中替换代码，我们应该运行该类的单元测试，以确保替换不会出现问题。如果我们在一个非类文件中替换代码，我们应该运行该文件的测试（如果存在的话，比如视图文件测试），否则抽查该文件是否存在测试。

## 删除 include 文件并测试

一旦我们替换了所有对该文件的`include`调用，我们就删除该文件。现在我们应该运行所有的测试和抽查整个遗留应用程序，以确保我们没有漏掉对该文件的`include`调用。如果测试或抽查失败，我们需要在继续之前解决它。

### 编写测试和重构

现在遗留应用程序的工作方式与我们将`include`代码提取到自己的类之前一样，我们为新类编写一个单元测试。

一旦我们为新类编写了一个通过的单元测试，我们根据迄今为止学到的所有规则重构该类中的代码：不使用全局变量或超全局变量，不在工厂之外使用`new`关键字，注入所有需要的依赖项，返回值而不是生成输出，以及（递归地）不使用`include`调用。我们继续运行我们的测试，以确保我们不会破坏任何已有的功能。

### 转换为依赖注入并测试

当我们新重构的类的单元测试通过时，我们继续用依赖注入替换所有内联实例化。我们只在我们的类文件中这样做；在我们的视图文件和其他非类文件中，内联实例化并不是什么大问题。

例如，我们可能在一个类中看到这样的内联实例化和调用：

```php
**classes/Controller/NewUserPage.php**
1 <?php
2 namespace Controller;
3
4 class NewUserPage
5 {
6 // ...
7
8 public function __invoke()
9 {
10 // ...
11 $user = $this->request->post['user'];
12
13 $validator = new \Validator\NewUserValidator;
14 $validator->__invoke($user, $user_messages, $u
15
16 if ($user_is_valid) {
17 $this->user_transactions->addNewUser($user
18 $this->response->setVars('success' => true
19 } else {
20 $this->response->setVars(array(
21 'success' => false,
22 'user_messages' => $user_messages
23 ));
24 }
25
26 return $this->response;
27 }
28 }
29 ?>
```

我们将`$validator`移到通过构造函数注入的属性中，并在方法中使用该属性：

```php
**classes/Controller/NewUserPage.php**
1 <?php
2 namespace Controller;
3
4 class NewUserPage
5 {
6 // ...
7
8 public function __construct(
9 \Mlaphp\Request $request,
10 \Mlaphp\Response $response,
11 \Domain\Users\UserTransactions $user_transactions,
12 \Validator\NewUserValidator $validator
13 ) {
14 $this->request = $request;
15 $this->response = $response;
16 $this->user_transactions = $user_transactions;
17 $this->validator = $validator;
18 }
19
20 public function __invoke()
21 {
22 // ...
23 $user = $this->request->post['user'];
24
25 $this->validator->__invoke($user, $user_messages, $user_is_valid);
26
27 if ($user_is_valid) {
28 $this->user_transactions->addNewUser($user);
29 $this->response->setVars('success' => true);
30 } else {
31 $this->response->setVars(array(
32 'success' => false,
33 'user_messages' => $user_messages
34 ));
35 }
36
37 return $this->response;
38 }
39 }
40 ?>
```

现在我们需要搜索代码库，并替换每个修改后的类的实例化以传递新的依赖对象。我们在进行这些操作时运行我们的测试，以确保一切继续正常运行。

### 提交，推送，通知 QA

此时，我们要么替换了单个`include`调用，要么替换了同一文件的多个`include`调用。因为我们一直在测试，现在我们可以提交我们的新代码和测试，将它们全部推送到公共存储库，并通知 QA 我们有新的工作需要他们审查。

### Do ... While

我们再次开始搜索类文件中的下一个`include`调用。当所有的`include`调用都被类方法调用替换后，我们就完成了。

## 常见问题一个类可以从多个 include 文件中接收逻辑吗？

在示例中，我们展示了`include`代码被提取到一个独立的类中。如果我们有许多相关的`include`文件，将它们收集到同一个类中，每个都有自己的方法名，可能是合理的。例如，*NewUserValidator*逻辑可能只是许多与用户相关的验证器之一。我们可以合理地想象将该类重命名为*UserValidator*，并具有诸如`validateNewUser()`、`validateExistingUser()`等方法。

## 那么在非类文件中发起的 include 调用呢？

在寻找`include`调用时，我们只在`classes/`目录中寻找原始调用。很可能还有`include`调用来自其他位置，比如`views/`。

对于我们重构的目的，我们并不特别关心`include`调用是否来自我们类外部。如果一个`include`只从非类文件中调用，我们可以放心地保留该`include`的现有状态。

我们的主要目标是从类文件中删除`include`调用，而不一定是整个遗留应用程序。此时，很可能我们类外的大多数或所有`include`调用都是呈现逻辑的一部分。

# 审查和下一步

在我们从类中提取了所有的 include 调用之后，我们最终删除了遗留架构的最后一个主要部分。我们可以加载一个类而不产生任何副作用，并且逻辑只有在调用方法时才执行。这对我们来说是一个重要的进步。

现在我们可以开始关注我们遗留应用程序的整体架构。

目前为止，整个遗留应用程序仍然位于 Web 服务器文档根目录中。用户直接浏览每个页面脚本。这意味着 URL 与文件系统耦合在一起。此外，每个页面脚本都有相当多的重复逻辑：加载设置脚本，使用依赖注入实例化控制器，调用控制器，并发送响应。

因此，我们下一个主要目标是在我们的遗留应用程序中开始使用前端控制器。前端控制器将由一些引导逻辑、路由器和调度器组成。这将使我们的应用程序与文件系统解耦，并允许我们开始完全删除我们的页面脚本。

但在这样做之前，我们需要将应用程序中的公共资源与非公共资源分开。


# 第十三章：分离公共和非公共资源

在这一点上，我们已经在重新组织我们传统应用程序的核心方面取得了重大进展。然而，周围的架构仍然有很多需要改进的地方。

除其他事项外，我们整个应用程序仍然嵌入在文档根中。这意味着我们需要对我们打算保持私有的资源进行特殊保护，或者我们需要依赖模糊来确保客户不会浏览到不打算公开的资源。Web 服务器配置错误或未注意特定的安全措施可能会将我们的应用程序部分展示给公众。

因此，我们的下一步是将所有公共资源提取到一个新的文档根目录。这将防止非公共资源被意外传送，并为进一步重构建立结构。

# 混合资源

目前，我们的 Web 服务器充当我们传统应用程序的组合前端控制器、路由器和调度器。页面脚本的路由直接映射到文件系统，使用 Web 服务器文档根作为基础。而 Web 服务器文档根又直接映射到传统应用程序的根目录。

例如，如果 Web 服务器文档根是`/var/www/htdocs`，它目前同时充当应用程序根。因此，URL 路径`/foo/bar.php`直接映射到`/var/www/htdocs/foo/bar.php`。

这对于公共资源可能没问题，但我们的应用程序中有很多部分是我们不希望外部直接访问的。例如，与配置和设置相关的目录不应该暴露给可能的外部检查。Web 服务器配置错误可能会暴露代码本身，使我们的密码和其他信息对恶意用户可用。

# 分离过程

尽管过程本身很简单，但我们正在进行的更改是基础性的。它影响了服务器配置以及传统应用程序结构。为了充分实现这一变化，我们需要与负责服务器部署的任何运营人员密切协调。

一般来说，流程如下：

1.  与运营协调以沟通我们的意图。

1.  在我们的传统应用程序中创建一个新的文档根目录，以及一个临时索引文件。

1.  重新配置服务器指向新的文档根目录，并抽查新配置，看看我们的临时索引文件是否出现。

1.  删除临时索引文件，然后将所有公共资源移动到新的文档根，并在此过程中进行抽查。

1.  提交、推送，并与运营协调进行 QA 测试。

## 与运营人员协调

这是整个过程中最重要的一步。我们绝不能在未与负责服务器的人员（我们的运营人员）讨论我们的意图的情况下进行影响服务器配置的更改。

运营的反馈将告诉我们我们需要遵循的路径，以确保我们的更改有效。他们将就新的文档根目录名称和新的服务器配置指令向我们提供建议或指导。他们负责部署应用程序，因此我们希望尽力让他们的工作尽可能轻松。如果运营不满意，那么每个人都会不开心。

或者，如果我们没有运营人员并且负责自己的部署，我们的工作既更容易又更困难。更容易是因为我们没有协调和沟通成本。更困难是因为我们需要特定的、详细的服务器配置知识。在这种情况下要小心进行。

## 创建文档根目录

与我们的运营人员协调后，我们在传统应用程序结构中创建了一个文档根目录。我们的运营联系人将会就适当的目录名称向我们提供建议；在这种情况下，让我们假设该名称是`docroot/`。

例如，如果我们当前有一个遗留的应用程序结构，看起来像这样：

**var/www/htdocs/**

```php
classes/
 ... 
css/
 ... 
foo/
    bar/
        baz.php
images/
 ... 
includes/
 ... 
index.php
js/
tests/
 ... 
views/
 ... 
```

...我们在应用程序的顶层添加一个新的`docroot/`目录。在新的文档根目录中，我们添加一个临时的`index.html`文件。这将让我们以后知道我们的服务器重新配置是否正常工作。它可以包含任何我们喜欢的文本，比如“庆祝！新配置有效！”。

完成后，新的目录结构将更像这样：

**/var/www/htdocs/**

```php
classes/
 ... 
css/
 ... 
docroot/
    index.html
foo/
    bar/
        baz.php
images/
 ... 
includes/
 ... 
index.php
    js/
 ... 
tests/
 ... 
views/
 ... 
```

## 重新配置服务器

我们现在重新配置我们的本地开发网络服务器，指向新的`docroot/`目录。我们的运维人员应该已经给了我们一些关于如何做这件事的指示。

在 Apache 中，我们可能需要编辑我们本地开发环境的配置文件，将相关的`.conf`文件中的`DocumentRoot`指令从主应用程序目录更改为新的目录：

```php
DocumentRoot "/var/www/htdocs"
```

...到我们在应用程序中新创建的子目录：

```php
DocumentRoot "/var/www/htdocs/docroot"
```

然后我们保存文件，并重新加载或重启服务器以应用我们的更改。

### 提示

适用的`DocumentRoot`指令可能在许多位置之一。它可能在主`httpd.conf`文件中，或者作为`VirtualHost`指令的一部分在单独的配置文件中。如果我们使用的不是 Apache，配置可能在一个完全不同的文件中。不幸的是，本书范围之外无法提供完整的 Web 服务器管理说明。请查阅您特定服务器的文档以获取更多信息。

应用我们的配置更改后，我们浏览遗留应用程序，看新的文档根是否被遵守。我们应该看到我们临时的`index.html`文件的内容。如果没有，我们做错了什么，需要重新检查我们的更改，直到它们按预期工作。

## 移动公共资源

现在我们已经配置了 Web 服务器指向我们的新`docroot/`目录，我们可以安全地删除我们的临时`index.html`文件。

这样做之后，我们的下一步是将所有公共资源从它们当前的位置移动到新的`docroot/`目录中。这包括我们所有的页面脚本、样式表、JavaScript 文件、图片等等。不包括任何用户不应该能够浏览到的东西：类、包含文件、设置、配置、命令行脚本、测试、视图文件等等。

我们希望在`docroot/`中保持与在应用程序基础目录中相同的相对位置，因此在移动时不应更改文件名或目录名。

当我们将我们的公共资源移动到新的位置时，我们应该偶尔通过应用程序浏览来检查我们修改后的结构。这将帮助我们及早发现任何问题，而不是晚些时候。

### 提示

我们移动的一些 PHP 文件可能仍然依赖于特定位置的`include`文件。在这些情况下，我们可能需要修改它们，指向相对于我们新的`docroot/`目录的路径。或者，我们可能需要修改我们的包含路径值，以便它们可以找到必要的文件。

完成后，我们将拥有一个看起来更像这样的目录结构：

**/var/www/htdocs/**

```php
classes/
 ... 
docroot/
   css/
       ... 
   foo/
       bar/
          baz.php

   index.php
   js/
     ... 
   images/
     ... 
includes/
    ... 
tests/
    ... 
views/
    ... 
```

## 提交、推送、协调

当我们将所有的公共资源移动到新的`docroot/`目录，并且遗留应用程序在这个新结构中正常工作时，我们提交所有的更改并将它们推送到公共存储库。

在这一点上，我们通常会通知 QA 我们的更改以供测试。然而，因为我们对服务器配置进行了基础性的更改，我们需要与运维人员协调 QA 测试。运维人员可能需要部署新的配置到 QA 服务器。只有这样，QA 才能有效地检查我们的工作。

# 常见问题

## 这真的有必要吗？

大多数时候，将各种非公共资源留在文档根目录似乎是无害的。但对于我们接下来的步骤来说，非常重要的是我们要在我们的公共资源和非公共资源之间有一个分离。

# 审查和下一步操作

我们现在已经开始重构我们遗留应用的总体架构。通过创建一个文档根目录，将我们的公共资源与非公共资源分开，我们可以开始组建一个前端控制器系统来控制对我们应用的访问。


# 第十四章：将 URL 路径与文件路径解耦

尽管我们有一个文档根目录将我们的公共和非公共资源分开，但我们传统应用程序的用户仍然直接浏览我们的页面脚本。这意味着我们的 URL 直接与网络服务器上的文件系统路径耦合。

我们的下一步是解耦路径，这样我们就可以独立地将 URL 路由到任何我们想要的目标。这意味着我们需要建立一个前端控制器来处理我们传统应用程序的所有传入请求。

# 耦合路径

正如我们在上一章中所指出的，我们的网络服务器充当了我们传统应用程序的前端控制器、路由器和调度器的综合功能。页面脚本的路由仍然直接映射到文件系统，使用我们的`docroot/`目录作为所有 URL 路径的基础。

这给我们带来了一些结构性问题。例如，如果我们想公开一个新的或不同的 URL，我们必须修改文件系统中相关页面脚本的位置。同样，我们无法更改哪个页面脚本响应特定的 URL。在路由之前，没有办法拦截传入的请求。

这些以及其他问题，包括完成未来重构的能力，意味着我们必须为所有传入请求创建一个单一入口点。这个入口点被称为前端控制器。

在我们对传统应用程序实现的第一个前端控制器中，我们将添加一个路由器来将传入的 URL 路径转换为页面脚本路径。这将允许我们将页面脚本从文档根目录中移除，从而将 URL 与文件系统解耦。

## 解耦过程

与将我们的公共资源与非公共资源分开一样，我们将不得不对我们的网络服务器配置进行更改。具体来说，我们将启用 URL 重写，以便将所有传入请求指向一个前端控制器。我们需要与我们的运维人员协调这次重构，以便他们能够尽可能轻松地部署这些更改。

一般来说，这个过程如下：

1.  与运维协调以沟通我们的意图。

1.  在文档根目录中创建一个前端控制器脚本。

1.  为我们的页面脚本创建一个`pages/`目录，以及一个`页面未找到`页面脚本和控制器。

1.  重新配置网络服务器以启用 URL 重写。

1.  抽查重新配置的网络服务器，确保前端控制器和 URL 重写正常工作。

1.  将所有页面脚本从`docroot/`移动到`pages/`，并在此过程中进行抽查。

1.  提交、推送，并与运维协调进行 QA 测试。

## 与运维协调

这是整个过程中最重要的一步。我们绝不能在没有与负责服务器的人员（即我们的运维人员）讨论我们意图的情况下进行影响服务器配置的更改。

在这种情况下，我们需要告诉我们的运维人员，我们必须启用 URL 重写。他们将告知或指导我们如何为我们特定的网络服务器执行此操作。

或者，如果我们没有运维人员并且负责我们自己的服务器，我们将需要自行确定如何启用 URL 重写。在这种情况下要小心进行。

### 添加一个前端控制器

一旦我们与运维人员协调好，我们将添加一个前端控制器脚本。我们还将添加一个`页面未找到`脚本、控制器和视图。

首先，在我们的文档根目录中创建前端控制器脚本。它使用`Router`类将传入的 URL 映射到页面脚本。我们称之为 front.php，或者其他表明它是前端控制器的名称：

```php
docroot/front.php
1 <?php
2 // the router class file
3 require dirname(__DIR__) . '/classes/Mlaphp/Router.php';
4
5 // set up the router
6 $pages_dir = dirname(__DIR__) . '/pages';
7 $router = new \Mlaphp\Router($pages_dir);
8
9 // match against the url path
10 $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
11 $route = $router->match($path);
12
13 // require the page script
14 require $route;
15 ?>
```

### 注意

我们`require`了`Router`类文件，因为自动加载程序尚未注册。这只会在执行页面脚本时发生，而这只会在前端控制器逻辑结束时发生。我们将在下一章中解决这个问题。

### 创建一个`pages/`目录

前端控制器引用了一个`$pages_dir`。我们的想法是将所有页面脚本从文档根目录移动到这个新目录中。

首先，在我们的旧应用程序的顶层创建一个`pages/`目录，与`classes/`、`docroot/`、`views/`等目录并列。

然后，我们创建一个`pages/not-found.php`脚本，以及一个相应的控制器和视图文件。当`Router`无法匹配 URL 路径时，前端控制器将调用`not-found.php`脚本。`not-found.php`脚本应该像旧应用程序中的任何其他页面脚本一样设置自己，然后调用相应的视图文件以获取响应：

```php
**pages/not-found.php**
1 <?php
2 require '../includes/setup.php';
3
4 $request = new \Mlaphp\Request($GLOBALS);
5 $response = new \Mlaphp\Response('/path/to/app/views');
6 $controller = new \Controller\NotFound($request, $response);
7
8 $response = $controller->__invoke();
9
10 $response->send();
11 ?>
```

```php
**classes/Controller/NotFound.php**
1 <?php
2 namespace Controller;
3
4 use Mlaphp\Request;
5 use Mlaphp\Response;
6
7 class NotFound
8 {
9 protected $request;
10
11 protected $response;
12
13 public function __construct(Request $request, Response $response)
14 {
15 $this->request = $request;
16 $this->response = $response;
17 }
18
19 public function __invoke()
20 {
21 $url_path = parse_url(
22 $this->request->server['REQUEST_URI'],
23 PHP_URL_PATH
24 );
25
26 $this->response->setView('not-found.html.php');
27 $this->response->setVars(array(
28 'url_path' => $url_path,
29 ));
30
31 return $this->response;
32 }
33 }
34 ?>
```

```php
**views/not-found.html.php**
1 <?php $this->header('HTTP/1.1 404 Not Found'); ?>
2 <html>
3 <head>
4 <title>Not Found</title>
5 </head>
6 <body>
7 <h1>Not Found</h1>
8 <p><?php echo $this->esc($url_path); ?></p>
9 </body>
10 </html>
```

## 重新配置服务器

现在我们已经放置了我们的前端控制器并为我们的页面脚本设置了目标位置，我们重新配置本地开发 Web 服务器以启用 URL 重写。我们的运维人员应该已经给了我们一些关于如何做这个的指示。

### 注意

不幸的是，本书范围之外无法提供有关 Web 服务器管理的完整说明。请查阅您特定服务器的文档以获取更多信息。

在 Apache 中，我们首先启用`mod_rewrite`模块。在某些 Linux 发行版中，这很容易，只需发出`sudo a2enmod` rewrite 命令。在其他情况下，我们需要编辑`httpd.conf`文件以启用它。

一旦启用了 URL 重写，我们需要指示 Web 服务器将所有传入的请求指向我们的前端控制器。在 Apache 中，我们可以向我们的旧应用程序添加一个`docroot/.htaccess`文件。或者，我们可以修改本地开发服务器的 Apache 配置文件之一。重写逻辑如下所示：

```php
**docroot/.htaccess**
1 # enable rewriting
2 RewriteEngine On
3
4 # turn empty requests into requests for the "front.php"
5 # bootstrap script, keeping the query string intact
6 RewriteRule ^$ front.php [QSA]
7
8 # for all files and dirs not in the document root,
9 # reroute to the "front.php" bootstrap script,
10 # keeping the query string intact, and making this
11 # the last rewrite rule
12 RewriteCond %{REQUEST_FILENAME} !-f
13 RewriteCond %{REQUEST_FILENAME} !-d
14 RewriteRule ^(.*)$ front.php [QSA,L]
```

### 注意

例如，如果传入请求是`/foo/bar/baz.php`，Web 服务器将调用`front.php`脚本。这对于每个请求都是如此。各种超全局变量的值将保持不变，因此`$_SERVER['REQUEST_URI']`仍将指示`/foo/bar/baz.php`。

最后，在启用了 URL 重写之后，我们重新启动或重新加载 Web 服务器以使我们的更改生效。

### 抽查

现在我们已经启用了 URL 重写以将所有请求指向我们的新前端控制器，我们应该浏览我们的旧应用程序，使用我们知道不存在的 URL 路径。前端控制器应该显示我们的`not-found.php`页面脚本的输出。这表明我们的更改正常工作。如果不是，我们需要回顾和修改到目前为止的更改，并尝试修复任何出错的地方。

### 移动页面脚本

一旦我们确定 URL 重写和前端控制器正常运行，我们可以开始将所有页面脚本从`docroot/`移动到我们的新`pages/`目录中。请注意，我们只移动页面脚本。我们应该将所有其他资源留在`docroot/`中，包括`front.php`前端控制器。

例如，如果我们开始时有这样的结构：

```php
**/path/to/app/**
docroot/
css/
foo/
bar/
baz.php
front.php
images/
index.php
js/
pages/
not-found.php
```

我们应该最终得到这样的结构：

```php
**/path/to/app/**
docroot/
css/
front.php
images/
js/
pages/
foo/
bar/
baz.php
index.php
not-found.php
```

我们只移动了页面脚本。图像、CSS 文件、Javascript 文件和前端控制器都保留在`docroot/`中。

因为我们在移动文件，我们可能需要更改我们的包含路径值，以指向新的相对目录位置。

当我们将每个文件或目录从`docroot/`移动到`pages/`时，我们应该抽查我们的更改，以确保旧应用程序继续正常工作。

由于之前描述的重写规则，我们的页面脚本应该继续工作，无论它们是在`docroot/`还是`pages/`中。我们要确保在继续之前将所有页面脚本移动到`pages/`中。

### 提交、推送、协调

当我们将所有页面脚本移动到新的`pages/`目录，并且我们的旧应用程序在这个新结构中正常工作时，我们提交所有更改并将它们推送到共同的存储库。

在这一点上，我们通常会通知质量保证部门我们的更改，让他们进行测试。然而，由于我们对服务器配置进行了更改，我们需要与运营人员协调质量保证测试。运营部门可能需要部署新配置到质量保证服务器上。只有这样，质量保证部门才能有效地检查我们的工作。

## 常见问题

### 我们真的解耦了路径吗？

敏锐的观察者会注意到我们的*Router*仍然使用传入的 URL 路径来查找页面脚本。这与原始设置之间的唯一区别是，路径被映射到`pages/`目录而不是`docroot/`目录。毕竟，我们真的将 URL 与文件系统解耦了吗？

是的，我们已经实现了我们的解耦目标。这是因为我们现在在 URL 路径和执行的页面脚本之间有一个拦截点。使用*Router*，我们可以创建一个路由数组，其中 URL 路径是键，文件路径是值。该映射数组将允许我们将传入的 URL 路径路由到任何我们喜欢的页面脚本。

例如，如果我们想将 URL 路径`/foo/bar.php`映射到页面脚本`/baz/dib.php`，我们可以通过*Router*上的`setRoutes()`方法来实现：

```php
1 $router->setRoutes(array(
2 '/foo/bar.php' => '/baz/dib.php',
3 ));
```

然后，当我们将传入的 URL 路径`/foo/bar.php`与*Router*进行`match()`时，我们返回的路由将是`/baz/dib.php`。然后我们可以执行该路由作为传入 URL 的页面脚本。我们将在下一章节中使用这种技术的变体。

# 回顾和下一步

通过将 URL 与页面脚本解耦，我们几乎已经完成了我们的现代化工作。只剩下两个重构。首先，我们将重复的逻辑从页面脚本移到前端控制器。然后我们将完全删除页面脚本，并用依赖注入容器替换它们。


# 第十五章：删除页面脚本中的重复逻辑

现在，我们的页面脚本中的逻辑非常重复。它们看起来都非常相似。每个页面加载一个设置脚本，为页面控制器实例化一系列依赖项，调用该控制器，并发送响应。

我们的前端控制器为我们提供了一个地方，可以执行每个页面脚本的通用元素并消除重复。一旦重复被移除，我们就可以开始消除页面脚本本身。

# 重复的逻辑

实质上，我们的每个页面脚本都遵循这个组织流程：

```php
**Generic Page Script**
1 <?php
2 // one or more identical setup scripts
3 require 'setup.php';
4
5 // a series of dependencies to build a controller
6 $request = new \Mlaphp\Request($GLOBALS);
7 $response = new \Mlaphp\Response('/path/to/app/views');
8 $controller = new \Controller\PageName($request, $response);
9
10 // invoke the controller and send the response
11 $response = $controller->__invoke();
12 $response->send();
13 ?>
```

因为我们一直都很勤奋地使用相同的变量名来表示我们的控制器对象（`$controller`），始终使用相同的方法名来调用它（`__invoke()`），并且始终使用相同的变量名来表示响应（`$response`），我们可以看到每个页面脚本唯一不同的部分是中心部分。中心块构建了控制器对象。之前和之后的一切都是相同的。

此外，因为我们有一个前端控制器来处理所有传入的请求，现在我们有一个地方可以放置每个页面脚本的通用前后逻辑。这就是我们要做的。

## 移除过程

一般来说，移除过程如下：

1.  修改前端控制器以添加设置、控制器调用和响应发送。

1.  修改每个页面脚本以删除设置、控制器调用和响应发送。

1.  检查，提交，推送，并通知 QA。

## 修改前端控制器

首先，我们修改前端控制器逻辑，执行每个页面脚本通用的逻辑。我们将其从上一章中列出的代码更改为以下内容：

```php
**docroot/front.php**
1 <?php
2 // page script setup
3 require dirname(__DIR__) . '/includes/setup.php';
4
5 // set up the router
6 $pages_dir = dirname(__DIR__) . '/pages';
7 $router = new \Mlaphp\Router($pages_dir);
8
9 // match against the url path
10 $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
11 $route = $router->match($path);
12
13 // require the page script
14 require $route;
15
16 // invoke the controller and send the response
17 $response = $controller->__invoke();
18 $response->send();
19 ?>
```

我们已经用一个需要`Router`类文件的行替换了一个需要设置脚本的行。（在自动加载的章节中，我们将自动加载器放入了我们的设置脚本中，所以现在它应该为我们自动加载`Router`类。）

我们还在页面脚本中需要`$route`文件后添加了两行。这些行调用了控制器并设置了响应。我们在这个共享逻辑中使用了控制器和响应对象的通用变量名。（如果你在页面脚本中选择了除`$controller`和`$response`之外的其他变量名，也请在上面的脚本中替换它们。同样，如果你使用了除`__invoke()`之外的通用控制器方法，请也替换它。）

### 注意

请注意，设置工作将是特定于我们的旧应用程序。只要每个页面脚本的设置工作都是相同的（在这一点上应该是这样），将通用设置工作放在这里就可以了。

## 从页面脚本中删除逻辑

现在我们已经将设置、控制器调用和响应发送工作添加到前端控制器中，我们可以从每个页面脚本中删除相同的工作。这样做应该就像在`pages/`目录中进行项目范围的搜索并删除找到的行一样简单。

找到设置行可能需要使用正则表达式，因为设置脚本的相对位置可能导致使用相对目录遍历的行。以下正则表达式将找到`includes/setup.php`，`../includes/setup.php`，`dirname(__DIR__)` . `/includes/setup.php`等：

搜索设置：

```php
**1 ^\s*(require|require_once|include|include_once) .*includes/setup\.php.*$**

```

然而，找到控制器调用和响应发送行不应该需要使用正则表达式，因为它们在每个页面脚本中应该是相同的。

搜索控制器调用…

```php
**1 $response = $controller->__invoke();**

```

搜索响应发送…

```php
**1 $response->send();**

```

在每种情况下，删除找到的行。现在这些逻辑已经移动到前端控制器中，不再需要。

## 检查，提交，推送，并通知 QA

一旦重复的页面脚本逻辑被移除，我们可以通过运行特性测试或浏览或以其他方式调用应用程序中的每个页面来检查应用程序。

在确保应用程序仍然正常工作之后，我们提交新代码并将其推送到公共存储库。然后我们通知质量保证部门，我们有新的工作需要他们审查。

## 常见问题

### 如果设置工作不一致会怎么样？

在本书的示例中，我们只展示了一个脚本为每个页面脚本做设置工作。一些传统应用程序可能使用多个设置脚本。只要设置工作在每个页面脚本中是相同的，即使它由多个脚本组成，我们也可以将所有设置工作移动到前端控制器中。

然而，如果设置工作在每个页面脚本中不一致，我们就有问题要处理。如果在这一点上，页面脚本的设置过程不相同，我们应该在继续之前尽力解决这个问题。

在所有页面脚本中使设置工作相同是至关重要的。这可能意味着在前端控制器中包含所有页面脚本的不同设置工作，即使有些脚本不需要所有这些设置工作。如果必要，我们可以在下一章解决这种重叠。

如果我们无法强制执行相同的单阶段设置过程，我们可能需要进行双阶段或两阶段设置过程。首先，我们将常见的设置工作合并到前端控制器中，并将其从页面脚本中删除。多余的、特殊情况或特定页面的设置工作可以作为依赖项创建工作的退化但必要的部分留在页面脚本中。

### 如果我们使用了不一致的命名？

在前几章中，本书强调了一致命名的重要性。这一章是一致性得到回报的时刻。

如果我们发现在控制器对象变量和/或控制器方法名称的命名上不一致，也不是没有办法。我们可能无法进行一次性搜索和替换，但我们仍然可以手动处理每个页面脚本，并将名称更改为一致。然后前端控制器可以使用新的一致名称。

# 审查和下一步

通过这一步，我们将页面脚本减少到了一个基本的逻辑核心。现在它们所做的就是为控制器对象设置依赖项，然后创建控制器对象。前端控制器在此之前和之后都做了一切。

事实上，即使这个逻辑也可以从页面脚本中提取出来。一个称为依赖注入容器的对象可以接收对象创建逻辑作为一系列闭包，每个页面脚本一个闭包。容器可以为我们处理对象创建，我们可以完全删除页面脚本。

因此，我们最终的重构将把所有对象创建逻辑提取到一个依赖注入容器中。我们还将修改我们的前端控制器，实例化控制器对象，而不是要求页面脚本。这样做，我们将删除所有页面脚本，我们的应用程序将拥有一个完全现代化的架构。


# 第十六章：添加依赖注入容器

我们已经完成了现代化过程的最后一步。我们将通过将剩余逻辑移入依赖注入容器来删除页面脚本的最后痕迹。容器将负责协调应用程序中的所有对象创建活动。这样做，我们将再次修改我们的前端控制器，并开始添加指向控制器类而不是文件路径的路由。

### 注意

在现代化过程的最后一步中，最好安装 PHP 5.3 或更高版本。这是因为我们需要闭包来实现应用程序逻辑的关键部分。如果我们没有访问 PHP 5.3，还有一种不太可行但仍然可行的选项来实现依赖注入容器。我们将在本章的“常见问题”中解决这种情况。

# 什么是依赖注入容器？

依赖注入作为一种技术，是我们从本书的早期就开始练习的。重申一下，依赖注入的理念是将依赖从外部推入对象。这与通过 new 关键字在类内部创建依赖对象，或者通过`globals`关键字从当前范围外部引入依赖的做法相反。

### 注意

要了解控制反转的概述以及具体的依赖注入，请阅读 Fowler 在[`martinfowler.com/articles/injection.html`](http://martinfowler.com/articles/injection.html)上关于容器的文章。

为了完成我们的依赖注入活动，我们一直在页面脚本中手动创建必要的对象。对于任何需要依赖的对象，我们首先创建了该依赖，然后创建了依赖它的对象并传入依赖。这个创建过程有时会非常复杂，比如当依赖有依赖时。无论复杂程度和深度如何，目前做法的逻辑都嵌入在页面脚本中。

依赖注入容器的理念是将所有对象创建逻辑放在一个地方，这样我们就不再需要使用页面脚本来设置我们的对象。我们可以将每个对象创建逻辑放在容器中，使用一个唯一的名称，称为服务。

然后我们可以告诉容器返回任何定义的服务对象的新实例。或者，我们可以告诉容器创建并返回该服务对象的共享实例，这样每次获取它时，它都是同一个实例。精心组合容器服务的新实例和共享实例将允许我们简化依赖创建逻辑。

### 注意

在任何时候，我们都不会将容器传递给需要依赖的任何对象。这样做将使用一种称为服务定位器的模式。我们避免服务定位器活动，因为这样做违反了范围。当容器在一个对象内部，并且该对象使用它来检索依赖时，我们只是离我们开始的地方一步之遥；也就是说，使用`global`关键字。因此，我们不会传递容器 -- 它完全留在创建对象的范围之外。

PHP 领域中有许多不同的容器实现，每种实现都有其自身的优势和劣势。为了使事情与我们的现代化过程相适应，我们将使用*Mlaphp\Di*。这是一个精简的容器实现，非常适合我们的过渡需求。

## 添加 DI 容器

一般来说，添加 DI 容器的过程如下：

1.  添加一个新的`services.php`包含文件来创建容器并管理其服务。

1.  在容器中定义一个`router`服务。

1.  修改前端控制器以包含`services.php`文件并使用`router`服务，然后对应用程序进行抽查。

1.  从每个页面脚本中提取创建逻辑到容器中：

1.  在容器中为页面脚本控制器类命名一个服务。

1.  将页面脚本中的逻辑复制到容器服务中。根据需要重命名变量以使用 DI 容器属性。

1.  将页面 URL 路径路由到容器服务名称（即控制器名称）。

1.  检查并提交更改。

1.  继续，直到所有页面脚本都已提取到容器中。

1.  删除空的`pages/`目录，提交，推送，并通知 QA。

## 添加 DI 容器包含文件

为了防止我们现有的设置文件变得更大，我们将引入一个新的`services.php`设置文件。是的，这意味着在前端控制器中添加另一个`include`，但是如果我们一直很勤奋，我们的应用程序中几乎没有剩余的`include`。这个`include`的重要性将会很小。

首先，我们需要选择一个适当的位置放置文件。最好是与我们已有的任何其他设置文件一起，可能是在现有的`includes/`目录中。

然后我们创建了以下行的文件。（随着我们的继续，我们将在这个文件中添加更多内容。）因为这个文件将作为我们设置文件的最后一个加载，我们可以假设自动加载将会生效，所以没有必要加载`Di`类文件：

```php
**includes/services.php**
1 <?php
2 $di = new \Mlaphp\Di($GLOBALS);
3 ?>
```

结果是新的`$di`实例加载了所有现有的全局变量值。这些值作为容器的属性被保留。例如，如果我们的设置文件创建了一个`$db_user`变量，现在我们还可以通过`$di->db_user`访问该值。这些是副本，而不是引用，因此对一个的更改不会影响另一个。

### 注意

**为什么我们保留现有变量作为属性？**

目前，我们的页面脚本直接访问全局变量来进行创建工作。然而，在后续步骤中，创建逻辑将不再在全局范围内。它将在 DI 容器中。因此，我们将 DI 容器填充了原本可以使用的变量的副本。

### 添加一个路由器服务

现在我们已经有了一个 DI 容器，让我们添加我们的第一个服务。

回想一下，DI 容器的目的是为我们创建对象。目前，前端控制器创建了一个*Router*对象，因此我们将在容器中添加一个`router`服务。（在下一步中，我们将让前端控制器使用这个服务，而不是自己创建一个*Router*。）

在`services.php`文件中，添加以下行：

```php
**includes/services.php**
1 <?php
2 // set a container service for the router
3 $di->set('router', function () use ($di) {
4 $router = new \Mlaphp\Router('/path/to/app/pages');
5 $router->setRoutes(array());
6 return $router;
7 });
8 ?>
```

让我们稍微检查一下服务定义。

+   服务名称是`router`。我们将用全小写名称来命名那些预期作为共享实例创建的服务对象，并使用完全限定的类名来命名那些预期每次创建新实例的服务对象。因此，在这种情况下，我们的意图是通过容器只提供一个共享的`router`。（这是一个约定，而不是容器强制执行的规则。）

+   服务定义是一个可调用的。在这种情况下，它是一个闭包。闭包不接收任何参数，但它确实使用了当前作用域中的`$di`对象。这使得定义代码可以在构建服务对象时访问容器属性和其他容器服务。

+   我们创建并返回由服务名称表示的对象。我们不需要检查对象是否已经存在于容器中；如果我们要求一个共享实例，容器内部将为我们执行这项工作。

有了这段代码，容器现在知道如何创建一个`router`服务。这是一个懒加载的代码，只有当我们调用`$di->newInstance()`（获取服务对象的新实例）或者`$di->get()`（获取服务对象的共享实例）时才会执行。

### 修改前端控制器

现在我们有了一个 DI 容器和一个`router`服务定义，我们修改前端控制器来加载容器并使用`router`服务。

```php
docroot/front.php
1 <?php
2 require dirname(__DIR__) . '/includes/setup.php';
3 require dirname(__DIR__) . '/includes/services.php';
4
5 // get the shared router service
6 $router = $di->get('router');
7
8 // match against the url path
9 $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
10 $route = $router->match($path);
11
12 // container service, or page script?
13 if ($di->has($route)) {
14 // create a new $controller instance
15 $controller = $di->newInstance($route);
16 } else {
17 // require the page script
18 require $route;
19 }
20
21 // invoke the controller and send the response
22 $response = $controller->__invoke();
23 $response->send();
24 ?>
```

我们从之前的实现中做了以下更改：

+   我们在设置包含的最后添加了对`services.php`容器文件的`require`。

+   我们不直接创建*Router*对象，而是从`$di`容器中`get()`一个共享实例的`router`服务对象。

+   我们已经在调度逻辑上做了一些更改。在我们从`$router`获取`$route`之后，我们检查看看`$di`容器是否`has()`匹配的服务。如果是，它将`$route`视为新`$controller`实例的服务名称；否则，它将`$route`视为在`pages/`中创建`$controller`的文件。无论哪种方式，代码都会调用控制器并发送响应。

在这些更改之后，我们会抽查应用程序，以确保新的`router`服务能够正常工作。如果不能正常工作，我们会撤消并重做到这一点，直到应用程序像以前一样正常工作。

一旦应用程序正常工作，我们可能希望提交我们的更改。这样，如果将来的更改出现问题，我们就有一个已知工作状态可以恢复。

### 将页面脚本提取到服务中

现在是现代化我们的遗留应用程序的最后一步。我们将逐个删除页面脚本，并将它们的逻辑放入容器中。

#### 创建一个容器服务

选择任何页面脚本，并确定它使用哪个类来创建其`$controller`实例。然后，在 DI 容器中，为该类名创建一个空的服务定义。

例如，如果我们有这个页面脚本：

```php
**pages/articles.php**
1 <?php
2 $db = new Database($db_host, $db_user, $db_pass);
3 $articles_gateway = new ArticlesGateway($db);
4 $users_gateway = new UsersGateway($db);
5 $article_transactions = new ArticleTransactions(
6 $articles_gateway,
7 $users_gateway
8 );
9 $response = new \Mlaphp\Response('/path/to/app/views');
10 $controller = new \Controller\ArticlesPage(
11 $request,
12 $response,
13 $user,
14 $article_transactions
15 );
16 ?>
```

我们实例化的控制器类是`Controller\ArticlesPage`。在我们的`services.php`文件中，我们创建了一个空的服务定义：

```php
**includes/services.php**
1 <?php
2 $di->set('Controller\ArticlesPage', function () use ($di) {
3 });
4 ?>
```

接下来，我们将页面脚本设置逻辑移到服务定义中。当我们这样做时，我们应该注意到我们期望从全局范围获得的任何变量，并使用`$di->`前缀来引用适当的容器属性。（回想一下，这些是在`services.php`文件的早期从`$GLOBALS`加载的。）我们还在定义的最后返回控制器实例。

完成后，服务定义将看起来像这样：

```php
**includes/services.php**
1 <?php
2 $di->set('Controller\ArticlesPage', function () use ($di) {
3 // replace `$variables` with `$di->` properties
4 $db = new Database($di->db_host, $di->db_user, $di->db_pass);
5 // create dependencies
6 $articles_gateway = new ArticlesGateway($db);
7 $users_gateway = new UsersGateway($db);
8 $article_transactions = new ArticleTransactions(
9 $articles_gateway,
10 $users_gateway
11 );
12 $response = new \Mlaphp\Response('/path/to/app/views');
13 // return the new instance
14 return new \Controller\ArticlesPage(
15 $request,
16 $response,
17 $user,
18 $article_transactions
19 );
20 });
21 ?>
```

一旦我们将逻辑复制到容器中，我们就从`pages/`中删除原始页面脚本文件。

#### 将 URL 路径路由到容器服务

现在我们已经删除了页面脚本，转而使用容器服务，我们需要确保*Router*指向容器服务，而不是现在缺失的页面脚本。我们通过向`setRoutes()`方法参数添加一个数组元素来实现这一点，其中键是 URL 路径，值是服务名称。

例如，如果 URL 路径是`/articles.php`，我们的新容器服务命名为`Controller\ArticlesPage`，我们将修改我们的`router`服务如下：

```php
**includes/services.php**
1 <?php
2 // ...
3 $di->set('router', function () use ($di) {
4 $router = new \Mlaphp\Router($di->pages_dir);
5 $router->setRoutes(array(
6 // add a route that points to a container service name
7 '/articles.php' => 'Controller\ArticlesPage',
8 ));
9 return $router;
10 });
11 ?>
```

#### 抽查和提交

最后，我们检查页面脚本转换为容器服务是否按我们的预期工作。我们通过浏览或以其他方式调用 URL 路径来抽查旧页面脚本。如果它起作用，那么我们知道容器服务已成功取代现在已删除的页面脚本。

如果不是，我们需要撤消并重做我们的更改，看看哪里出了问题。我在这里看到的最常见的错误是：

+   未能将页面脚本中的`$var`变量替换为服务定义中的`$di->var`属性

+   未能从服务定义中返回对象

+   控制器服务名称与映射的路由值之间的不匹配

一旦我们确定应用程序将 URL 路由到新的容器服务，并且服务正常工作，我们就提交我们的更改。

### 做...直到

我们继续下一个页面脚本，并重新开始这个过程。当所有页面脚本都转换为容器服务然后被删除时，我们就完成了。

### 删除 pages/，提交，推送，通知 QA

在我们将所有页面脚本提取到 DI 容器之后，`pages/`目录应该是空的。我们现在可以安全地将其删除。

有了这个，我们提交我们的工作，推送到共同的存储库，并通知 QA 我们有新的更改需要他们审查。

## 常见问题

### 我们如何完善我们的服务定义？

当我们完成将对象创建逻辑提取到容器后，每个服务定义可能会变得相当长，而且可能重复。我们可以通过进一步将对象创建逻辑的每个部分提取到自己的服务中来减少重复并完善服务定义，使其变得简短而简洁。

例如，如果我们有几个服务使用*Request*对象，我们可以将对象创建逻辑提取到自己的服务中，然后在其他服务中引用该服务。我们可以命名它以显示我们的意图，即它可以被用作共享服务（`request`）或新实例（`Mlaphp\Request`）。其他服务可以使用`get()`或`newInstance()`而不是在内部创建请求。

考虑到我们之前的`Controller\ArticlesPage`服务，我们可以将其拆分为几个可重用的服务，如下所示：

```php
includes/services.php
1 <?php
2 // ...
3
4 $di->set('request', function () use ($di) {
5 return new \Mlaphp\Request($GLOBALS);
6 });
7
8 $di->set('response', function () use ($di) {
9 return new \Mlaphp\Response('/path/to/app/views');
10 });
11
12 $di->set('database', function () use ($di) {
13 return new \Database(
14 $di->db_host,
15 $di->db_user,
16 $di->db_pass
17 );
18 });
19
20 $di->set('Domain\Articles\ArticlesGateway', function () use ($di) {
21 return new \Domain\Articles\ArticlesGateway($di->get('database'));
22 });
23
24 $di->set('Domain\Users\UsersGateway', function () use ($di) {
25 return new \Domain\Users\UsersGateway($di->get('database'));
26 });
27
28 $di->set('Domain\Articles\ArticleTransactions', function () use ($di) {
29 return new \Domain\Articles\ArticleTransactions(
30 $di->newInstance('Domain\Articles\ArticlesGateway'),
31 $di->newInstance('Domain\Users\UsersGateway'),
32 );
33 });
34
35 $di->set('Controller\ArticlesPage', function () use ($di) {
36 return new \Controller\ArticlesPage(
37 $di->get('request'),
38 $di->get('response'),
39 $di->user,
40 $di->newInstance('Domain\Articles\ArticleTransactions')
41 );
42 });
43 ?>
```

注意`Controller\ArticlesPage`服务现在引用容器中的其他服务来构建自己的对象。当我们获得`Controller\ArticlesPage`服务对象的新实例时，它会访问`$di`容器以获取共享的请求和响应对象、`$user`属性以及*ArticleTransactions*服务对象的新实例。这反过来又会递归地访问`$di`容器以获取该服务对象的依赖关系，依此类推。

### 如果页面脚本中有包含文件怎么办？

尽管我们已经尽力删除它们，但我们的页面脚本中可能仍然存在一些包含文件。当我们将页面脚本逻辑复制到容器时，我们别无选择，只能一并复制它们。然而，一旦我们所有的页面脚本都转换为容器，我们就可以寻找共同点，并开始将包含逻辑提取到设置脚本或单独的类中（如果需要，这些类本身可以成为服务）。

### 我们能减小 services.php 文件的大小吗？

根据我们应用程序中页面脚本的数量，我们的 DI 容器可能会有数十个或数百个服务定义。这可能会使单个文件难以管理或浏览。

如果愿意，将容器拆分为多个文件，并使`services.php`成为包含各种定义的一系列调用也是完全合理的。

### 我们能减小 router 服务的大小吗？

作为 DI 容器文件长度的子集，`router`服务特别可能会变得非常长。这是因为我们将应用程序中的每个 URL 映射到一个服务；如果有数百个 URL，就会有数百行`router`。

作为一种替代方案，我们可以创建一个单独的`routes.php`文件，并让它返回一个路由数组。然后我们可以在`setRoutes()`调用中包含该文件：

```php
**includes/routes.php**
1 <?php return array(
2 '/articles.php' => 'Controller\ArticlesPage',
3 ); ?>
```

```php
**includes/services.php**
1 <?php
2 // ...
3 $di->set('router', function () use ($di) {
4 $router = new \Mlaphp\Router($di->pages_dir);
5 $router->setRoutes(include '/path/to/includes/routes.php');
6 return $router;
7 });
8 ?>
```

至少这将减小`services.php`文件的大小，尽管它并不会减小路由数组的大小。

### 如果我们无法升级到 PHP 5.3 怎么办？

本章的示例显示了一个使用闭包封装对象创建逻辑的 DI 容器。闭包只在 PHP 5.3 中才可用，因此如果我们卡在较早版本的 PHP 上，使用 DI 容器似乎根本不是一个选择。

事实证明这并不正确。通过一些额外的努力和更大的容忍度，我们仍然可以为 PHP 5.2 及更早版本构建 DI 容器。

首先，我们需要扩展 DI 容器，以便我们可以向其添加方法。然后，我们不再将服务定义为闭包，而是将它们创建为我们扩展容器上的方法：

```php
**classes/Di.php**
1 <?php
2 class Di extends \Mlaphp\Di
3 {
4 public function database()
5 {
6 return new \Database(
7 $this->db_host,
8 $this->db_user,
9 $this->db_pass
10 );
11 }
12 }
13 ?>
```

（注意我们在方法中使用`$this`而不是`$di`。）

然后在我们的`services.php`文件中，可调用的内容变成了对这个方法的引用，而不是内联闭包。

```php
**includes/services.php**
1 <?php
2 $di->set('database', array($di, 'database'));
3 ?>
```

这有些混乱但可行。它也可能变得非常冗长。我们之前将`Controller\ArticlesPage`拆分的示例最终看起来更像这样：

```php
**includes/services.php**
1 <?php
2 // ...
3 $di->set('request', array($di, 'request'));
4 $di->set('response', array($di, 'response'));
5 $di->set('database', array($di, 'database'));
6 $di->set('Domain\Articles\ArticlesGateway', array($di, 'ArticlesGateway'));
7 $di->set('Domain\Users\UsersGateway', array($di, 'UsersGateway'));
8 $di->set(
9 'Domain\Articles\ArticleTransactions',
10 array($di, 'ArticleTransactions')
11 );
12 $di->set('Controller\ArticlesPage', array($di, 'ArticlesPage'));
13 ?>
```

```php
**classes/Di.php**
1 <?php
2 class Di extends \Mlaphp\Di
3 {
4 public function request()
5 {
6 return new \Mlaphp\Request($GLOBALS);
7 }
8
9 public function response()
10 {
11 return new \Mlaphp\Response('/path/to/app/views');
12 }
13
14 public function database()
15 {
16 return new \Database(
17 $this->db_host,
18 $this->db_user,
19 $this->db_pass
20 );
21 }
22
23 public function ArticlesGateway()
24 {
25 return new \Domain\Articles\ArticlesGateway($this->get('database'));
26 }
27
28 public function UsersGateway()
29 {
30 return new \Domain\Users\UsersGateway($this->get('database'));
31 }
32
33 public function ArticleTransactions()
34 {
35 return new \Domain\Articles\ArticleTransactions(
36 $this->newInstance('ArticlesGateway'),
37 $this->newInstance('UsersGateway'),
38 );
39 }
40
41 public function ArticlesPage()
42 {
43 return new \Controller\ArticlesPage(
44 $this->get('request'),
45 $this->get('response'),
46 $this->user,
47 $this->newInstance('ArticleTransactions')
48 );
49 }
50 }
51 ?>
```

不幸的是，为了使服务名称看起来像它们相关的方法名称，我们可能不得不打破一些我们的风格约定。我们还必须将用于新实例的服务方法名称缩短为它们的结束类名，而不是它们的完全限定名称。否则，我们会发现自己有着过长和令人困惑的方法名称。

这可能会很快让人困惑，但它确实有效。总的来说，如果我们能升级到 PHP 5.3 或更高版本，那真的会更好。

# 回顾和下一步

我们终于完成了现代化的过程。我们不再有任何页面脚本。我们所有的应用逻辑都已转换为类，剩下的唯一包含文件是引导和设置过程的一部分。我们所有的对象创建逻辑都存在于一个容器中，我们可以直接修改它，而不必干扰我们对象的内部。

在这之后可能的下一步是什么呢？答案是持续改进，这将持续到你的职业生涯的最后。


# 第十七章：结论

让我们回顾一下我们的进展。

我们开始时是一个混乱的遗留应用程序。整个应用程序都基于文档根目录，并且用户直接浏览到页面脚本。它使用了一个包含导向的架构，仅仅包含一个文件就会导致逻辑被执行。全局变量随处可见，这使得调试变得困难甚至不可能。没有任何测试，更不用说单元测试，所以每次更改都可能导致其他地方出现问题。模型、视图和控制器层没有明确的分离。SQL 语句嵌入在我们的代码中，领域逻辑与展示和行为逻辑混在一起。

现在，在经过大量的努力、奉献和承诺之后，我们已经现代化了我们的遗留应用程序。文档根目录只包含公共资源和一个前端控制器。所有页面脚本都被分解成单独的模型、视图和控制器层。这些层由一系列良好结构的类表示，每个类都有自己的一套单元测试。应用程序对象是在依赖注入容器内构建的，使它们的操作与它们的创建分开。

还有什么可以做的吗？

# 改进机会

即使我们已经现代化了我们的应用程序，它仍然不完美。坦率地说，它将永远不会完美（无论这意味着什么）。总会有一些机会来改进它。事实上，现代化过程本身已经为我们揭示了许多机会。

+   数据源层由一系列网关组成。虽然它们现在很好地满足了我们的目的，但将这些重组为与我们的领域对象更清晰地交互的数据映射器可能更好。

+   领域层建立在事务脚本之上。这些也都有它们自己的好处，但在使用它们时，我们可能会意识到它们对我们的需求来说是不够的。它们将我们的领域逻辑的太多方面结合到了单块的类和方法中。我们可能会希望开始将我们的领域逻辑的不同方面分离出来，形成一个领域模型，并用一系列服务层来包装它。

+   展示层仍然相对来说是单块的。我们可能希望将我们的视图文件转换为一个两步视图系统。这将为我们提供一个统一的布局，提供一系列可重用的“部分”模板，并帮助我们将每个视图文件减少到其核心部分。

+   我们的控制器可能作为遗留架构的产物处理了几个不相关的操作。我们可能希望重新组织它们，以便更快地理解。事实上，每个控制器可能做的工作太多了（即一个臃肿的控制器而不是一个精简的控制器），这些工作可能更好地由辅助类或服务层来处理。

+   响应系统将内容构建与 HTTP 响应构建的问题结合在一起。我们可能希望重构整个响应发送过程为两个或更多个单独的层：一个处理响应主体，一个处理响应头。事实上，我们可能希望将响应表示为数据传输对象，描述我们的意图，但将实际的响应构建和发送交给一个单独的处理程序。

+   路由系统肯定是过渡性的。我们可能仍然依赖 URL 中的查询参数将客户端请求信息传递到应用程序中，而不是使用“美化的 URL”，其中参数被表示为路径信息的一部分。路由本身仅描述要调用的类，并没有携带应用程序应执行的动作的太多信息。我们将希望用更强大的路由器替换这个基本的路由器。

+   前端控制器充当我们的调度器，而不是将路由分发交给一个单独的对象。我们可能希望将发现路由信息的任务与分发该路由的任务分开。

+   最后，我们的依赖注入容器在本质上是非常“手动”的。我们可能希望找到一个能自动化一些对象创建的基本方面的容器系统，这样我们就可以集中精力解决服务定义的更复杂方面。

换句话说，我们面临的是现代代码库的问题，而不是遗留代码库的问题。我们已经将一个混乱的低质量问题换成了一个自动加载、依赖注入、单元测试、层分离、前端控制的高质量问题。

因为我们已经现代化了我们的代码库，我们可以以完全不同的方式解决这些问题，而不是在遗留体系下所做的。我们可以利用重构工具来改进代码。现在我们有了更好的关注点分离，我们可以在代码的有限部分进行小的改变，以提高代码的质量。每个改变都可以通过我们的单元测试套件进行回归测试。

我们添加的每个新功能都可以使用我们在现代化过程中获得的技术插入到我们的新应用程序架构中。我们不再随意地从以前的页面脚本中复制和修改一个新页面。相反，我们添加了一个经过单元测试的控制器类，并通过前端控制器路由到它。我们领域逻辑中的新功能是作为领域层中的经过单元测试的类或方法添加的。对呈现的更改和添加可以通过我们的视图层与我们的模型和控制器分开进行测试。

# 转换到框架

还有将我们的应用程序转换到最新、最热门的框架的可能性。虽然切换到一个公共框架有点像应用程序重写，但现在应该更容易，因为我们有一系列良好分离的应用程序层。我们应该能够确定哪些部分将被移植到公共框架，哪些只是我们特定架构运作的附属部分。

我不建议支持或反对这种方法。我只会指出，在现代化我们的遗留应用程序的过程中，我们实际上建立了我们自己定制的框架。我们所做的可能比 PHP 领域中大多数公共框架更加纪律严明和严格。虽然我们获得了与公共框架一起的社区，但我们也获得了框架开发者自己的包袱。这些以及其他权衡是我无法代表你来判断的；你必须自己决定利益是否超过成本。

# 回顾和下一步

无论我们从这里如何继续，毫无疑问，*应用程序*的改进已经导致了我们生活质量和专业方法的改进。我们在代码上投入的时间不仅在我们的就业方面得到了回报，我们现在花费更少的时间感到沮丧和泄气，更多的时间感到能干和富有成效。它在我们的技能、知识和应用架构、模式和实践方面也得到了回报。

我们现在的目标是继续改进我们的代码，继续改进自己，并帮助其他人也改进。我们需要分享我们的知识。通过这样做，我们将减少世界上因不得不处理遗留应用程序而产生的痛苦。当更多的人学会应用我们在这里学到的东西时，我们自己也可以继续处理更大、更好、更有趣的专业问题。

所以继续向你的同事、同胞和同事们传播这个好消息，他们不必因为不想要遗留应用程序而受苦。他们也可以现代化他们的代码库，并在这样做的过程中改善自己的生活。


# 附录 A. 典型的传统页面脚本

```php
<?php
2 include("common/db_include.php");
3 include("common/functions.inc");
4 include("theme/leftnav.php");
5 include("theme/header.php");
6
7 define("SEARCHNUM", 10);
8
9 function letter_links()
10 {
11 global $p, $letter;
12 $lettersArray = array(
13 '0-9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
14 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
15 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'
16 );
17 foreach ($lettersArray as $let) {
18 if ($letter == $let)
19 echo $let.' ';
20 else
21 echo '<a class="letters" '
22 . 'href="letter.php?p='
23 . $p
24 . '&letter='
25 . $let
26 . '">'
27 . $let
28 . '</a> ';
29 }
30 }
31
32 $page = ($page) ? $page : 0;
33
34 if (!empty($p) && $p!="all" && $p!="none") {
35 $where = "`foo` LIKE '%$p%'";
36 } else {
37 $where = "1";
38 }
39
40 if ($p=="hand") {
41 $where = "`foo` LIKE '%type1%'"
42 . " OR `foo` LIKE '%type2%'"
43 . " OR `foo` LIKE '%type3%'";
44 }
45
46 $where .= " AND `bar`='1'";
47 if ($s) {
48 $s = str_replace(" ", "%", $s);
49 $s = str_replace("'", "", $s);
50 $s = str_replace(";", "", $s);
51 $where .= " AND (`baz` LIKE '%$s%')";
52 $orderby = "ORDER BY `baz` ASC";
53 } elseif ($letter!="none" && $letter) {
54 $where .= " AND (`baz` LIKE '$letter%'"
55 . " OR `baz` LIKE 'The $letter%')";
56 $orderby = "ORDER BY `baz` ASC";
57 } else {
58 $orderby = "ORDER BY `item_date` DESC";
59 }
60 $query = mysql_query(
61 "SELECT * FROM `items` WHERE $where $orderby
62 LIMIT $page,".SEARCHNUM;
63 );
64 $count = db_count("items", $where);
65 ?>
66
67 <td align="middle" width="480" valign="top">
68 <img border="0" width="480" height="30"
69 src="http://example.com/images/example1.gif">
70 <table border="0" cellspacing="0" width="480"
71 cellpadding="0" bgcolor="#000000">
72 <tr>
73 <td colspan="2" width="480" height="50">
74 <img border="0"
75 src="http://example.com/images/example2.gif">
76 </td>
77 </tr>
78 <tr>
79 <td width="120" align="right" nowrap>
80 <img border="0"
81 src="http://example.com/images/example3.gif">
82 </td>
83 <td width="360" align="right" nowrap>
84 <div class="letter"><?php letter_links(); ?></div>
85 </td>
86 </tr>
87 </table>
88
89 <form name="search" enctype="multipart/form-data"
90 action="search.php" method="POST" margin="0"
91 style="margin: 0px;">
92 <table border="0" style="border-collapse: collapse"
93 width="480" cellpadding="0">
94 <tr>
95 <td align="center" width="140">
96 <input type="text" name="s" size="22"
97 class="user_search" title="enter your search..."
98 value="<?php
99 echo $s
100 ? $s
101 : "enter your search..."
102 ;
103 ?>" onFocus=" enable(this); "
104 onBlur=" disable(this); ">
105 </td>
106 <td align="center" width="70">
107 <input type="image" name="submit"
108 src="http://example.com/images/user_search.gif"
109 width="66" height="17">
110 </td>
111 <td align="right" width="135">
112 <img border="0"
113 src="http://example.com/images/list_foo.gif"
114 width="120" height="26">
115 </td>
116 <td align="center" width="135">
117 <select size="1" name="p" onChange="submit();">
118 <?php
119 if ($p) {
120 ${$p} = 'selected="selected"';
121 }
122 foreach ($foos as $key => $value) {
123 echo '<option value="'
124 . $key
125 . '" '
126 . ${$key}
127 . '>'
128 . $value
129 . '</option>';
130 }
131 ?>
132 </select>
133 </td>
134 </tr>
135 </table>
136 <?php if ($letter) {
137 echo '<input type="hidden" name="letter" '
138 . 'value="' . $letter . '">';
139 } ?>
140 </form>
141
142 <table border="0" cellspacing="0" width="480"
143 cellpadding="0" style="border-style: solid; border-color:
144 #606875; border-width: 1px 1px 0px 1px;">
145 <tr>
146 <td>
147 <div class="nav"><?php
148 $pagecount = ceil(($count / SEARCHNUM));
149 $currpage = ($page / SEARCHNUM) + 1;
150 if ($pagecount)
151 echo ($page + 1)
152 . " to "
153 . min(($page + SEARCHNUM), $count)
154 . " of $count";
155 ?></div>
156 </td>
157 <td align="right">
158 <div class="nav"><?php
159 unset($getstring);
160 if ($_POST) {
161 foreach ($_POST as $key => $val) {
162 if ($key != "page") {
163 $getstring .= "&$key=$val";
164 }
165 }
166 }
167 if ($_GET) {
168 foreach ($_GET as $key => $val) {
169 if ($key != "page") {
170 $getstring .= "&$key=$val";
171 }
172 }
173 }
174
175 if (!$pagecount) {
176 echo "No results found!";
177 } else {
178 if ($page >= (3*SEARCHNUM)) {
179 $firstlink = " | <a class=\"searchresults\"
180 href=\"?page=0$getstring\">1</a>";
181 if ($page >= (4*SEARCHNUM)) {
182 $firstlink .= " ... ";
183 }
184 }
185
186 if ($page >= (2*SEARCHNUM)) {
187 $prevpages = " | <a class=\"searchresults\""
188 . " href=\"?page="
189 . ($page - (2*SEARCHNUM))
190 . "$getstring\">"
191 . ($currpage - 2)
192 ."</a>";
193 }
194
195 if ($page >= SEARCHNUM) {
196 $prevpages .= " | <a class=\"searchresults\""
197 . " href=\"?page="
198 . ($page - SEARCHNUM)
199 . "$getstring\">"
200 . ($currpage - 1)
201 . "</a>";
202 }
203
204 if ($page==0) {
205 $prevlink = "&laquo; Previous";
206 } else {
207 $prevnum = $page - SEARCHNUM;
208 $prevlink = "<a class=\"searchresults\""
209 . " href=\"?page=$prevnum$getstring\">"
210 . "&laquo; Previous</a>";
211 }
212
213 if ($currpage==$pagecount) {
214 $nextlink = "Next &raquo;";
215 } else {
216 $nextnum = $page + SEARCHNUM;
217 $nextlink = "<a class=\"searchresults\""
218 . " href=\"?page=$nextnum$getstring\">"
219 . "Next &raquo;</a>";
220 }
221
222 if ($page < (($pagecount - 1) * SEARCHNUM))
223 $nextpages = " | <a class=\"searchresults\""
224 . " href=\"?page="
225 . ($page + SEARCHNUM)
226 . "$getstring\">"
227 . ($currpage + 1)
228 . "</a>";
229
230 if ($page < (($pagecount - 2)*SEARCHNUM)) {
231 $nextpages .= " | <a class=\"searchresults\""
232 . " href=\"?page="
233 . ($page + (2*SEARCHNUM))
234 . "$getstring\">"
235 . ($currpage + 2)
236 . "</a>";
237 }
238
239 if ($page < (($pagecount - 3)*SEARCHNUM)) {
240 if ($page < (($pagecount - 4)*SEARCHNUM))
241 $lastlink = " ... of ";
242 else
243 $lastlink = " | ";
244 $lastlink .= "<a class=\"searchresults\""
245 . href=\"?page="
246 . (($pagecount - 1)*SEARCHNUM)
247 . "$getstring\">"
248 . $pagecount
249 . "</a>";
250 }
251
252 $pagenums = " | <b>$currpage</b>";
253 echo $prevlink
254 . $firstlink
255 . $prevpages
256 . $pagenums
257 . $nextpages
258 . $lastlink
259 . ' | '
260 . $nextlink;
261 }
262 ?></div>
263 </td>
264 </tr>
265 </table>
266
267 <table border="0" cellspacing="0" width="100%"
268 cellpadding="0" style="border-style: solid; border-color:
269 #606875; border-width: 0px 1px 0px 1px;">
270
271 <?php while($item = mysql_fetch_array($query)) {
272
273 $links = get_links(
274 $item[id],
275 $item[filename],
276 $item[fileinfotext]
277 );
278
279 $dls = get_dls($item['id']);
280
281 echo '
282 <tr>
283 <td class="bg'.(($ii % 2) ? 1 : 2).'" align="center">
284
285 <div style="margin:10px">
286 <table border="0" style="border-collapse:
287 collapse" width="458" id="table5" cellpadding="0">
288 <tr>
289 <td rowspan="3" width="188">
290 <table border="0" cellpadding="0"
291 cellspacing="0" width="174">
292 <tr>
293 <td colspan="4">
294 <img border="0"
295 src="http://www.example.com/common/'
296 .$item[thumbnail].'"
297 width="178" height="74"
298 class="media_img">
299 </td>
300 </tr>
301 <tr>
302 <td style="border-color: #565656;
303 border-style: solid; border-width: 0px
304 0px 1px 1px;" width="18">
305 <a target="_blank"
306 href="'.$links[0][link].'"
307 '.$links[0][addlink].'>
308 <img border="0"
309 src="http://example.com/images/'
310 .$links[0][type].'.gif"
311 width="14" height="14"
312 hspace="3" vspace="3">
313 </a>
314 </td>
315 <td style="border-color: #565656;
316 border-style: solid; border-width: 0px
317 0px 1px 0px;" align="left" width="71">
318 <a target="_blank"
319 href="'.$links[0][link].'"
320 class="media_download_link"
321 '.$links[0][addlink].'>'
322 .(round($links[0][filesize]
323 / 104858) / 10).' MB</a>
324 </td>
325 <td style="border-color: #565656;
326 border-style: solid; border-width: 0px
327 0px 1px 0px;" width="18">
328 '.(($links[1][type]) ? '<a
329 target="_blank"
330 href="'.$links[1][link].'"
331 '.$links[1][addlink].'><img
332 border="0"
333 src="http://example.com/images/'
334 .$links[1][type].'.gif"
335 width="14" height="14" hspace="3"
336 vspace="3">
337 </td>
338 <td style="border-color: #565656;
r339 border-style: solid; border-width: 0px
340 1px 1px 0px;" align="left" width="71">
341 <a target="_blank"
342 href="'.$links[1][link].'"
343 class="media_download_link"
344 '.$links[1][addlink].'>'
345 .(round($links[1][filesize]
346 / 104858) / 10).' MB</a>' :
347 '&nbsp;</td><td>&nbsp;').'
348 </td>
349 </tr>
350 </table>
351 </td>
352 <td width="270" valign="bottom">
353 <div class="list_title">
354 <a
355 href="page.php?id='.$item[rel_id].'"
356 class="list_title_link">'.$item[baz].'</a>
357 </div>
358 </td>
359 </tr>
360 <tr>
361 <td align="left" width="270">
362 <div class="media_text">
363 '.$item[description].'
364 </div>
365 </td>
366 </tr>
367 <tr>
368 <td align="left" width="270">
369 <div class="media_downloads">'
370 .number_format($dls)
371 .' Downloads
372 </div>
373 </td>
374 </tr>
375 </table>
376 </div>
377 </td>
378 </tr>';
379 $ii++;
380 } ?>
381 </table>
382
383 <table border="0" cellspacing="0" width="480"
384 cellpadding="0" style="border-style: solid; border-color:
385 #606875; border-width: 0px 1px 1px 1px;">
386 <tr>
387 <td>
388 <div class="nav"><?php
389 if ($pagecount)
390 echo ($page + 1)
391 . " to "
392 . min(($page + SEARCHNUM), $count)
393 . " of $count";
394 ?></div>
395 </td>
396 <td align="right">
397 <div class="nav"><?php
398 if (!$pagecount) {
399 echo "No search results found!";
400 } else {
401 echo $prevlink
402 . $firstlink
403 . $prevpages
404 . $pagenums
405 . $nextpages
406 . $lastlink
407 . ' | '
408 . $nextlink;
409 }
410 ?></div>
411 </td>
412 </tr>
413 </table>
414 </td>
415
416 <?php include("theme/footer.php"); ?>
```
