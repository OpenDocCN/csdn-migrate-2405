# 安卓 UI 开发（三）

> 原文：[`zh.annas-archive.org/md5/0C4D876AAF9D190F8124849256569042`](https://zh.annas-archive.org/md5/0C4D876AAF9D190F8124849256569042)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：验证和处理输入数据

*不幸的是，在应用程序中验证和处理输入通常在设计过程中是一个后顾之忧。这些应该在用户界面第二轮草稿中的首要考虑事项。触摸屏设备提供了许多机会来简化从用户那里捕获数据的流程，在许多情况下，无需进行数据清理或验证，同时大幅提升用户的应用体验。*

安卓提供了一个优秀的工具集，以捕获用户的各种不同类型的数据，同时以`Intent`结构的形式为应用程序组件之间的松耦合提供支持。通过使用几个较小的`Activity`类来捕获数据，同时抽象出捕获不同类型输入的功能，你将能够更容易地重用输入捕获`Activity`类，不仅在应用程序内，也可以在其他应用程序中使用。此外，通过正确注册`Activity`，你将允许其他应用程序覆盖或使用你的`Activity`实现，让用户选择他们偏好的捕获机制。

# 处理不期望的输入

通常应用程序需要其用户输入特定类型的数据。应用程序从用户那里捕获输入是为了让用户告诉它关于世界的一些信息。这可以是任何东西，从用户正在寻找的内容（即一个搜索词），到关于用户自己的信息（即他们的年龄）。在大多数这些情况下，可以使用诸如自动完成框之类的机制引导用户输入。然而，如果用户可以给你“不期望”的输入，那么在某些环节中就会发生。

不期望的输入可以是任何从预期数字却输入文本，到搜索词没有结果的各种情况。在这两种情况下，你需要做三件事：

1.  告诉用户你期望数据以何种格式输入

1.  让他们知道他们输入了不期望的数据

1.  让他们重新输入数据

## 正确标记输入

防止用户输入不期望数据的第一道防线是正确标记输入控件。这不仅仅意味着，有一个如下所示的标签：

`出生日期（dd/mm/yy）：`

这意味着使用正确的控件来捕获数据。你的输入控件是一种标签，它们向用户指示你期望他们输入哪种类型的数据。在许多情况下，它们可以用来阻止用户输入无效数据，或者至少降低这种可能性。

### 注意

要牢记用户期望事物的工作方式，以及他们期望能够快速选择事物。如果你需要他们为你的应用程序提供一个国家的名字，不要使用`Spinner`并强迫他们浏览看似无尽的名称列表。

## 信号不期望的输入

如果用户确实输入了不希望或无用的内容，你需要迅速告诉他们！你越早让用户知道他们给了你无用的东西，他们就能越快地改正并回到使用你的应用程序。

一个常见的错误是在用户按下**保存**或**提交**按钮时简单地`Toast`通知用户。虽然如果你只能在那时确定他们的错误，这样做是可以的，但你几乎总是可以提前弄清楚。

请记住，在触摸屏设备上，虽然你有一个“聚焦”的小部件，但它并不像在桌面系统上那样发挥作用，用户不会“跳转”离开小部件。这意味着，只要可能，你的用户界面就应该实时响应用户的操作，而不是等待他们做其他事情（即选择另一个小部件）后才给予反馈。如果他们做了使另一个表单元素无效的事情，就禁用它。如果他们做了使一组小部件无效的事情，就将整个组从他们那里隐藏或放在另一个屏幕上。

![表示不希望的输入](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_06_01.jpg)

使用颜色和图标是快速告诉用户他们做错了事情的好方法。当你意识到用户的某些输入是错误的时候，你可以采取额外的步骤，禁用任何**保存**、**下一步**或**提交**按钮。但是，如果你禁用这样的按钮，请确保清楚哪个表单元素上有不理想的数据，并确保它显示在屏幕上。一个很好的替代方法是当用户选择**下一步**按钮时`Toast`通知用户，并滚动到无效元素。

如果你需要检查用户的输入是否与某些远程服务相匹配，请使用后台（或异步）消息。这将允许你在用户使用应用程序时验证用户的内容。它还允许你在不阻止他们使用表单的其余部分的情况下，指出某些地方出了问题。他们总是可以回到无效字段并进行更正。

## 从不受欢迎的输入中恢复。

一定要确保用户纠正错误尽可能无痛。他们为了改正一个拼写错误（或类似的错误）而需要做的工作越多，他们停止使用应用程序的可能性就越大。从不受欢迎的输入中恢复（这与上述评论非常契合）的最简单方法是在用户有机会进入流程的另一部分之前告诉他们。然而，这并不总是可能的。

在某些流程中，你可能需要弹出一个**请等待**对话框，这通常会（作为副作用）验证用户的输入。在这种情况下，使用`ProgressDialog`是明智的，这样你就不会在这个阶段将用户从当前`Activity`中移开。这将带来两个重要的副作用：

+   你不要向活动堆栈中添加不必要的层次。

+   当你关闭`ProgressDialog`时，用户给出的输入仍然可用。

## 给用户提供直接反馈。

当接受用户输入文本或其他键盘输入时，最好在用户输入过程中向他们指示输入的有效性。一个常见的方法是在`EditText`组件右边使用一个`ImageView`，并通过更改图像内容来指示用户输入的是有效还是无效内容。`ImageView`中显示的图像可以根据输入当前是否有效来设置。这使用户能够实时查看验证过程。这种机制也适用于指示不同级别的验证（即输入不是严格的有效或无效，而是良好质量或不良质量），如在密码输入的情况下。

你可以使用图像图标，或者简单使用一个 Android 可绘制 XML 资源来表示有效性（即绿色表示有效，红色表示无效）。这也意味着你的图标会根据你在布局 XML 文件中指定的任何大小进行缩放。

### 提示

**颜色和图标**

通常使用非颜色指示器来区分图标是一个好主意。色盲的人可能很难或无法区分两个仅颜色不同的图标，除非你同时改变形状和颜色。将“有效”图标设为绿色圆形，而“无效”图标设为红色六边形，将使你的应用程序更具可用性。

为了避免屏幕上图标过多，你可能只想在用户当前操作的领域旁边显示验证图标。然而，使用`INVISIBLE View`状态而不是`GONE`是一个好主意，以避免用户改变用户界面焦点时改变布局。同时，请确保验证图标大小一致。

# 完全避免无效输入

请记住，在使用移动设备时，时间往往对用户是一种限制。因此（出于简单易用的原因），你通常应该尽力避免用户输入无效内容。Android 为你提供了多种机制来实现这一点，在每一个机会都利用它们是明智的。通常，你会想要使用那些避免验证需求的组件。在 Android 中这几乎总是一个选项，即使你的需求比简单的类型信息更复杂，你也可以通常自定义组件，以阻止用户违反你的验证规则。

## 捕获日期和时间

如我们已讨论的，在输入日期和时间时，你应该使用`DatePicker`和`TimePicker`组件，或使用`DatePickerDialog`和`TimePickerDialog`以避免基本组件引入的布局问题。

### 注意

除非你的应用程序有严格的要求，否则不要创建自己的日历小部件。你可能不喜欢`DatePickerDialog`的外观，但用户在其他 Android 应用程序中已经见过它们，并且知道如何使用。这些标准小部件还可能在未来的 Android 版本中得到改进，从而让你的应用程序在不做任何修改的情况下得到提升。

![捕获日期和时间](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_06_02.jpg)

你可能会发现，对于日期和时间输入，你需要额外的验证，特别是在捕获日期或时间范围时。例如，如果你要求用户输入出生日期，用户不应该能够输入晚于“今天”的任何时间（除非是预期的出生日期）。虽然`DatePicker`类有一个事件监听器，允许你监听对其数据的更改（`DatePickerDialog`实现此事件监听器），但你不能使用此事件监听器来取消更改事件。

因此，为了**取消**事件，你需要在事件执行期间将输入改回有效的值。这是 Android 中一个出奇简单的技巧。由于事件是在进行绘制的同一线程上执行的，这允许你在无效数据在屏幕上渲染之前更改值。以下是一个`ValidatingDatePickerDialog`的简单示例，你可以使用它来实现应用程序中简单的日期验证级别。如果你需要，也可以轻松地为`TimePickerDialog`编写类似的类。

```kt
public class ValidatingDatePickerDialog extends DatePickerDialog {

    private int lastValidYear;
    private int lastValidMonth;
    private int lastValidDay;
    private ValidationCallback callback = null;

    public ValidatingDatePickerDialog(
            final Context context,
            final OnDateSetListener callBack,
            final int year,
            final int monthOfYear,
            final int dayOfMonth) {

        super(context, callBack, year, monthOfYear, dayOfMonth);
        setValidData(year, monthOfYear, dayOfMonth);
    }

 protected void setValidData(
 final int year,
 final int monthOfYear,
 final int dayOfMonth) {

 lastValidYear = year;
 lastValidMonth = monthOfYear;
 lastValidDay = dayOfMonth;
 }

    @Override
    public void onDateChanged(
            final DatePicker view,
            final int year,
            final int month,
            final int day) {

        if(callback != null && !callback.isValid(year, month, day)) {
 view.updateDate(
 lastValidYear,
 lastValidMonth,
 lastValidDay);
        } else {
            super.onDateChanged(view, year, month, day);
            setValidData(year, month, day);
        }
    }

    public void setValidationCallback(
            final ValidationCallback callback) {
        this.callback = callback;
    }

    public ValidationCallback getValidationCallback() {
        return callback;
    }

    public interface ValidationCallback {
        boolean isValid(int year, int monthOfYear, int dayOfMonth);
    }
}
```

这种处理验证的方法适用于大多数不提供事件隐式验证的 Android 小部件，并且它比给用户一个带有文本 **请输入一个有效的出生日期** 的`Toast` 提供了更好的用户体验。它还避免了在应用程序中增加额外验证层的需要。

## 使用下拉菜单和列表视图进行选择

在应用程序中，用户经常需要从可能的值列表中选择某项。我们在第二章 *视图的数据展示* 中已经讨论了`Spinner`和`ListView`小部件。然而，当涉及到验证时，它们提供的几个特性非常有用。它们是隐式验证的小部件，也就是说，由于输入的可能值是由应用程序定义的，用户不可能输入错误的数据。但是，当有效项目集基于其他用户输入或某些外部信息源改变时该怎么办呢？在这些情况下，你有几个选项可用。

### 更改数据集

阻止用户选择不再有效的值的简单方法是将其从数据集中移除。我们在`BurgerAdapter`中已经做过类似的事情，在第二章，*为视图提供数据*，当用户触摸某些项目时，我们修改了数据集。修改`AdapterView`的数据集是一个好主意，因为它“从菜单中移除了选项”。然而，它并不适用于`Spinner`类，因为如果项目从屏幕上移除，用户会想知道刚才还在那里的项目去哪了（可能会担心自己是否疯了）。

为了避免混淆或让用户感到沮丧，只有当某个项目可能不会重新添加到数据集中时，才应该从`Spinner`或`ListView`数据集中移除项目。一个符合这一要求的好例子是可用的 Wi-Fi 网络列表或范围内的蓝牙设备列表。在这两种情况下，可用的项目列表由环境定义。用户会接受显示的选项并不总是对他们可用，而且新的项目可能会时不时出现。

### 禁用选择

一种替代的、通常对用户更友好的阻止某些项目被选中的方法是禁用它们。你可以通过覆盖`ListAdapter`类中的`isEnabled(int)`方法，让`ListView`或`Spinner`忽略项目。然而，这种方法只会在事件级别上禁用项目，项目仍然会显示为启用状态（它的主要目的是定义分隔视图）。

为了在视觉上禁用一个项目，你需要禁用显示该项目的`View`。这是告诉用户“你改变了某些东西，使得这个项目不可用”的一种非常有效的方式。图形化地禁用一个项目也让用户知道它将来可能会变得可用。

## 捕获文本输入

最难处理的输入是各种文本输入形式。我发现使用软键盘可能不如使用硬件键盘快，但从开发角度来看，它提供了硬件键盘所不具备的东西——灵活性。当我想要在字段中输入文本时，软键盘的状态将指示该字段有效的输入类型。如果我需要输入电话号码，键盘可以只显示数字，甚至变成拨号盘。这不仅告诉我应该做什么，还阻止我输入可能导致验证错误的内容。

安卓的`TextView`（以及`EditText`）控件为你提供了众多不同的选项和方法，通过这些你可以为文本输入定义复杂的验证规则。这些选项中的许多也被各种软键盘所理解，使得它们可以根据`TextView`控件的配置显示完整键盘的子集。即使软键盘不完全理解（或使用硬件键盘时），也必须遵守指定选项的规则。最简单的方法是使用`inputType` XML 属性来告诉`EditText`你希望它捕获的数据类型。

从`inputType`的文档中，你可以看到其所有可能的值都是`android.view.inputmethod.InputType`接口中可用的位掩码的不同组合。`inputType`属性可用的选项将涵盖大多数需要捕获特定类型输入的情况。你也可以通过使用`TextView.setRawInput`或`TextView.setKeyboardListener`方法创建自己的更复杂的输入类型。

### 提示

**键盘监听器**

尽可能地，你应该使用输入类型或标准的`KeyListener`来处理你的文本验证。编写一个`KeyListener`并非易事，在某些情况下，你可能需要实现一个自定义软键盘。在安卓中，如果一个软键盘存在，定义了除`TYPE_NULL`之外输入类型的`KeyListener`可能根本不会调用其监听事件（`onKeyDown`、`onKeyUp`和`onKeyOther`）。`KeyListener`的按键事件仅用于接受或拒绝来自硬件键盘的事件。软件键盘使用`TextView`的输入类型属性来决定应向用户提供哪些功能。

## 自动完成文本输入

`Spinner`和`ListView`控件是让用户从预定义选项列表中选择的好方法。然而，它们的主要缺点是不适合非常长的列表。尽管实现和性能都很好，用户只是不喜欢查看大量数据列表。解决这个问题的标准方法是提供一个自动完成的文本输入控件。

![自动完成文本输入](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_06_03.jpg)

带有自动完成功能的输入控件也常与用户过去提供的选项历史一起使用，或者建议用户可能想要“完成”输入的可能方式。安卓的`AutoCompleteTextView`控件是一个带有自动完成功能的`EditText`。它使用一个`ListAdapter`（也必须实现`Filterable`接口）来查找并显示可能的建议列表给用户。

然而，`AutoCompleteTextView`存在两个主要缺陷：

+   它仍然是一个`TextView`，并且用户并不需要选择建议项之一，这意味着它的内容必须单独验证。

+   提示列表直接显示在小部件下方，占用了相当大的屏幕空间。结合软键盘输入，用户界面可能会在小屏幕上变得杂乱无章或几乎无法使用。

通过谨慎和适度地使用`AutoCompleteTextView`类，可以解决这两个问题。当你需要一个搜索框、URL 输入或类似的东西时，它们非常有用，但它们通常不适合放在屏幕中间（最好放在顶部，这样它们有足够的空间显示提示列表）。

## 小测验

1.  `KeyboardListener`中的`onKeyDown`事件何时被调用？

    1.  当广播系统范围内的按键按下事件时

    1.  取决于系统是否有硬件键盘

    1.  当按下硬件键盘按键时

    1.  当按下硬件接口控制按钮之一时

1.  你何时会使用`Toast`通知用户验证错误？

    1.  当他们犯了一个错误（也就是说，勾选了不应该勾选的复选框）

    1.  当他们从无效小部件上移开焦点后

    1.  在从外部服务接收到验证错误之后

1.  在一个即时通讯（IM）应用中，如果用户的其中一个联系人下线了，你如何更新联系人`ListView`以反映这一变化？

    1.  在`ListView`中图形化地禁用用户图标，并将其移动到`ListView`底部

    1.  从`ListView`中移除用户

    1.  在`ListView`中禁用用户的图标

# 为结果构建活动

有时候，Android 中的默认小部件单独无法满足你的输入需求，你需要某种复合输入结构。在这种情况下，你可以创建一个`Dialog`小部件，或者构建一个新的`Activity`。当`Dialog`小部件的内容保持简短（最多两到三行小部件）时，它们非常有用，因为它们在视觉上保持在当前`Activity`的顶部。然而，这意味着它们会消耗额外的资源（因为它们的调用`Activity`不能被换到后台），并且由于它们有自己的装饰，它们没有像`Activity`那样多的可用屏幕空间。

在第四章，*利用活动和意图*中，我们讨论了`Activity`类将数据返回给调用者的概念。当你需要某种额外的验证形式或想要隔离特定的输入小部件（或小部件组）时，这是一个很好的技术。你可以在`Activity.setResult`方法中指定一些结果数据。通常，一个`Activity`只需指定成功或失败的结果（使用`RESULT_OK`和`RESULT_CANCELLED`常量）。也可以通过填充`Intent`来返回数据：

```kt
Intent result = new Intent();
result.putExtra("paymentDetails", paymentDetails);
setResult(RESULT_OK, result);
```

当你调用`finish()`方法时，`Intent`数据会被传递给父`Activity`对象的`onActivityResult`方法，以及结果代码。

# 通用筛选搜索 Activity

正如本章前面所讨论的，有时你有一个预定义的对象列表，并希望用户选择其中一个。这个列表对于用户来说太大，无法滚动浏览（例如，世界上所有国家的列表），但它也是一个定义好的列表，所以你不希望他们能够选择自由文本。

在这种情况下，一个可过滤的`ListView`通常是最合适的选择。尽管`ListView`类具有过滤功能，但在没有硬件键盘的设备上，它工作得并不是很好（如果有的话）。因此，利用`EditText`小部件让用户过滤`ListView`的内容是明智的。

这种需求非常常见，因此在本节中，我们将研究构建一个几乎完全通用的`Activity`，用于过滤和选择数据。这个例子将为用户提供两种显示数据的方式。一种是通过`Cursor`，另一种是通过简单的`Object`数组。在这两种情况下，过滤`ListView`的任务都留给`ListAdapter`实现，使得实现相对简单。

# 动手时间——创建`ListItemSelectionActivity`

这是一个相当大且有些复杂的例子，因此我会将其分解成易于消化的部分，每个部分都有一个目标。我们首先想要的是一个具有美观布局的`Activity`类。我们将构建的布局是一个`EditText`在上，一个`ListView`在下，每个都有可以被`Activity`使用的 ID。

1.  创建一个新项目来包含你的`ListItemSelectionActivity`类：

    ```kt
    android create project -n Selector -p Selector -k com.packtpub.selector -a ListItemSelectionActivity -t 3
    ```

1.  在编辑器或 IDE 中打开`res/layout/main.xml`文件。

1.  移除任何默认的布局代码。

1.  确保根元素是一个在`Activity`中占用可用屏幕空间的`LinearLayout`：

    ```kt
    <LinearLayout

        android:orientation="vertical"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent">"
    ```

1.  在根元素内部，声明一个 ID 为`input`，`inputType`为`textFilter`的`EditText`，以表示它将过滤另一个小部件的内容：

    ```kt
    <EditText android:id="@+id/input"
              android:inputType="textFilter"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  在`EditText`之后，我们声明一个`ListView`，它将占用剩余的空间：

    ```kt
    <ListView android:id="@+id/list"
              android:layout_width="fill_parent"
              android:layout_height="fill_parent"/>
    ```

1.  在编辑器或 IDE 中打开`ListItemSelectionActivity` Java 源文件。

1.  在类的顶部声明一个`ListAdapter`字段：

    ```kt
    private ListAdapter adapter;
    ```

1.  在`ListAdapter`字段之后，声明一个`Filter`字段：

    ```kt
    private Filter filter;
    ```

1.  在`onCreate`方法中，确保你将`main.xml`加载为`ListItemSelectionActivity`的内容视图：

    ```kt
    setContentView(R.layout.main);
    ```

1.  然后获取在 XML 文件中声明的`ListView`，以供我们稍后使用：

    ```kt
    ListView list = (ListView)findViewById(R.id.list);
    ```

1.  最后，获取在 XML 文件中声明的`EditText`，以供我们稍后使用：

    ```kt
    EditText input = (EditText)findViewById(R.id.input);
    ```

## *刚才发生了什么？*

现在你已经得到了`ListItemSelectionActivity`类的框架。此时应用程序能够运行，向你展示一个空的`ListView`和一个`EditText`。稍后阶段将使用类顶部声明的`ListAdapter`和`Filter`字段来保存列表信息，并过滤屏幕上可见的内容。

# 动手时间——创建一个`ArrayAdapter`

`ListItemSelectionActivity`类将接受来自两个不同来源的列表内容。你可以指定一个数据库查询`Uri`，用于从外部源选择两列，或者可以在`Intent`对象中指定一个`Object`数组作为额外数据。对于下一个任务，我们将编写一个私有实用方法，从`Intent`对象创建一个`ArrayAdapter`。

1.  在编辑器或 IDE 中打开`ListItemSelectionActivity`的 Java 源文件。

1.  声明一个新的实用方法，用于为`Intent`创建`ListAdapter`：

    ```kt
    private ListAdapter createArrayAdapter(Intent intent) {
    ```

1.  从`Intent`的额外数据中获取`Object`数组：

    ```kt
    Object[] data = (Object[])intent.getSerializableExtra("data");
    ```

1.  如果数组不为`null`且不为空，返回一个新的`ArrayAdapter`对象，该对象将显示数组内容在 Android 定义的标准列表项资源中：

    ```kt
    if(data != null && data.length > 0) {
    return new ArrayAdapter<Object>(
        this,
        android.R.layout.simple_list_item_1,
        data);
    ```

1.  如果数组为`null`或为空，抛出`IllegalArgumentException`异常：

    ```kt
    else {
        throw new IllegalArgumentException(
                "no list data specified in Intent: "
                + intent);
    }
    ```

## *刚才发生了什么？*

你刚刚编写了一个非常基本的实用方法，从`Intent`中提取`Object`数组并返回它。如果数组不存在或为空，该方法会抛出`IllegalArgumentException`。这是一个有效的响应，因为我们在查找数据库查询*之后*会查找数组。如果我们没有从外部获取任何数据，那么这个`Activity`无法执行。让用户从空白列表中选择项目是没有意义的。

### 注意

请记住，这个`Activity`旨在由另一个`Activity`启动，而不是通过应用程序菜单直接由用户启动。因此，当`Activity`的使用方式不符合预期时，我们希望给自己或其他开发者提供有用的反馈。

# 动手操作——创建`CursorAdapter`

`CursorAdapter`的设置比`ArrayAdapter`复杂得多。一方面，`CursorAdapter`提供的选项比`ArrayAdapter`多。我们的`CursorAdapter`可以根据指定一列或两列来显示单行或双行列表项。尽管`ArrayAdapter`包含一些默认的过滤逻辑，但我们需要为`CursorAdapter`提供更多的支持。

1.  首先，我们允许使用两种不同的列命名约定，并附带一些默认值。声明一个实用方法，从`Intent`中查找预期的列名：

    ```kt
    private String getColumnName(
            final Intent intent,
            String primary,
            String secondary,
            String def) {
    ```

1.  首先，尝试使用`primary`属性名获取列名：

    ```kt
    String col = intent.getStringExtra(primary);
    ```

1.  如果列名为`null`，尝试使用`secondary`属性名：

    ```kt
    if(col == null) {
        col = intent.getStringExtra(secondary);
    }
    ```

1.  如果列名仍然是`null`，使用默认值：

    ```kt
    if(col == null) {
        col = def;
    }
    ```

1.  返回列名：

    ```kt
    return col;
    ```

1.  现在，声明另一个实用方法，该方法将创建实际的`CursorAdapter`，以便在`ListView`中使用：

    ```kt
    private ListAdapter createCursorAdapter(Intent intent) {
    ```

1.  查找要显示的第一列的名称：

    ```kt
    final String line1 = getColumnName(intent, "name", "line1", "name");
    ```

1.  查找要显示的可选第二列的名称：

    ```kt
    String line2 = getColumnName(
            intent, "description", "line2", null);
    ```

1.  现在我们有两种可能的路径——单行列表项或双行列表项。它们的构建非常相似，因此我们声明一些变量来保存这两条路径之间的不同值：

    ```kt
    int listItemResource;
    final String[] columns;
    String[] displayColumns;
    int[] textIds;
    ```

1.  如果已指定`line2`列名，我们使用以下代码：

    ```kt
    if(line2 != null) {
    ```

1.  我们将使用一个两行列表项资源：

    ```kt
    listItemResource = android.R.layout.two_line_list_item;
    ```

1.  数据库查询需要选择`_id`列以及`Intent`中指定的两列：

    ```kt
    columns = new String[]{"_id", line1, line2};
    ```

1.  然而，列表项将只显示两个指定的列：

    ```kt
    displayColumns = new String[]{line1, line2};
    ```

1.  `CursorAdapter`需要知道在`two_line_list_item`资源中声明的`TextView`小部件的资源 ID：

    ```kt
    textIds = new int[]{android.R.id.text1, android.R.id.text2};
    ```

1.  如果在`Intent`中没有指定第二列的名称，则`ListView`应该有单行项目：

    ```kt
    else {
    listItemResource = android.R.layout.simple_list_item_1;
    ```

1.  我们只需要请求`_id`列和单个列名：

    ```kt
    columns = new String[]{"_id", line1};
    ```

1.  列表中的项目应该包含请求列的内容：

    ```kt
    displayColumns = new String[]{line1};
    ```

1.  我们不需要告诉`CursorAdapter`在单行列表项资源中查找哪个小部件 ID：

    ```kt
    textIds = null;
    ```

1.  在`else`子句之后，我们将拥有所需的变量填充。我们可以运行初始的数据库查询并获得数据的完整列表以展示给用户：

    ```kt
    Cursor cursor = managedQuery(
            intent.getData(),
            columns,
            null,
            null,
            line1);
    ```

1.  我们现在可以创建`CursorAdapter`来包装数据库`Cursor`对象，供`ListView`使用。我们使用`SimpleCursorAdapter`的实现：

    ```kt
    CursorAdapter cursorAdapter = new SimpleCursorAdapter(
            this,
            listItemResource,
            cursor,
            displayColumns,
            textIds);
    ```

1.  为了让用户过滤列表，我们需要给`CursorAdapter`一个`FilterQueryProvider`。将`FilterQueryProvider`声明为一个匿名内部类：

    ```kt
    cursorAdapter.setFilterQueryProvider(
            new FilterQueryProvider() {
    ```

1.  在匿名`FilterQueryProvider`内部，声明`runQuery`方法，该方法将在用户每次按键时被调用：

    ```kt
    public Cursor runQuery(CharSequence constraint) {
    ```

1.  我们可以返回一个`managedQuery`，它只对我们将在`ListView`中渲染的第一列执行 SQL `LIKE`操作：

    ```kt
    return managedQuery(
            intent.getData(),
            columns,
            line1 + " LIKE ?",
            new String[] {constraint.toString() + '%'},
            line1);
    ```

1.  最后，`createCursorAdapter`方法可以返回`CursorAdapter`：

    ```kt
    return cursorAdapter;
    ```

## *刚才发生了什么？*

这个实用方法处理在`Intent`中指定了查询`Uri`时创建`CursorAdapter`的情况。这种结构允许对非常大的数据集进行过滤，因为它通常是建立在 SQL Lite 数据库之上的。其性能与它将查询的数据库表结构直接相关。

由于数据库查询可能非常大，`CursorAdapter`类本身不执行任何数据集过滤。相反，您需要实现`FilterQueryProvider`接口，为每次过滤更改创建并运行新的查询。在上述示例中，我们创建了一个与默认`Cursor`完全相同的`Cursor`，但我们为查询添加了`selection`和`selectionArgs`。这个`LIKE`子句将告诉 SQL Lite 只返回以用户输入的过滤条件开头的行。

# 动手时间——设置`ListView`：

现在我们有了创建此`Activity`可以过滤的两种类型`ListAdapter`的实现。现在我们需要一个实用方法来确定使用哪一个并返回它；然后我们希望使用新的实用方法在`ListView`小部件上设置`ListAdapter`。

1.  声明一个新方法来创建所需的`ListAdapter`对象：

    ```kt
    protected ListAdapter createListAdapter() {
    ```

1.  获取用于启动`Activity`的`Intent`对象：

    ```kt
    Intent intent = getIntent();
    ```

1.  如果`Intent`中的数据`Uri`不为`null`，则返回给定`Intent`的`CursorAdapter`。否则，返回给定`Intent`的`ArrayAdapter`：

    ```kt
    if(intent.getData() != null) {
    return createCursorAdapter(intent);

    else {
        return createArrayAdapter(intent);
    }
    ```

1.  在`onCreate`方法中，从布局中找到两个`View`对象之后，使用新的实用方法创建所需的`ListAdapter`：

    ```kt
    adapter = createListAdapter();
    ```

1.  将`Filter`字段分配给`ListAdapter`给出的`Filter`：

    ```kt
    filter = ((Filterable)adapter).getFilter();
    ```

1.  在`ListView`上设置`ListAdapter`：

    ```kt
    list.setAdapter(adapter);
    ```

## *刚才发生了什么？*

这段代码现在引用了创建的`ListAdapter`对象及其配合使用的`Filter`。如果你现在运行应用程序，会发现打开时会弹出**强制关闭**对话框。这是因为现在代码需要某种数据来填充`ListView`。虽然对于一个正常的应用程序来说这并不理想，但这实际上是一个可重用的组件，可以在多种情况下使用。

# 行动时间——过滤列表

尽管代码已经设置好了显示列表，甚至可以过滤它，但我们还没有将`EditText`框与`ListView`关联起来，因此在`EditText`中输入目前将完全不起作用。我们需要监听`EditText`框的变化，并根据输入的内容请求过滤`ListView`。这将涉及`ListItemSelectionActivity`类监听`EditText`上的事件，然后请求`Filter`对象缩小可用的项目集合。

1.  应该让`ListItemSelectionActivity`实现`TextWatcher`接口：

    ```kt
    public class ListItemSelectionActivity extends Activity
            implements TextWatcher
    ```

1.  在`onCreate`方法中在`ListView`上设置`ListAdapter`后，将`ListItemSelectionActivity`作为`TextWatcher`添加到`EditText`组件上：

    ```kt
    input.addTextChangedListener(this);
    ```

1.  你需要声明`beforeTextChanged`和`onTextChanged`方法的空实现，因为我们实际上并不关心这些事件：

    ```kt
    public void beforeTextChanged(
            CharSequence s,
            int start,
            int count,
            int after) {
    }

    public void onTextChanged(
            CharSequence s,
            int start,
            int count,
            int after) {
    }
    ```

1.  然后声明我们感兴趣的`afterTextChanged`方法：

    ```kt
    public void afterTextChanged(Editable s) {
    ```

1.  在`afterTextChanged`方法中，我们只需请求当前`ListAdapter`的`Filter`过滤`ListView`：

    ```kt
    filter.filter(s);
    ```

## *刚才发生了什么？*

`TextWatcher`接口用于追踪`TextView`组件的变化。实现该接口可以监听到`TextView`实际内容的任何改变，无论这些改变来自何处。尽管`OnKeyListener`和`KeyboardListener`接口主要用于处理硬件键盘事件，但`TextWatcher`可以处理来自硬件键盘、软键盘甚至内部调用`TextView.setText`的变化。

# 行动时间——返回选择项

`ListItemSelectionActivity`现在可以用来显示可能的条目列表，并通过在`ListView`上方的`EditText`中输入来过滤它们。然而，我们还没有办法让用户从`ListView`中实际选择一个选项，以便将其传递回我们的父`Activity`。这只需要实现一个简单的`OnItemClickListener`接口。

1.  `ListItemSelectionActivity`类现在需要实现`OnItemClickListener`接口：

    ```kt
    public class ListItemSelectionActivity extends Activity
            implements TextWatcher, OnItemClickListener {
    ```

1.  在`onCreate`方法中注册为`TextWatcher`之后，在`ListView`上注册为`OnItemClickListener`：

    ```kt
    list.setOnItemClickListener(this);
    ```

1.  重写`onItemClick`方法以监听用户的选择：

    ```kt
    public void onItemClick(
            AdapterView<?> parent,
            View clicked,
            int position,
            long id) {
    ```

1.  创建一个空的`Intent`对象，以便传回我们的父`Activity`：

    ```kt
    Intent data = new Intent();
    ```

1.  如果`ListAdapter`是`CursorAdapter`，传递给`onItemClick`的`id`将是选择的数据的数据库`_id`列值。将这个值添加到`Intent`中：

    ```kt
    if(adapter instanceof CursorAdapter) {
    data.putExtra("selection", id);
    ```

1.  如果`ListAdapter`不是`CursorAdapter`，我们将实际选择的`Object`添加到`Intent`中：

    ```kt
    else {
        data.putExtra(
                "selection",
                (Serializable)parent.getItemAtPosition(position));
    }
    ```

1.  将结果代码设置为`RESULT_OK`，并将`Intent`传回：

    ```kt
    setResult(RESULT_OK, data);
    ```

1.  用户已经做出了他们的选择，所以这部分我们已经完成了：

    ```kt
    finish();
    ```

## *刚才发生了什么？*

`ListItemSelectionActivity`现在已完成并准备使用。它提供了与`AutoCompleteTextView`非常相似的功能，但作为一个独立的`Activity`，它为用户提供了更大的建议列表，并且用户必须从`ListView`中选择一个项目，而不是简单地输入他们的数据。

## 使用 ListItemSelectionActivity

您需要指定用户要从哪个数据中选择，这是启动`ListItemSelectionActivity`的`Intent`的一部分。如已经讨论过的，实际上有两种路径：

+   传入某种类型的数组（非常适合在您自己的应用程序中使用）

+   提供一个数据库查询`Uri`以及您想要显示的列名（如果您想从另一个应用程序中使用它，这非常方便）

由于`ListItemSelectionActivity`返回其选择（如果它不这样做，那就没有多大用处），因此您需要使用`startActivityForResult`方法而不是正常的`startActivity`方法来启动它。如果您想传递一个`String`对象数组供选择，可以使用类似于以下意图的代码：`new Intent(this, ListItemSelectionActivity.class)`：

```kt
intent.putExtra("data", new String[] {
    "Blue",
    "Green",
    "Red",// more colors    
});
startActivityForResult(intent, 101);
```

如果上述`data`数组中有足够的颜色，您将看到一个可以按用户所需颜色进行筛选的`ListItemSelectionActivity`屏幕。以下是结果屏幕外观的截图：

![使用 ListItemSelectionActivity](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_06_04.jpg)

为了从`ListItemSelectionActivity`接收结果，您需要在`onActivityResult`方法中监听结果（如第四章所述，*利用活动和意图*）。例如，如果您只是想`Toast`确认选择的结果，可以使用以下代码：

```kt
@Override
protected void onActivityResult(
        int requestCode,
        int resultCode,
        Intent data) {

    super.onActivityResult(requestCode, resultCode, data);

    if(requestCode == 101 && resultCode == RESULT_OK) {
        Object obj = data.getSerializableExtra("selection");
        Toast.makeText(
                this,
                String.valueOf(obj),
                Toast.LENGTH_LONG).show();
    }
}
```

最后，您会如何在`ListItemSelectionActivity`中使用数据库查询呢？这非常容易展示，可能是`ListItemSelectionActivity`最激动人心的功能。以下代码段将允许用户从他们的电话簿中选择一个联系人：

```kt
Intent intent = new Intent(
        this,
        ListItemSelectionActivity.class);

intent.setData(People.CONTENT_URI);
intent.putExtra("line1", People.NAME);
intent.putExtra("line2", People.NUMBER);

startActivityForResult(intent, 202);
```

## 动手试试吧！

`ListItemSelectionActivity` 可以过滤和选择几乎任何内容。尝试构建一个包含世界上所有国家（网上有许多这样的列表）的列表，然后创建一个 `Activity`，使用 `ListItemSelectionActivity` 让你选择其中一个。

# 总结

你如何接受用户的输入，以及如何验证这些输入，这在用户使用你的应用程序的整体体验中起着至关重要的作用。软件应该帮助用户，并在每一步告诉他们它需要什么。这不仅使应用程序更容易使用，而且还能让用户更快地操作。

使用 `ListItemSelectionActivity` 常常可以帮助用户浏览大量数据集，同时防止他们做出不想要或无效的选择。这是一种非常常用的控件类型，在许多不同的应用程序中以各种形式出现。目前，Android 没有一个通用的类能像这样轻松地执行这项任务。

在下一章中，我们将开始了解一种相当现代的用户反馈形式：动画。Android 不仅仅支持动画化用户界面的部分元素，还支持组合复杂的自定义动画。动画在用户享受应用程序的过程中起着至关重要的作用。这不仅仅因为它看起来很棒，还因为它提供了视觉线索，让用户了解应用程序当前正在做什么，以及他们的操作产生了什么效果。


# 第七章：动画小部件和布局

*动画是现代应用程序用户界面设计的重要元素。然而，在设计中过度使用动画也是很容易的。在非游戏应用程序中使用动画的一般准则是——只对用户交互和通知进行动画处理，并保持动画时长简短，以免对用户体验产生负面影响。对于游戏来说，更多的动画通常是可以接受的（甚至可能是预期的）。*

那么为什么动画要针对用户交互而不是（例如）应用程序的背景呢？一方面，动画化应用程序的背景是分散注意力的，如果你试图捕捉或向用户呈现重要信息，这是不专业的（无论它看起来多好）。关于通知，动画也非常重要。屏幕上的移动会吸引注意力，因此，通常需要一个大的弹出对话框可以被一个小型动画图标所替代。一个完美的例子就是在安卓设备的通知区域顶部左侧放置的“下载中”图标，当安卓**市场**应用程序正在下载新软件或更新时。

布局动画和过渡为用户提供了有用的状态信息。当使用屏幕过渡时，你告诉用户刚刚发生了什么，或者即将发生什么。不同的过渡对用户意味着不同的事件，了解每个不同活动应使用哪种过渡，将让用户知道即将采取哪种类型的动作。布局动画是用户反馈的重要组成部分，如果省略它们或在错误的地方使用错误的动画，可能会让用户感到烦躁或稍微有些困惑（“改变茫然”）。使用正确的动画将提升用户体验，甚至可以通过提供简短的提示，告诉用户接下来需要做什么，从而加快他们使用应用程序的速度。

在本章中，我们将重点介绍两种主要的动画类型——小部件动画和布局动画。我们将查看安卓提供的标准动画结构，并探讨如何创建新的动画类型和扩展现有类型。我们还将探讨动画的定时和“良好实践”使用，以及在不降低速度或分散注意力的前提下让用户保持愉悦。

# 使用标准的安卓动画

安卓中的任何`View`或`ViewGroup`对象都可以附加动画。动画通常在 XML 文件中定义为应用程序资源，安卓在`android`包中提供了一些有用的默认动画。同时，安卓还包含几个专门设计用来处理动画的`View`类。使用这些类时，你会发现它们具有布局属性，这些属性允许你为某些特定动作设置特定类型的动画。然而，通常在布局文件中并不指定动画，而是依赖 Java 代码来设置和启动`Animation`对象。

动画通常不作为布局 XML 的一部分来指定，原因非常简单——它们应该在何时运行？许多动画可以作为对用户输入的响应，让用户知道正在发生什么。大多数动画在某种程度上都会由用户的行为触发（除非它们用于通知）。因此，你需要指定两个内容：应该在哪个小部件上运行哪个动画，以及关于动画何时运行的信号。默认的 Android 动画会立即开始动画，而其他动画结构可能有一个预定延迟才会开始。

# 动手操作——动画新闻源

我们将从创建一个选择器`Activity`和一个简单的`NewsFeedActivity`开始。在新闻源中，我们将使用计时器使最新的新闻标题“进入和退出”。对于这个示例，我们将使用 Android 提供的一些默认动画，并通过布局资源主要驱动这个过程。

1.  创建一个新项目，包含本章的动画示例，主`Activity`名为`AnimationSelectionActivity`：

    ```kt
    android create project -n AnimationExamples -p AnimationExamples -k com.packtpub.animations -a AnimationSelector -t 3
    ```

1.  在编辑器或 IDE 中打开`res/layout/main.xml`布局文件。

1.  清除布局资源的默认内容。

1.  声明一个消耗所有可用屏幕空间的垂直`LinearLayout`：

    ```kt
    <LinearLayout

        android:orientation="vertical"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  创建一个标签为“新闻源”的`Button`，链接到第一个动画示例：

    ```kt
    <Button android:id="@+id/news_feed"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"
            android:layout_marginBottom="10dip"
            android:text="News Feed"/>
    ```

1.  创建一个名为`news.xml`的新布局资源文件。

1.  声明一个垂直的`LinearLayout`，包含所有可用的屏幕空间：

    ```kt
    <LinearLayout

        android:orientation="vertical"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent">"
    ```

1.  向`LinearLayout`添加一个`TextSwitcher`对象，指定默认的“滑动”动画作为“进入”和“退出”动画：

    ```kt
    <TextSwitcher
            android:id="@+id/news_feed"
            android:inAnimation="@android:anim/slide_in_left"
            android:outAnimation="@android:anim/slide_out_right"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"
            android:text=""/>
    ```

1.  在编辑器或 IDE 中打开`res/values/strings.xml`文件。

1.  声明一个名为`headlines`的字符串数组，包含一些模拟新闻标题的元素：

    ```kt
    <string-array name="headlines">
        <item>Pwnies found to inhabit Mars</item>
        <item>Geeks invent \"atoms\"</item>
        <item>Politician found not lying!</item>
        <!-- add some more items here if you like -->
    </string-array>
    ```

1.  在生成的根包中，声明一个名为`NewsFeedActivity.java`的新 Java 源文件。

1.  在你的`AndroidManifest.xml`文件中注册`NewsFeedActivity`类：

    ```kt
    <activity android:name=".NewsFeedActivity" android:label="News Feed" />
    ```

1.  新类应继承`Activity`类并实现`Runnable`接口：

    ```kt
    public class NewsFeedActivity
            extends Activity implements Runnable {
    ```

1.  声明一个`Handler`，用作改变标题的时间结构：

    ```kt
    private final Handler handler = new Handler();
    ```

1.  我们需要引用`TextSwitcher`对象：

    ```kt
    private TextSwitcher newsFeed;
    ```

1.  声明一个字符串数组，用于保存你添加到`strings.xml`文件中的模拟新闻标题：

    ```kt
    private String[] headlines;
    ```

1.  你还需要跟踪当前正在显示的新闻标题：

    ```kt
    private int headlineIndex;
    ```

1.  重写`onCreate`方法：

    ```kt
    protected void onCreate(final Bundle savedInstanceState) {
    ```

1.  调用`Activity`的`onCreate`方法：

    ```kt
    super.onCreate(savedInstanceState);
    ```

1.  将内容视图设置为`news`布局资源：

    ```kt
    setContentView(R.layout.news);
    ```

1.  从`strings.xml`应用程序资源文件中存储对标题字符串数组的引用：

    ```kt
    headlines = getResources().getStringArray(R.array.headlines);
    ```

1.  查找`TextSwitcher`小部件，并将其分配给之前声明的字段：

    ```kt
    newsFeed = (TextSwitcher)findViewById(R.id.news_feed);
    ```

1.  将`TextSwitcher`的`ViewFactory`设置为一个新的匿名类，当被请求时创建`TextView`对象：

    ```kt
    newsFeed.setFactory(new ViewFactory() {
        public View makeView() {
            return new TextView(NewsFeedActivity.this);
        }
    });
    ```

1.  重写`onStart`方法：

    ```kt
    protected void onStart() {
    ```

1.  调用`Activity`类的`onStart`方法：

    ```kt
    super.onStart();
    ```

1.  重置`headlineIndex`，以便我们从第一条新闻标题开始：

    ```kt
    headlineIndex = 0;
    ```

1.  使用`Handler`将`NewsFeedActivity`作为延迟动作发布：

    ```kt
    handler.postDelayed(this, 3000);
    ```

1.  重写`onStop`方法：

    ```kt
    protected void onStop() {
    ```

1.  调用`Activity`类的`onStop`方法：

    ```kt
    super.onStop();
    ```

1.  移除任何待处理的`NewsFeedActivity`调用：

    ```kt
    handler.removeCallbacks(this);
    ```

1.  实现我们将用来切换到下一个标题的`run`方法：

    ```kt
    public void run() {
    ```

1.  打开一个`try`块以交换内部标题：

1.  使用`TextSwitcher.setText`方法切换到下一个标题：

    ```kt
    newsFeed.setText(headlines[headlineIndex++]);
    ```

1.  如果`headlineIndex`超过了标题总数，将`headlineIndex`重置为零：

    ```kt
    if(headlineIndex >= headlines.length) {
        headlineIndex = 0;
    }
    ```

1.  关闭`try`块，并添加一个`finally`块。在`finally`块中，将`NewsFeedActivity`重新发布到`Handler`队列中：

    ```kt
    finally {
        handler.postDelayed(this, 3000);
    }
    ```

1.  在编辑器或 IDE 中打开自动生成的`AnimationSelector` Java 源文件。

1.  `AnimationSelector`类需要实现`OnClickListener`：

    ```kt
    public class AnimationSelector
            extends Activity implements OnClickListener {
    ```

1.  在`onCreate`方法中，确保将内容视图设置为之前创建的`main`布局资源：

    ```kt
    setContentView(R.layout.main);
    ```

1.  找到声明的`Button`并将其`OnClickListener`设置为`this`：

    ```kt
    ((Button)findViewById(R.id.news_feed)).
           setOnClickListener(this);
    ```

1.  声明`onClick`方法：

    ```kt
    public void onClick(final View view) {
    ```

1.  使用 switch 来判断点击了哪个`View`：

    ```kt
    switch(view.getId()) {
    ```

1.  如果是新闻源`Button`，则使用以下`case`：

    ```kt
    case R.id.news_feed:
    ```

1.  使用新的`Intent`启动`NewsFeedActivity`：

    ```kt
    startActivity(new Intent(this, NewsFeedActivity.class));
    ```

1.  从`switch`语句中断，从而完成`onClick`方法。

## *刚才发生了什么？*

`TextSwitcher`是一个动画工具`View`的示例。在这种情况下，它是交换新闻标题的完美结构，一次显示一个标题并在每段文本之间动画过渡。`TextSwitcher`对象创建两个`TextView`对象（使用匿名`ViewFactory`类）。当你使用`setText`方法时，`TextSwitcher`会改变“离屏”`TextView`的文本，并在“在屏”`TextView`和“离屏”`TextView`之间动画过渡（显示新的文本内容）。

`TextSwitcher`类要求你为其指定两个动画资源以创建过渡效果：

+   将文本动画移到屏幕上

+   将文本动画移出屏幕

在前一个示例中，我们使用了默认的`slide_in_left`和`slide_out_right`动画。这两个都是基于平移动画的示例，因为它们实际上改变了`TextView`对象的“在屏”位置以产生效果。

# 使用 flipper 和 switcher 小部件

本章的第一个示例使用了`TextSwitcher`类，这是标准 Android API 中的一个动画`View`类。还有其他几个动画工具类，你可能之前遇到过（比如`ImageSwitcher`）。`TextSwitcher`和`ImageSwitcher`都是相关类，并且都继承自更通用的`ViewSwitcher`类。

`ViewSwitcher`类是一个通用的动画工具，并定义了我们在前一个示例中匿名实现的`ViewFactory`接口。`ViewSwitcher`是一个只包含两个子`View`对象的`ViewGroup`。一个在屏幕上显示，另一个隐藏。`getNext`实用方法允许你找出哪个是“离屏”的`View`对象。

虽然你通常使用`ViewFactory`来填充`ViewSwitcher`，但你也可以选择手动填充。例如，你可以通过继承自`ViewGroup`的`addView`方法，为`TextSwitcher`添加内容。

![使用翻转和切换小部件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_07_01.jpg)

## 使用 ImageSwitcher 和 TextSwitcher 的实现

`ImageSwitcher`和`TextSwitcher`类是`ViewSwitcher`的专业实现，它们了解所包含的`View`对象的类型。当你调用`TextSwitcher`对象的`setText`方法时，它类似于在包含两个`TextView`子项的`ViewSwitcher`上调用以下代码片段：

```kt
((TextView)switcher.getNext()).setText("Next text to display");
switcher.showNext();
```

`TextSwitcher`可用于显示内容，如（示例中的）新闻源，或像 Android 通知区域一样，显示不适合单行显示的文本内容。当动画使文本向上运行时，在`TextSwitcher`中显示多行特别有效，这会使文本看起来在`TextSwitcher`对象后面向上滚动。

`ImageSwitcher`通常用于画廊、幻灯片或类似结构中。你也可以使用`ImageSwitcher`让用户从一组小图片中选择，例如，选择登录头像的简短列表。

## 动手英雄 - 填充 TextSwitcher

在新闻源示例中，除了使用`ViewFactory`填充`TextSwitcher`外，还可以尝试在 XML 布局资源中填充。记住，它需要正好两个`TextView`子部件。如果做对了，尝试给两个`TextView`对象设置不同的字体颜色和样式。

## 动画布局小部件

使用如`TextSwitcher`和`ImageSwitcher`这样的动画工具小部件，可以让你随着时间的推移显示比一次能容纳在屏幕上的更多信息。通过`LayoutAnimationController`类，`ViewGroup`对象也可以在不进行重大修改的情况下进行动画处理。然而，在这种情况下，需要在你的 Java 代码中添加动画。

`LayoutAnimationController`最适合用于创建`ViewGroup`出现或即将从屏幕消失时的“进入”或“退出”效果。控制器只需在指定`ViewGroup`的每个`View`子项上启动一个指定的动画。然而，它不必同时进行，或按顺序进行。你可以轻松地配置`LayoutAnimationController`，使每个子部件动画开始之间有一小段延迟，从而产生交错效果。

如果正确应用于`LinearLayout`，你可以实现与以下图表类似的效果：

![动画布局小部件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_07_02.jpg)

# 动手操作时间 - 动画化 GridView

`GridView`类拥有自己的`LayoutAnimationController`，专门设计用来以行和列的形式动画化它，可以实现比标准`LayoutAnimationController`更复杂的效果。在“动画”示例的下一部分，我们将使用`GridView`构建一个可爱的颜色选择器。当选择器首次出现在屏幕上时，每个颜色样本将从左上角开始淡入，直至右下角结束。

1.  首先，在项目的根包中声明一个新的 Java 源文件，命名为`ColorAdapter.java`，它将为`GridView`生成颜色样本。

1.  `ColorAdapter`需要扩展`BaseAdapter`以处理`Adapter`的样板要求：

    ```kt
    public class ColorAdapter extends BaseAdapter {
    ```

1.  `ColorAdapter`将被创建，并指定行数和列数，这些数字将在`GridView`上显示：

    ```kt
    private final int rows;
    private final int cols;

    public ColorAdapter(int rows, int cols) {
        this.rows = rows;
        this.cols = cols;
    }
    ```

1.  `ColorAdapter`将提供的项目数是行数乘以列数：

    ```kt
    public int getCount()
        return rows * cols;
    }
    ```

1.  颜色的 ID 是它所在的位置或索引：

    ```kt
    public long getItemId(int pos) {
        return pos;
    }
    ```

1.  我们使用一个实用方法从“列表”中的索引组合颜色。对于这个函数，我们利用了 Android `Color`类中的`HSVtoRGB`方法：

    ```kt
    private int getColor(int pos) {
        float h = (float)pos / (float)getCount();
        return Color.HSVToColor(new float[]{h * 360f, 1f, 1f});
    }
    ```

1.  适配器模型中索引处的项目作为其颜色值返回：

    ```kt
    public Object getItem(int pos) {
        return getColor(pos);
    }
    ```

1.  为了创建颜色样本`View`对象，我们像平常一样实现`Adapter`的`getView`方法：

    ```kt
    public View getView(int pos, View reuse, ViewGroup parent) {
    ```

1.  我们返回的`View`将是一个`ImageView`对象，因此我们要么复用父控件提供的对象，要么创建一个新的：

    ```kt
    ImageView view = reuse instanceof ImageView
            ? (ImageView)reuse
            : new ImageView(parent.getContext());
    ```

1.  我们利用`ColorDrawable`类用我们的`getColor`实用方法指定的颜色填充`ImageView`：

    ```kt
    view.setImageDrawable(new ColorDrawable(getColor(pos)));
    ```

1.  `ImageView`需要设置其`android.widget.AbsListView.LayoutParams`，然后才能返回给`GridView`进行显示：

    ```kt
    view.setLayoutParams(new LayoutParams(16, 16));
    return view;
    ```

1.  创建一个新的 XML 布局资源文件，名为`res/layout/colors.xml`，以保存将作为颜色选择器的`GridView`的声明。

1.  `colors.xml`布局文件的内容仅包含一个`GridView`小部件：

    ```kt
    <GridView

        android:id="@+id/colors"
        android:verticalSpacing="5dip"
        android:horizontalSpacing="5dip"
        android:stretchMode="columnWidth"
        android:gravity="center"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent" />
    ```

1.  在你的`AnimationExamples`项目的根包中定义另一个新的 Java 源文件。将这个命名为`ColorSelectorActivity.java`。

1.  新的类声明应该扩展`Activity`：

    ```kt
    public class ColorSelectorActivity extends Activity {
    ```

1.  正常重写`onCreate`方法，并将内容视图设置为刚刚编写的`colors` XML 布局资源：

    ```kt
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.colors);
    ```

1.  现在你可以使用`android.view.animation`包中的便捷`AnimationUtils`类加载默认的 Android“淡入”动画：

    ```kt
    Animation animation = AnimationUtils.loadAnimation(
            this, android.R.anim.fade_in);
    ```

1.  为了正确地动画化`GridView`，你需要实例化一个新的`GridLayoutAnimationController`对象，并传递给它“淡入”动画：

    ```kt
    GridLayoutAnimationController animationController =
            new GridLayoutAnimationController(
            animation, 0.2f, 0.2f);
    ```

1.  现在查找你在`colors.xml`文件中声明的`GridView`：

    ```kt
    GridView view = (GridView)findViewById(R.id.colors);
    ```

1.  将`GridView`中的列数设置为`10`（注意我们并没有在 XML 布局资源中这样做，尽管通常你会这样做）：

    ```kt
    view.setNumColumns(10);
    ```

1.  当你将`GridView`的适配器设置为`ColorAdapter`时，你还需要知道列数，最简单的方法是在 Java 中同时保持这两个值：

    ```kt
    view.setAdapter(new ColorAdapter(10, 10));
    ```

1.  现在`view`对象已经准备好使用`GridLayoutAnimationController`了：

    ```kt
    view.setLayoutAnimation(animationController);
    ```

1.  为了在屏幕显示时开始动画，我们重写了`onStart`方法。在这里，我们再次查找`GridView`并开始动画：

    ```kt
    protected void onStart() {
        super.onStart();
        ((GridView)findViewById(R.id.colors)).
                getLayoutAnimation().start();
    }
    ```

1.  为了将这个新示例与其它动画示例整合，你需要在一个编辑器或 IDE 中打开`res/layout/main.xml`文件。

1.  在`LinearLayout`的末尾添加一个新的`Button`，我们将使用它来启动颜色选择示例：

    ```kt
    <Button android:id="@+id/colors"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"
            android:layout_marginBottom="10dip"
            android:text="Color Selector" />
    ```

1.  在你的编辑器或 IDE 中打开`AnimationSelector`源文件。

1.  设置了`news_feed Button`的`OnClickListener`之后，以同样的方式找到并设置新的`colors Button`的`OnClickListener`：

    ```kt
    ((Button)findViewById(R.id.colors)).setOnClickListener(this);
    ```

1.  在`onClick`方法中，在`news_feed Button`的`switch case`之后，为新的`colors Button`添加另一个`switch case`，并启动`ColorSelectorActivity`：

    ```kt
    case R.id.colors:
        startActivity(new Intent(this, ColorSelectorActivity.class));
        break;
    ```

1.  在你的编辑器或 IDE 中打开`AndroidManifest.xml`文件。

1.  在`<application>`部分的底部，注册新的`ColorSelectorActivity`：

    ```kt
    <activity android:name=".ColorSelectorActivity"
              android:label="Your Favorite Color" />
    ```

## *刚才发生了什么？*

新示例使用了`GridLayoutAnimationController`，在上一动画开始后的几分之一秒内开始每个“淡入”动画。这创建了一个流畅的动画效果，颜色样本从屏幕左上角到右下角出现。

当你实例化一个`GridLayoutAnimationController`时，它需要你提供动画以及两个参数，这两个参数表示开始下一行或下一列动画之间的时间间隔。所给的延迟不是以“直接”时间格式指定，而是由给定动画完成所需的时间决定。在我们的例子中，如果动画需要一秒钟来完成，每个动画开始之间的延迟将是 200 毫秒，因为延迟被指定为`0.2`。

我们在`Activity`一变为可见状态时对色块进行动画处理，实际上这成为了一个过渡动画，向用户介绍这个新屏幕。对于这类动画，尽可能缩短时间同时提供一个令人愉悦的介绍是至关重要的。当你运行这个新示例时，你应该会得到与以下图片中展示的动画相似的动画效果：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_07_03b.jpg)

## 创建自定义动画

到目前为止，我们已经探索了使用 Android 的默认动画与普通小部件，但是如果是将自定义动画应用于一个不是为动画设计的小部件呢？Android 支持四种基本动画类型，可以应用于`View`对象：

+   平移/移动

+   旋转

+   缩放

+   透明度/Alpha

这些不同的动画结构可以单独应用，或者在一个动画集合中合并在一起，任意三种组合都可以同时运行。通过在动画开始前设置延迟时间，你可以通过简单的动画集合一个接一个地创建复杂的动画。

与 Android 中的许多事物一样，创建自定义动画的最简单方法是在资源 XML 文件中定义它。Android 使用的动画格式中的元素直接对应于`android.animation.view`包中的类。动画文件还可以引用其他动画资源中的动画，这使得组合复杂动画和复用简单动画变得更加容易。

# 动手实践——编写自定义动画

编写自定义动画非常简单，但并不完全直观。在本节中，你将定义一个自定义动画，它将使动画组件的大小增加五倍，同时逐渐淡出直至完全透明。

1.  创建一个名为`res/anim/vanish.xml`的新 XML 资源文件，并在编辑器或 IDE 中打开它。

1.  动画文件的根元素将是一个动画`set`元素：

    ```kt
    <set >
    ```

1.  在`<set>`元素中，声明一个元素来定义缩放动画：

    ```kt
    <scale />
    ```

1.  缩放动画的持续时间需要设置为`300`毫秒：

    ```kt
    android:duration="300"
    ```

1.  动画从原始大小开始缩放：

    ```kt
    android:fromXScale="1.0"
    android:fromYScale="1.0"
    ```

1.  缩放动画需要将大小增加`5.0`倍：

    ```kt
    android:toXScale="5.0"
    android:toYScale="5.0"
    ```

1.  我们希望缩放效果从组件的中心向外扩展：

    ```kt
    android:pivotX="50%"
    android:pivotY="50%"
    ```

1.  `<scale>`元素的最后一部分定义了动画的加速曲线。在这里，我们希望缩放效果在运行时减速：

    ```kt
    android:interpolator="@android:anim/decelerate_interpolator"
    ```

1.  接下来，定义一个新元素来处理动画的淡出部分：

    ```kt
    <alpha />
    ```

1.  淡出动画的持续时间也是`300`毫秒：

    ```kt
    android:duration="300"
    ```

1.  我们从没有透明度开始：

    ```kt
    android:fromAlpha="1.0"
    ```

1.  淡出效果以组件完全不可见结束：

    ```kt
    android:toAlpha="0.0"
    ```

1.  淡出效果应该随着运行而加速，因此我们使用了加速插值器：

    ```kt
    android:interpolator="@android:anim/accelerate_interpolator"
    ```

## *刚才发生了什么？*

这是一个相对简单的动画集合，但其效果视觉效果令人满意。将动画保持在`300`毫秒内，足够快，不会干扰用户的交互，但又足够长，能让用户完全看到。

在`<set>`元素中定义动画时，每个非集合子动画都需要定义其`duration`。`<set>`元素没有它自己的`duration`的概念。然而，你可以为整个集合定义一个单一的`interpolator`来共享。

`<scale>`动画默认会使用左上角作为"轴心"点来缩放组件，导致组件向右和向下增长，而不是向左和向上。这会造成一边倒的动画效果，看起来并不吸引人。在上一个示例中，缩放动画以动画组件的中心作为轴心点运行。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_07_05.jpg)

# 动手实践——让一个按钮消失

那么我们如何将这个漂亮的光泽动画应用于 `Button` 对象呢？`Button` 对象没有动画属性，因此你不能直接从布局资源文件中引用它。我们想要的是当点击 `Button` 控件时运行动画。

1.  创建一个名为 `res/layout/vanish.xml` 的新布局资源文件，并在编辑器或 IDE 中打开。

1.  在新布局的根元素中，声明一个 `RelativeLayout` 元素：

    ```kt
    <RelativeLayout

        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  `Button` 需要足够大，并在屏幕上居中。为此，我们给它一些内边距：

    ```kt
    <Button android:id="@+id/vanish"
            android:paddingTop="20dip"
            android:paddingBottom="20dip"
            android:paddingLeft="60dip"
            android:paddingRight="60dip"
            android:layout_centerInParent="true"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"
            android:text="Vanish" />
    ```

1.  在 `AnimationExamples` 项目的根包中创建一个名为 `VanishingButtonActivity.java` 的新 Java 源文件。

1.  新类需要扩展 `Activity` 并实现 `OnClickListener` 接口：

    ```kt
    public class VanishingButtonActivity extends Activity
            implements OnClickListener {
    ```

1.  重写 `onCreate` 方法并调用 `Activity.onCreate` 方法以执行所需的 Android 设置：

    ```kt
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
    ```

1.  将内容视图设置为新的 `vanish` 布局资源：

    ```kt
    setContentView(R.layout.vanish);
    ```

1.  在 XML 布局资源中找到声明的 `Button` 控件并设置其 `OnClickListener`：

    ```kt
    Button button = (Button)findViewById(R.id.vanish);
    button.setOnClickListener(this);
    ```

1.  实现 `OnClickListener` 的 `onClick` 方法：

    ```kt
    public void onClick(View clicked) {
    ```

1.  从资源文件中加载 `Animation`：

    ```kt
    Animation vanish = AnimationUtils.loadAnimation(
            this, R.anim.vanish);
    ```

1.  在 `Button` 对象上启动 `Animation`：

    ```kt
    findViewById(R.id.vanish).startAnimation(vanish);
    ```

1.  在编辑器或 IDE 中打开 `AndroidManifest.xml` 文件。

1.  在 `<application>` 部分的末尾，使用显示标签声明 `VanishingButtonActivity`：

    ```kt
    <activity android:name=".VanishingButtonActivity"
              android:label="Vanishing Button" />
    ```

1.  在编辑器或 IDE 中打开 `res/layout/main.xml` 布局资源。

1.  在 `LinearLayout` 的末尾添加一个新的 `Button` 以激活 `VanishingButtonActivity`：

    ```kt
    <Button android:id="@+id/vanish"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"
            android:layout_marginBottom="10dip"
            android:text="Vanishing Button" />
    ```

1.  在编辑器或 IDE 中打开 `AnimationSelector` Java 源文件。

1.  在 `onCreate` 方法的末尾，从布局中获取新的 `vanish Button` 并设置其 `OnClickListener`：

    ```kt
    ((Button)findViewById(R.id.vanish)).setOnClickListener(this);
    ```

1.  在 `onClick` 方法中，添加一个新的 switch case 以启动 `VanishingButtonActivity`：

    ```kt
    case R.id.vanish:
        startActivity(new Intent(
            this, VanishingButtonActivity.class));
        break;
    ```

## *刚才发生了什么？*

前述示例的添加将在屏幕中央显示一个单独的 `Button`。点击后，`Button` 将被 `vanish` 动画改变 `300` 毫秒。完成时，动画将不再对 `Button` 产生任何影响。这是动画的一个重要特点——当它们完成时，它们动画化的控件将返回到原始状态。

还需要注意到，被动画修改的不是控件本身，而是它所绘制的 `Canvas` 的状态。这与在 Java AWT 或 Swing 中修改 `Graphics` 或 `Graphics2D` 对象的状态的概念相同，在控件使用 `Graphics` 对象绘制自身之前。

在以下图片中，你可以看到当点击 `Button` 时动画对其产生的影响。实际上，`Button` 在动画的每一帧都会重新绘制，并且在那个时间保持完全活跃。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_07_06b.jpg)

# 总结

在本章中，我们探讨了将动画应用于用户界面各个部分的各种方法。我们研究了某些小部件是如何设计来自我动画化的，布局可以为了进出`Activity`而进行动画过渡。

安卓资源中默认提供了一些简单的动画，但最终，手动创建自己的动画并将它们应用到用户界面上，无疑会为用户带来最视觉吸引人且用户友好的体验。

移动设备上的许多应用程序需要在屏幕上展示大量信息，并以易于吸收的方式呈现。在下一章中，我们将探讨关于向用户友好且有用地展示信息方面的用户界面设计。这使得用户能够以快速简便的方式尽可能快地访问他们所需的信息，同时不限制他们所能获取的信息量。


# 第八章：设计内容中心式活动

*当您需要向用户展示大量数据，并且需要一个内容展示`Activity`时，通常这类 Activity 会变成以内容为中心的。内容中心式`Activity`的主要目的是在不过度压倒用户的情况下向用户提供尽可能多的信息。这是执行某种搜索或展示任何类型专业信息的应用程序的一个常见要求。*

购物及相关电子商务应用是内容中心式应用的一个理想示例。在设计过程中，大部分努力都致力于展示有关在售产品的信息。如果用户无法找到他们想要的产品信息，他们就会去其他地方寻找。因此，产品展示不仅要吸引人、易于使用，还必须尽可能提供更多信息，同时避免晦涩难懂或杂乱无章。

另一个内容中心式布局的示例是社交网络应用中的用户个人资料页面。人们通常有很多关于自己的话要说，如果没有，其他人也经常会说很多关于他们的话。这些应用不仅需要向用户展示大量信息，而且信息的质量和相关性也大不相同。仅仅因为一个用户认为某件事很重要，并不意味着下一个人也会这么认为。在这些情况下，拥有一个可以根据用户偏好定制的界面（通常只需重新组织信息展示的顺序）也非常重要，同时还能吸引用户的注意力到他们可能感兴趣的新信息或区域。

一个吸引用户注意的好方法的绝佳示例可以在聊天应用程序中看到。如果用户向上滚动，他/她可能正在阅读几分钟前说过的内容。如果此时收到一条新消息，直接将他们滚动到新消息是非常不礼貌的，因为他们可能还在阅读旧消息。用音频提示通知他们有新消息是一种常见的选择，但这也会吸引其他人对用户的注意（毕竟这是移动设备）。最佳选择是在屏幕底部显示一个小型动画图标，可能通过颜色编码来告诉用户消息的相关性（如果有的话）。这样的图标也可以是交互式元素，允许用户点击它以自动滚动到最近发布的信息。这种思维方式在设计任何应用程序时都很重要，但在构建以内容为中心的`Activity`时，在设计上多花一些心思更为关键。

在本章中，我们将探讨在向用户展示内容时需要考虑的不同方面，以及内容屏幕可以开发的多种方式。具体来说，我们将探讨：

+   设计 Android 内容展示时的思考过程

+   用户如何使用和查看内容屏幕

+   使用`WebView`类来显示内容

+   构建用于显示内容的原生布局

+   在 Android 中格式化和样式化文本

+   引导用户注意屏幕的特定区域

# 在 Android 设备上显示内容时考虑设计选项

以内容为核心的`Activity`与网页非常相似，但在设计上有一些关键考虑因素，这些是人们在创建网页时不会考虑到的。例如，触摸屏设备通常没有软件指针，因此没有“悬停”的概念。然而，许多网页是利用光标悬停来驱动从链接高亮到菜单的一切操作。

在设计以内容为核心的`Activity`时，你需要仔细考虑设计的美观性。屏幕应避免杂乱，因为许多元素可能是可交互的，当用户触摸时会呈现附加信息。同时，你应尽量减少滚动的需要，尤其是水平滚动。保持信息简洁通常是使更多元素可交互的驱动力。如前几章所述，考虑在可能的地方使用图标代替文字，并按照对用户的重要性组织信息。

还要考虑到屏幕尺寸的变化。一些设备拥有大量像素（如各种 Android 平板电脑），而其他设备则只有 3.5 英寸的小屏幕。因此，考虑到一些人可以在一个屏幕上看到所有展示的信息，而其他人可能需要三个或四个屏幕来显示相同数量的内容，这是非常重要的。

当在 Android 应用程序中工作时，网页是快速轻松地构建以内容为中心的布局的好方法。它具有 WebKit 对 HTML 和 CSS 的出色支持以及与应用程序其他部分轻松集成的优势。它还可以由现有的网页设计师处理，或者如果应用程序连接到基于网页的系统，甚至只需显示一个网页。

然而，网页在某种程度上受到 HTML 和 CSS 布局结构的限制。虽然这些在一级上非常灵活，但如果你不习惯于构建基于网页的系统，即使是针对单一的渲染引擎（在 Android 的案例中是 WebKit），HTML 和 CSS 布局开发也可能是一个繁琐和令人沮丧的过程。当涉及到动画和类似结构时，你还会受到 HTML 渲染引擎性能的进一步限制，无论使用 JavaScript 还是 CSS3 动画。

## 考虑用户行为

与任何类型的用户界面一样，了解用户的行为以及他们如何与你提供的屏幕互动非常重要。在大量内容信息的情况下，了解哪些信息是重要的，以及用户如何阅读和吸收这些信息至关重要。

虽然你可能想要吸引用户注意某个选定的信息（如价格），但运行一个循环动画来改变该元素的颜色会分散用户对屏幕上其他信息的注意力。然而，简单地改变字体、将数据放在框内，或者改变文字颜色也可以达到预期的效果。同时，考虑用户如何与屏幕互动也很重要。在触摸屏设备上，用户几乎会触摸屏幕的每一个部分。他们还会拖动看起来可以移动的项，如果内容看起来超出了屏幕长度，他们也会使用滚动手势。 

大多数人以相同的方式扫描信息。当用户第一次看到一个屏幕，或者屏幕上有大量信息时，他们阅读信息的方式大致相同。以下是用户在屏幕上寻找重要信息时眼睛会遵循的各种移动模式的说明。

![考虑用户行为](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_08_01.jpg)

你通常需要确保重要信息位于一个箭头与另一个箭头相遇的区域。最重要的区域是用户通常开始阅读的角落。对于大多数西方用户来说，这是屏幕的左上角，而亚洲和阿拉伯用户经常会从右上角开始。

### 注意事项

在设计内容屏幕时，可以考虑让这些区域的信息比正常情况下更加突出。这将产生一个“停留”时间，用户的眼光通常会在这个区域上比平时停留得更久一些。这就是为什么我们通常会在网页的左上角放置一个标志的原因。

### 吸引用户注意

几乎总是，某些信息比其他信息更重要。你希望用户能够尽可能快地识别出重要信息，并继续他们正在做的事情。一旦用户熟悉了你的应用，他们很可能会完全停止阅读细则。这是一件好事，你通过让用户继续他们的生活，帮助他们更好地使用你的应用。

当你需要吸引用户注意特定信息，如产品名称或价格时，利用`TextView`类提供的广泛选项是一个好主意。简单地改变一个项目的颜色就可以让用户注意到它。如果你需要更进一步，可以考虑添加阴影，或者将内容放在“高亮框”中。正如我们在第七章 *动画小部件和布局*中已经讨论过的，动画也可以用来吸引用户界面的特定区域。一个简单的“闪烁”动画（由淡出后紧跟淡入动画组成）可以用来吸引用户注意变化。

### 提示

**一个更具体的例子：金钱**

如果你向用户销售产品，并允许他们选择不同的运输方式和包装选项，那么根据他们的选择，总价会发生变化。确保通过加粗字体使总价突出显示。当价格更新时，通过一系列的“中间”价格循环显示，以便总价的图形“递增”或“递减”到新值。

仔细考虑你希望在用户界面中使用的控件。你可能会选择将通常为单一字段的文本放入 `TextSwitcher`（或类似控件）中，以便对单个单词或值进行动画处理，而不是使用常规的`TextView`。

# 使用 `WebView` 类显示内容

`WebView` 类（位于 `android.webkit` 包中）通常是基于内容的设计逻辑选择，并且与构建用户界面和常规的 Android XML 布局资源相比，具有非常明显的优势。`WebView` 类提供了一个单独的入口，你可以在这里放置屏幕的所有内容，它自行处理历史记录和滚动，使得你的代码非常易于编写。

当显示需要复杂布局和/或大量文本内容（可能需要标记）的内容时，`WebView` 类是一个非常好的选择。它内置支持 HTML 和 CSS 标记，减少了屏幕上所需的控件数量。鉴于 Android 使用 Web-Kit 作为渲染引擎，你还可以使用许多 CSS3 结构（如 CSS 动画）。尽管 `WebView` 通常用于类似浏览器的网络应用，其中超链接非常重要，但你也可以轻松地为其提供不包含链接的本地内容。你还可以拦截链接请求，以允许导航到应用程序的其他部分。

通常在使用 `WebView` 结构时，你需要某种方法来生成你将要显示的内容。与在布局资源中构建用户界面不同，你可以简单地为需要注入动态内容的各种 `View` 对象分配 ID。也就是说，完整的模板引擎通常比 XML 布局和 Java 代码的混合更容易使用，尽管实施的难易程度强烈依赖于你拥有的技能以及需要在屏幕上显示的信息类型。

## 使用 `WebView` 对象

为了与 `WebView` 进行一些操作，并给出一个更具体的示例，说明如何使用它来呈现大量内容，我们将构建一个 `Activity` 来在屏幕上显示食谱。在这个例子中，我们将硬编码实际的食谱和布局代码以生成 HTML。实际上，你会希望使用如 Velocity/FreeMarker 或 XSLT 这样的模板引擎来生成 HTML 代码。

# 动手实践——创建食谱查看器应用

你会注意到，以下示例没有使用 XML 布局资源，而是完全在 Java 中创建了 `Activity`。在此示例中，我们使用 `Recipe` 对象生成 HTML 代码到 `StringBuilder` 以显示。这是一个简单但有效的实现。然而，如果需要更改食谱的外观和感觉，它要求修改 Java 代码。

1.  创建一个新项目以包含食谱阅读器应用程序：

    ```kt
    android create project -n RecipeViewer -p RecipeViewer -k com.packtpub.viewrecipe -a ViewRecipeActivity -t 3
    ```

1.  在新应用程序的根包中创建一个新的 `Ingredient.java` 源文件，以保存单个所需成分的信息，并在你的编辑器或 IDE 中打开这个新文件。

1.  声明 `name`、`amount` 和 `unit` 字段，这些字段对于食谱是必需的：

    ```kt
    private final String name;
    private final double amount;
    private final String unit;
    ```

1.  创建一个构造函数以接收参数并将它们赋值给字段：

    ```kt
    public Ingredient(
            String name,
            double amount,
            String unit) {
        this.name = name;
        this.amount = amount;
        this.unit = unit;
    }
    ```

1.  为每个字段创建一个获取器方法：

    ```kt
    public double getAmount() {
        return amount;
    }

    // . . .
    ```

1.  在项目的根包中，创建一个名为 `Recipe.java` 的新源文件以包含一个单独的食谱，并在编辑器或 IDE 中打开它。

1.  声明一个字段用于 `Recipe` 对象的名称：

    ```kt
    private final String name;
    ```

1.  声明另一个字段以包含此 `Recipe` 所需的成分列表。我们将这些作为 `Ingredient` 对象的数组存储：

    ```kt
    private final Ingredient[] ingredients;
    ```

1.  然后声明一个 `String` 对象数组，该数组将包含需要遵循的 `Recipe` 指令列表：

    ```kt
    private final String[] instructions;
    ```

1.  创建一个构造函数以接受字段数据并将其赋值以存储：

    ```kt
    public Recipe(
            String name,
            Ingredient[] ingredients,
            String[] instructions) {
        this.name = name;
        this.ingredients = ingredients;
        this.instructions = instructions;
    }
    ```

1.  为这三个字段创建一个获取器方法：

    ```kt
    public Ingredient[] getIngredients() {
        return ingredients;
    }

    // . . .
    ```

1.  在此示例中，`Recipe` 类负责生成 HTML。声明一个名为 `toHtml` 的新方法：

    ```kt
    public String toHtml() {
    ```

1.  创建一个 `DecimalFormat` 对象以处理体积的格式化：

    ```kt
    DecimalFormat format = new DecimalFormat("0.##");
    ```

1.  创建一个新的 `StringBuilder` 对象以构建 HTML：

    ```kt
    StringBuilder s = new StringBuilder();
    ```

1.  追加 HTML 标题：

    ```kt
    s.append("<html>").append("<body>");
    ```

1.  追加一个一级标题元素，其中包含食谱的名称：

    ```kt
    s.append("<h1>").append(getName()).append("</h1>");
    ```

1.  追加一个二级标题元素以打开 `ingredients` 部分：

    ```kt
    s.append("<h2>You will need:</h2>");
    ```

1.  打开一个无序列表以列出食谱所需的成分：

    ```kt
    s.append("<ul class=\"ingredients\">");
    ```

1.  对于每个 `Ingredient` 对象，为新的成分打开一个列表项：

    ```kt
    for(Ingredient i : getIngredients()) {
        s.append("<li>");
    ```

1.  使用声明的 `DecimalFormat` 格式化后，将成分的量追加到 `StringBuilder`：

    ```kt
    s.append(format.format(i.getAmount()));
    ```

1.  然后追加成分的测量单位：

    ```kt
    s.append(i.getUnit());
    ```

1.  现在将成分的名称追加到 `StringBuilder`，并关闭 `ingredient` 列表项：

    ```kt
    s.append(" - ").append(i.getName());
    s.append("</li>");
    ```

1.  在关闭 for 循环后，关闭无序列表：

    ```kt
    s.append("</ul>");
    ```

1.  创建一个二级标题，打开食谱的 `Instructions` 部分：

    ```kt
    s.append("<h2>Instructions:</h2>");
    ```

1.  打开另一个无序列表以将食谱指令渲染其中：

    ```kt
    s.append("<ul class=\"instructions\">");
    ```

1.  使用 for-each 循环遍历指令数组，将它们渲染成 `StringBuilder` 中的无序列表结构：

    ```kt
    for(String i : getInstructions()) {
        s.append("<li>").append(i).append("</li>");
    }
    ```

1.  关闭无序列表和 HTML 标题，返回 `StringBuilder` 对象的 `String` 内容：

    ```kt
    s.append("</ul>");
    s.append("</body>").append("</html>");
    return s.toString();
    ```

1.  在你的编辑器或 IDE 中打开 `ViewRecipeActivity` Java 源代码。

1.  在 `onCreate` 方法中，在调用 `super.onCreate` 之后，创建一个新的 `WebView` 对象，将 `this` 作为它的 `Context` 传递给它：

    ```kt
    WebView view = new WebView(this);
    ```

1.  将`WebView LayoutParams`设置为占用所有可用的屏幕空间，因为`WebView`（与`ListView`类似）具有内置的滚动功能：

    ```kt
    view.setLayoutParams(new LayoutParams(
            LayoutParams.FILL_PARENT,
            LayoutParams.FILL_PARENT));
    ```

1.  创建一个`Recipe`对象以在`WebView`中显示，完整的食谱在本示例部分末尾：

    ```kt
    Recipe recipe = new Recipe(
            "Microwave Fudge",
            // . . .
    ```

1.  将由`Recipe`对象生成的 HTML 内容加载到`WebView`中：

    ```kt
    view.loadData(recipe.toHtml(), "text/html", "UTF-8");
    ```

1.  将`Activity`的内容视图设置为创建的`WebView`对象：

    ```kt
    setContentView(view);
    ```

## *刚才发生了什么？*

食谱查看器示例显示了一个简单的结构，可以通过多种不同的方式扩展，以易于使用的格式向用户呈现大量信息。由于`WebView`与 HTML 一起工作，使得呈现非交互式信息列表比使用`ListView`或类似结构更具吸引力。

之前使用的`loadData`方法有限制，它不允许页面轻松引用外部结构，如样式表或图片。你可以通过使用`loadDataWithBaseURL`方法来绕过这个限制，该方法与`loadData`类似，但会相对于指定的 URL 渲染页面，该 URL 可能是线上的或设备本地的。

`Recipe`对象被认为负责渲染其 HTML，这在纯 Java 情况下工作良好。你也可以将`Recipe`传递给模板引擎，或者使用访问者模式将`Recipe`对象渲染为 HTML 代码。上一个示例中`Recipe`对象的完整代码如下：

```kt
Recipe recipe = new Recipe(
    "Microwave Fudge",
    new Ingredient[]{
        new Ingredient("Condensed Milk", 385, "grams"),
        new Ingredient("Sugar", 500, "grams"),
        new Ingredient("Margarine", 125, "grams"),
        new Ingredient("Vanilla Essence", 5, "ml")
    },
    new String[]{
        "Combine the condensed milk, sugar and margarine "
        + "in a large microwave-proof bowl",
        "Microwave for 2 minutes on full power",
        "Remove from microwave and stir well",
        "Microwave for additional 5 minutes on full power",
        "Add the Vanilla essence and stir",
        "Pour into a greased dish",
        "Allow to cool",
        "Cut into small squares"
    });
```

使用`WebView`对象的 一个不利的副作用是它不符合其他小部件的外观和感觉。这就是当你将其与其他小部件放在同一屏幕上时，它不能很好地工作的原因。上一个示例的最终效果实际上是一个非交互式的网页，如下所示：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_08_02.jpg)

## 动手英雄——改进食谱查看器的观感

上一个示例生成了一个非常简单的 HTML 页面，并且没有包含任何样式。内联包含 CSS 是一个非常简单的操作，甚至可以通过从应用资源中读取样式内容来完成。创建一个 CSS，将其内联包含在 HTML 页面中，并包含如下规则：

+   设置一级标题和二级标题元素背景颜色

+   将一级标题和二级标题的字体颜色改为白色

+   将头部元素的圆角设置为五个像素

+   将列表项目符号从圆形改为方形

## 进一步使用 WebView

`WebView`类具有非常重要的功能，在处理内容屏幕时非常有用，例如，使用超链接为不太重要的内容提供一个**显示**/**隐藏**的披露部分。这需要 HTML 页面中使用 JavaScript，此时强烈建议你的应用程序使用模板引擎来生成 HTML 页面，而不是在 Java 代码中生成（因为 Java 代码将很快变得难以维护）。

`WebView`类还允许你的应用程序通过一种非常简单的机制与页面上的 JavaScript 代码交互，你可以通过这种方式将 Java 对象暴露给 JavaScript 代码。这是通过`addJavascriptInterface`方法实现的。这样，HTML 页面就可以调用你提供的 Java 对象上的动作，从而有效地允许页面控制你应用程序的一部分。如果你的内容屏幕需要执行诸如**购买**或**取消**的业务动作，可以在 JavaScript 接口对象中公开所需的功能。当用户选择**书籍**HTML 元素时，页面中的 JavaScript 可以调用你定义的`appInterface.buy();`方法。

在考虑`WebView`类时，另一个重要的特性是“缩放”控件。当向用户展示大量信息时，用户可能需要放大或缩小以使某些元素更容易阅读。要启用`WebView`的内置缩放控件，你需要访问`WebSettings`对象：

```kt
webView.getWebSettings().setBuiltInZoomControls(true);
```

`WebSettings`对象可以用来启用和禁用 WebKit 浏览器组件中可用的许多其他功能，阅读可用的文档是非常值得的。

`WebView`类的主要问题是它的外观和感觉。默认主题的 Android 应用程序在黑色背景上是浅灰色，而`WebView`类在白色背景上是黑色，这使得由`WebView`驱动的屏幕在用户看来就像是一个单独的应用程序。

解决样式问题的最简单方法似乎是将 HTML 页面样式设计得与应用程序的其他部分一样。问题是，一些设备制造商有自己的 Android 应用程序样式，所以你无法确定应用程序的其余部分看起来会是什么样子。将 HTML 页面的背景和前景改为符合标准的 Android 主题，在制造商主题的设备上运行时，可能会使其与应用程序的其他部分形成鲜明对比。

## 小测验

1.  渲染大型对象图以在`WebView`中显示的最佳方式是什么？

    1.  将其转换为 XML 并通过 XSLT 处理

    1.  将其发送到外部网络服务以进行渲染

    1.  硬编码 HTML 生成

    1.  使用简单的模板引擎

1.  你如何通过`WebView`访问外部 CSS 和图片？

    1.  使用`loadDataWithBaseURL`方法

    1.  在 HTML 页面中指定完整的 URL 路径

    1.  生成包含内联数据的 HTML 代码

1.  Android 的`WebView`使用什么渲染引擎？

    1.  Gecko

    1.  MSIE/Trident

    1.  KHTML

    1.  WebKit

# 为内容显示创建相对布局

`WebView`提供了一种简单的方式，可以轻松地向用户展示大量内容，并以易于阅读的格式呈现。它还内置了许多专为查看内容而设计的功能。然而，它并不总是提供简单的解决方案，通常不允许使用其他小部件提供的现成功能。`RelativeLayout`类提供了与`WebView`类相同的布局功能。

正如我们刚刚讨论的，`WebView`几乎像一个独立的应用程序一样突出。使用`RelativeLayout`，你将使用标准的 Android 小部件来填充你的屏幕，这意味着从一屏切换到另一屏时，外观和感觉不会有任何变化。而`WebView`需要某种模板引擎（无论是 API 中的，还是在示例中简单的`StringBuilder`），`RelativeLayout`可以声明为应用程序资源中的 XML 文件。使用布局文件还意味着屏幕布局将通过资源选择过程进行选择，从而可以实现难以用`WebView`类和 HTML 代码实现的复杂自定义。

在某种意义上，使用`RelativeLayout`提供了一种模板引擎的形式。只需为需要用数据填充的`View`对象提供 ID，就可以通过将这些暴露的对象注入相关内容来填充屏幕。当我们构建基于 HTML 的视图时，我们需要为成分列表和说明列表创建标题元素，如果使用编码的布局结构，这些标题将从布局文件中加载，或从字符串束资源中加载。

在处理信息列表时，这是内容布局的常见要求，你可以以多种不同的方式提供数据。你可以使用`ListView`对象，或者你可以使用嵌入式`LinearLayout`作为列表。在使用它们中的任何一个时，建议有一个可以重复用于列表中每个项目的布局资源。使用`ListView`意味着你有了一个`Adapter`，通过它你可以将数据对象转换为可以在屏幕上显示的`View`对象。然而，`ListView`对象还有各种其他限制（如包含项目的大小），最好在它们显示的项目以某种方式交互时使用。如果你需要一个非交互式的项目列表（或网格），最好通过创建一个负责根据你的数据对象创建`View`对象的单独类来遵循`Adapter`机制。

## 充分利用 RelativeLayout

`RelativeLayout`结构的主要优势在于它们可以直接与你的应用程序的其余部分集成。它们比 HTML 页面更容易本地化。直接`ViewGroup`结构提供的事件结构比通过其专用的事件监听器和 JavaScript 的`WebView`对象提供的事件结构更为灵活。

XML 布局结构也提供了与模板引擎类似的效果，无需导入像 XSLT 引擎、Java 模板引擎这样的外部 API，或者硬编码 HTML 生成。标准的 Android `Activity` 类也内置了与 Android 动画结构工作的功能。虽然 `WebView` 类允许使用 CSS 动画或运行 JavaScript 动画，但这需要为动画的每一帧重新布局 HTML 结构。

一个实现了整个内容屏幕的 Android `Activity` 类还有个优点，那就是它可以从应用程序资源结构中加载外部资源。这不仅使得你能够更容易地本地化图像等资源，也意味着所有资源都会通过资源编译器处理，因此可以通过 Android 工具链进行优化。而使用 `WebView` 的话，你需要一个基本 URL 来加载这些资源，或者能够将它们内嵌编码在 HTML 页面中。

## 考虑到 Android 布局的限制

完全将内容视图开发为 Android 布局有一些缺点。从技能角度来看，只有开发者能够构建和维护用户界面。这也意味着任何针对单个小部件的样式设计都必须由开发者管理。而基于 `WebView` 的布局，布局的大部分创建工作可以由网页开发人员和图形设计师来处理。

### 注意

向屏幕上添加更多小部件会带来另一个问题——性能。不仅更大、更复杂的布局可能导致用户体验非常缓慢，还可能导致你的 `Activity` 完全崩溃。

屏幕上保持较少的小部件意味着用户一次需要吸收的信息量会减少，界面也将更容易操作。

过长或过深的布局会导致应用程序崩溃。如果你需要让句子中的一个单词动起来，你将不得不定义两个额外的 `TextView` 小部件，用来显示动画单词两侧的非动画文本。这增加了你的布局长度。如果你还需要一个水平 `LinearLayout` 来放置这三个 `TextView` 对象，你将增加布局结构的深度。考虑到这两个限制，你可以想象在布局渲染时，你很快就会耗尽内存或处理能力。每个小部件在渲染之前都必须进行布局测量。每次测量、布局步骤或渲染步骤都会通过递归调用方法来使用语言堆栈，以确保所有小部件在屏幕上的正确位置正确渲染（或者如果它们在屏幕外则不渲染）。Android 中的软件堆栈大小是有限的，每次方法调用都需要将其参数推送到堆栈上以进行调用。除此之外，所有测量信息都需要存储在堆空间中，这也是 Android 平台上另一个严重受限的资源（默认情况下，Dalvik VM 只分配了 8 MB 的堆空间开始）。

下图展示了布局结构的长度和深度的区别。左边的屏幕展示了一个长布局，而右边的屏幕展示了一个深布局：

![考虑 Android 布局限制](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_08_03.jpg)

## 设置 `TextView` 对象的样式

在这一点上，考虑如何让句子中的一个单词变粗体，或者给它加个阴影，这似乎令人担忧。在 `WebView` 中，只需添加一个带有特殊样式的 `<span>` 元素就很容易实现，但在原生布局中，难道你需要为文本的每个部分添加单独的 `TextView` 对象吗？如果是这样，你将极大地限制能够向用户显示的文本量，因为你将创建成千上万的几乎无用的对象。

幸运的是，Android 非常容易地对所有默认小部件中的文本进行标记。任何从 `TextView` 继承的类都可以处理带有样式信息或甚至图片的文本。通常，`android.text.style` 包中可用的类可以用来设置你想要显示的文本字符串的子片段的样式。

为了使用这些不同的样式结构，你需要使用一个`SpannableString`对象。`SpannableString`是 Android 字符串的一种特殊类型，它记录了一个需要显示的正常`CharSequence`文本的样式信息。还有其他一些类似的类（如`SpannableStringBuilder`），它们处理文本的简单修改，因此适合于将被编辑的文本。出于我们当前的目的，`SpannableString`是完美的，而且更简单易用。`SpannableString`有一个基于`Spannable`接口需要实现的方法——`setSpan`。`setSpan`方法允许你向`SpannableString`添加标记结构，这些标记结构影响文本特定部分的渲染方式。

如果我们只想在屏幕上写下**There is nothing to fear!**这个文本，你通常会使用一个指定字符串的`TextView`对象。但如果我们想将字符串中的**nothing**划掉呢？现在的方法是使用`StrikethroughSpan`对象来处理第 9 到 16 个字符。在这种情况下，字符串不能只在布局文件中定义，需要在 Java 代码中创建一个`SpannableString`。以下是实现此操作的一个简单示例，以及结果`TextView`的外观：

```kt
TextView fear = new TextView(this);
SpannableString string = new SpannableString(
        "There is nothing to fear!");
string.setSpan(new StrikethroughSpan(), 9, 16, 0);
fear.setText(string);
```

这段 Java 代码的结果是一个`TextView`小部件，它显示的是样式化的内容，而不是普通的`String`，如下面的截图所示：

![样式化 TextView 对象](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_08_04.jpg)

如你所见，使用这种标记非常有效，而且实际上非常容易操作。与`WebView`渲染相比，这个示例的执行速度也非常快，因为它不包含任何形式的解析。

然而，这种机制存在一些问题。最重要的是索引处理。为了知道何时开始或结束标记渲染的`Span`，你需要指定需要用给定`Span`渲染的第一个和最后一个字符。除非你计划更改文本，甚至更糟——国际化它，否则这不是问题。

幸运的是，Android 已经有一个内置的解决方案，尽管这会牺牲一些性能。你可以将几乎任何 HTML 文本转换成一个`Spannable`对象，然后这个对象可以直接传递给任何`TextView`对象进行渲染。要使用的类是`android.text.Html`类，它包括用于将 HTML 代码解析为`Spannable`对象的实用方法，以及将`Spannable`对象转换为 HTML 代码的方法。

如果你需要国际化打算用额外样式属性渲染的字符串，`Html`类可能是唯一合理的做法。它还有一个额外的好处，即图片加载可以由你的应用程序处理（通过使用`Html.ImageGetter`接口）。此外，`TextView`仍然看起来和感觉像一个正常的 Android 小部件，这增强了用户的体验。

`Html`类处理大多数 HTML 标签，但并非所有。一方面，CSS 样式被忽略，因此颜色和边框不在考虑之列。然而，仍然可以实现很好的样式，至少你不需要在应用程序资源中记录字符索引值，以便所有样式对齐。

如果你想将`Button`标签中的文本设置为粗体，使用`Html`类可以轻松实现。直接将`fromHtml`方法的结果传递给`TextView`对象要快得多。例如，以下代码片段将生成一个`Button`对象，其中单词**Hello**会以斜体显示，而单词**World**则具有粗体权重：

```kt
Button button = new Button(this);
button.setText(Html.fromHtml("<i>Hello</i> <b>World!</b>"));
```

你还可以在布局资源 XML 文件中指定 HTML 内容，它将在传递给`TextView`对象的`setText`方法之前通过`Html`类进行解析。

上面的 Java 代码片段创建了一个`Button`小部件，其外观如下所示：

![设置 TextView 对象的样式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_08_05.jpg)

HTML 标签也可以用于将迷你文档渲染到`TextView`对象中，尽管它们具有自己的样式，但也会遵循`TextView`对象的样式。这意味着，如果你需要一个比`WebView`更快速处理静态文本（且不含超链接）的解决方案，`TextView`实际上可以作为一个很好的替代品。例如，考虑以下代码片段：

```kt
TextView text = new TextView(this);
text.setTextColor(0xff000000);
text.setBackgroundColor(0xffffffff);
text.setText(Html.fromHtml(
        "<h1>Cows Love to Eat Grass</h1>"
        + "<p>Do not fear the Cow</p>"));
```

这将渲染一个带有第一级标题和单行段落元素的`TextView`。两者都将包含一些内边距，以便与屏幕上的其他元素保持距离。生成的图像应该看起来相当熟悉：

![设置 TextView 对象的样式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_08_06.jpg)

如你所见，正确设置了样式的`TextView`可以成为`WebView`的优秀替代品，特别是当你将其与一系列原生小部件并列使用时。然而，黑底白字的样式确实带来了不一致的问题。因此，除非你的整个应用程序遵循这种模式，否则最好将样式保留为默认。

如果你打算使用`TextView`显示较长的内容，需要考虑一些额外的因素：

+   确保如果文本长度超过用户屏幕尺寸，用户将能够滚动。这很容易做到，只需将`TextView`放置在`ScrollView`对象中。

+   如果你的文本非常长，考虑对内容进行样式设计，要么使文本更亮白，要么使用黑底白字。虽然这与其他 Android 应用程序以及你自己的应用程序中的其他屏幕非常不一致，但它对眼睛来说要轻松得多，你的用户会为此感谢你。

+   考虑允许用户通过长按或菜单更改字体大小。如果他们的屏幕是低密度的，或者他们视力不佳，你可能使他们的生活变得稍微轻松一些。

## 小测验

1.  如果需要显示一个非交互式的项目符号列表，以下哪个更合适？

    1.  带有无序列表的`WebView`

    1.  一个特别样式的`ListView`对象

    1.  一个带有 HTML 内容的`TextView`对象

1.  关于超链接，你可能使用`WebView`而不是`TextView`，因为：

    1.  `TextView`不能处理超链接

    1.  在`WebView`中显示效果更佳

    1.  `WebView`具有内置的历史管理功能

1.  对于动画密集型应用，原生接口效果更好，因为：

    1.  你可以使用 Android 动画资源文件

    1.  `WebView`类不处理动画

    1.  HTML 动画运行成本更高

# 是时候采取行动了——开发专用内容视图

在许多情况下，你需要一种特定的交互逻辑，以便在应用程序的许多部分重复使用。在内容屏幕上，某些显示区域将需要更新，由显示的其他部分的变化来驱动。这通常是因为屏幕的一部分在向用户传递信息，而其他部分则在从用户那里捕获新数据。接下来，我们将构建一个简单的控件，负责向用户显示金额。它存在的主要原因是它不仅在变化之间进行动画处理，而且通过改变颜色来反馈给用户金额是上升还是下降。

1.  创建一个名为`AmountBox.java`的新 Java 源文件用于新类，并在编辑器或 IDE 中打开新文件。

1.  新类应扩展`TextSwitcher`类并实现`ViewSwitcher.ViewFactory`接口：

    ```kt
    public class AmountBox extends TextSwitcher
            implements ViewSwitcher.ViewFactory {
    ```

1.  声明一个字段用于`DecimalFormat`，以便渲染金额：

    ```kt
    private DecimalFormat format = new DecimalFormat("0.##");
    private double amount;
    ```

    同时声明一个字段来存储当前显示的数值：

1.  声明从`TextSwitcher`类提供的两个构造函数的副本，以允许`LayoutInflator`类从资源文件实例化`AmountBox`类：

    ```kt
    public AmountBox(Context context, AttributeSet attrs) {
        super(context, attrs);
        init();
    }
    public AmountBox(Context context) {
        super(context);
        init();
    }
    ```

1.  声明`init()`方法以处理“常见构造函数”的要求：

    ```kt
    private void init() {
    ```

1.  将“进入”和“退出”动画设置为 Android 提供的淡入淡出动画：

    ```kt
    setOutAnimation(getContext(), android.R.anim.fade_out);
    setInAnimation(getContext(), android.R.anim.fade_in);
    ```

1.  接下来，将`ViewFactory`设置为`AmountBox`：

    ```kt
    setFactory(this);
    ```

1.  最后，调用`setAmount(0)`以确保显示的金额已指定：

    ```kt
    setAmount(0);
    ```

1.  声明一个 setter 方法，以允许覆盖默认的`DecimalFormat`：

    ```kt
    public void setFormat(DecimalFormat format) {
        this.format = format;
    }
    ```

1.  声明一个 getter 方法，以便轻松访问当前数值：

    ```kt
    public double getAmount() {
        return amount;
    }
    ```

1.  重写`ViewFactory`的`makeView()`方法：

    ```kt
    public View makeView() {
    ```

1.  使用传递给此`AmountBox`的上下文创建一个新的`TextView`对象：

    ```kt
    TextView view = new TextView(getContext());
    ```

1.  指定一个较大的文本大小，因为该数量将表示货币，然后返回`TextView`对象以显示：

    ```kt
    view.setTextSize(18);
    return view;
    ```

1.  现在声明一个设置器方法，以允许更改金额值：

    ```kt
    public void setAmount(double value) {
    ```

1.  这个方法将改变文本的颜色，因此声明一个变量来显示新的文本`颜色`：

    ```kt
    int color;
    ```

1.  首先检查我们应该将文本更改为哪种`颜色`：

    ```kt
    if(value < amount) {
        color = 0xff00ff00;
    } else if(value > amount) {
        color = 0xffff0000;
    } else {
        return;
    }
    ```

1.  获取屏幕外的`TextView`对象：

    ```kt
    TextView offscreen = (TextView)getNextView();
    ```

1.  根据数值的变化设置字体颜色：

    ```kt
    offscreen.setTextColor(color);
    ```

1.  在文本周围渲染阴影以产生“光晕”效果：

    ```kt
    offscreen.setShadowLayer(3, 0, 0, color);
    ```

1.  将`TextView`的文本设置为新的值：

    ```kt
    offscreen.setText(format.format(value));
    ```

1.  显示屏幕外的`TextView`并记住新值：

    ```kt
    showNext();
    amount = value;
    ```

## *刚才发生了什么？*

`AmountBox`类是一个需要更新内容的小单元的很好例子。这个类向用户提供信息，同时也提供了一种反馈形式。当用户执行影响显示金额的操作时，`AmountBox`通过更新字体颜色来反映变化的方向——金额减少时为绿色，金额增加时为红色。

示例使用了第七章讨论的标准 Android 淡入淡出动画，即*动画小部件和布局*。动画的速度为两个金额之间的交叉淡入效果提供了很好的效果。注意在`setAmount`方法中，文本内容的更新和`View`对象的切换是手动处理的。

你可能可以用一个`setText`方法的调用替换`offscreen.setText`和`showNext`方法的调用，但了解它内部的工作原理很有趣。此方法也不受未来实现变更的影响。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_08_07.jpg)

# 开发在线音乐商店

一个以内容为中心的布局的绝佳例子是嵌入媒体播放器应用程序中的音乐商店。直接从媒体播放器购买音乐的能力是一个极大提升用户体验的功能，并且与 Android 应用程序作为“连接”应用程序的行为而非纯粹的离线系统相得益彰。Android 还使得将商店真正集成到应用程序中变得非常简单，而不仅仅是提供到适当网站的链接。通常，如果用户点击**购买音乐**按钮而没有突然跳转到网页浏览器，他们会更有信任感。将应用程序的在线和离线部分正确集成，对于你的销售统计也能起到很大的作用。

在线购买音乐与在商店购买音乐非常不同。关于用户正在查看的歌曲、艺术家或专辑的附加信息是吸引人的部分。因此，一个针对移动设备的在线音乐商店必须精心设计，以提供尽可能多的信息，同时不使屏幕显得杂乱，也不偏离用户购买音乐的初衷。与应用程序的整合感也有助于建立用户信任，因此外观和感觉非常重要。在线购买音乐的另一个优点是，你只需为你想购买的内容付费。为此，用户界面需要允许用户选择他们想从专辑中购买的曲目，以及他们不想购买或计划以后购买的曲目。另外，他们如何知道哪些是他们喜欢的？他们还需要能够播放每首曲目的样本（无论是限时播放，还是只是低质量的）。

## 设计音乐商店

要真正说明以内容为中心的设计是如何结合在一起的，你需要构建一个。在这个例子中，我们将通过设计过程以及该设计的实现来工作。由于设计和实现是这里的重要部分，我们不会深入构建一个功能性的示例。它只是一个漂亮的屏幕。

首先，我们需要有一个基本的用户界面设计。我发现最好是从一块白板或一张纸和一支笔开始。尽管市面上有很多绘制模拟屏幕的工具，但没有一个能真正接近纸和笔的用户界面。首先，我们绘制一个高级线框，展示整个屏幕设计。这只是一系列告诉我们在屏幕的哪些部分显示什么类型信息的盒子。

![设计音乐商店](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_08_08.jpg)

在图表中，我们将用户界面分成了三个部分：

+   专辑和艺术家信息区域：这一区域显示用户想要购买专辑的名称和封面艺术。

+   曲目列表区域：在这个区域，用户可以试听样本，并选择他们想要购买的曲目。

+   购买区域：这一区域显示用户将支付的总金额，以及一个购买选定曲目的按钮。

在上一个图表中，我遵循了屏幕的大小，但根据屏幕大小和可用的曲目数量，用户界面可能需要一个滚动条才能完全访问。

接下来的工作是对我们定义的用户界面的每个部分进行查看，并决定将哪些小部件放入它们中。首先，我们需要查看专辑和艺术家信息。专辑信息将作为专辑封面艺术和专辑名称显示。我们将包括一个用于艺术家标志的图像区域，并包括一个带有录音标签名称的文本块。

![设计音乐商店](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_08_09.jpg)

这样一个简单的块状图可以让你直观地考虑各种元素。它还允许你开始考虑诸如字体大小、边框和间距等因素。在上述图表中，我们希望右侧的三个元素大致与左侧的封面艺术大小相同。不幸的是，Android 的 `RelativeLayout` 类目前不允许我们直接规定这一点作为约定。接下来我们需要考虑的设计元素是音轨列表框。对于这个，我们不是在框中绘制所有内容，而是专注于单行外观及其包含的信息。

![设计音乐商店](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_08_10.jpg)

上述结构是一个非常简单的单行结构，用于显示单个音轨的详细信息。左侧的 `CheckBox` 可用于选择用户想要购买的音轨，而右侧的按钮可用于播放给定音轨的样本。两侧类似按钮的元素为中间的纯文本元素创建了一种框架。

最后，我们需要考虑我们打算如何让用户支付他们的钱。这是用户界面非常重要的部分，它需要清晰明了——他们预期要支付的金额。我们还需要让用户实际进行交易变得非常容易，所以需要一个单一的 **购买** 或 **购买选定音轨** 按钮。

![设计音乐商店](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_08_11.jpg)

用户界面的最后一部分仅包含两个小部件，左侧用于购买，右侧显示用户预期支付的总金额。对于左侧的按钮，我们将使用一个简单的 Android `Button` 小部件，而在右侧，我们将使用本章前一部分编写的新的 `AmountBox`。

## 开发音乐商店

我们将从构建一系列新的模型类开始新的示例，但首先你需要为我们的概念性媒体播放器创建一个新项目。为此，在命令行或控制台上运行以下命令：

```kt
android create project -n PacktTunes -p PacktTunes -k com.packtpub.packttunes -a ShopActivity -t 3
```

创建新项目后，将 `AmountBox` 源代码复制到新项目的根包中。然后，你需要创建一个类来包含单个音轨的数据。这只需存储音轨的名称和以秒为单位的音轨时长。我们还将包括一些实用方法，用于计算我们可以用来显示时长数据的分：秒值。

```kt
public class Track {
    private final String name;
    private final int length;

    public Track(final String name, final int length) {
        this.name = name;
        this.length = length;
    }

    public String getName() {
        return name;
    }

    public int getLength() {
        return length;
    }

    public int getMinutes() {
        return length / 60;
    }

    public int getSeconds() {
        return length % 60;
    }
}
```

`Track` 类是一个非常简单的结构，可以很容易地从 XML 解析或从二进制流反序列化。我们还需要另一个类来保存关于单个艺术家的信息。虽然以下类实际上不过是数据存储的一种形式，但很容易扩展以存储如需的生物信息：

```kt
public class Artist {
    private final Drawable logo;
    private final String description;

    public Artist(
            final Drawable logo,
            final String description) {

        this.logo = logo;
        this.description = description;
    }

    public String getDescription() {
        return description;
    }

    public Drawable getLogo() {
        return logo;
    }
}
```

最后，在数据类方面，我们需要一个类来将前两个类连接到一个单一的专辑。这个类将被用作可以传递给`Activity`的单一点。将以下代码复制到项目根包中名为`Album.java`的新文件中：

```kt
public class Album {
    private final Drawable cover;
    private final String name;
    private final Artist artist;
    private final String label;
    private final Track[] tracks;

    public Album(
            final Drawable cover,
            final String name,
            final Artist artist,
            final String label,
            final Track... tracks) {

        this.cover = cover;
        this.name = name;
        this.artist = artist;
        this.label = label;
        this.tracks = tracks;
    }

    public Drawable getCover() {
        return cover;
    }

    public Artist getArtist() {
        return artist;
    }

    public String getLabel() {
        return label;
    }

    public String getName() {
        return name;
    }

    public Track[] getTracks() {
        return tracks;
    }
}
```

# 动手时间——构建一个轨道条目

要开始新的用户界面工作，你需要一些图片。在接下来的部分，你需要一个用于播放按钮的图片。播放图片应该是一个简单的“播放”箭头，我们将它放入的按钮会提供背景和边框。列表结构中的行将被放入一个`TableLayout`中，以便对齐所有子结构。

1.  在项目的`res/layouts`目录中创建一个新的布局资源文件，并将新文件命名为`track.xml`。

1.  将新文件的根元素声明为一个`TableRow`元素，占用所有可用宽度和所需高度：

    ```kt
    <TableRowandroid:layout_width="fill_parent"android:layout_height="wrap_content">
    ```

1.  作为`TableRow`的第一个元素，创建一个`CheckBox`，用户可以使用它来选择和取消选择他们想要购买的轨道：

    ```kt
    <CheckBox android:id="@+id/selected"
              android:checked="true"
              android:layout_width="wrap_content"
              android:layout_height="wrap_content"/>
    ```

1.  声明一个`TextView`元素，以比通常更大的字体显示轨道名称，并使用纯白色字体颜色：

    ```kt
    <TextView android:id="@+id/track_name"
              android:textSize="16sp"
              android:textColor="#ffffff"
              android:layout_width="wrap_content"
              android:layout_height="wrap_content"/>
    ```

1.  在`TextView`轨道名称后面跟随另一个右对齐的`TextView`对象，用于显示轨道的时长：

    ```kt
    <TextView android:id="@+id/track_time"
              android:gravity="right"
              android:layout_width="wrap_content"
              android:layout_height="wrap_content"/>
    ```

1.  以一个`ImageButton`元素结束`TableRow`元素，用户可以使用它来在购买前试听轨道：

    ```kt
    <ImageButton android:id="@+id/play"
                 android:src="img/play"
                 android:layout_width="wrap_content"
                 android:layout_height="wrap_content"/>
    ```

## *刚才发生了什么*

上面的布局资源文件将处理用户界面第二部分轨道列表项的布局。我们需要能够创建几个这样的结构，以处理专辑中所有可用的轨道。我们将它们包裹在一个`TableRow`元素中，当它被放入一个`TableLayout`对象时，会自动将其子元素与其他行中的元素对齐。

之后，在 Java 代码中，我们将使用`LayoutInflator`加载这个资源，用轨道的名称和时长填充它，然后将其添加到一个`TableLayout`对象中，这个对象我们将作为主用户界面的一部分进行声明。一旦这个新项目被填充了一些数据，它看起来将类似于以下的截图：

![刚才发生了什么](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_08_12.jpg)

# 动手时间——开发主用户界面布局

建立了后来将变成列表中轨道条目的布局资源文件后，我们现在需要定义这个用户界面的其余元素。虽然这个结构相对简单，但它也非常容易扩展，并且有一些小细节让它看起来非常棒。它还需要一些 Java 代码才能正确填充，但我们在完成资源文件后会涉及到这些内容。

![动手时间——开发主用户界面布局](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484OS_08_13.jpg)

1.  创建或打开新项目中的`res/layout/main.xml`文件。

1.  为了处理主布局可能超出可用屏幕空间的情况，主布局的根元素需要是一个`ScrollView`。`ScrollView`应占据所有可用屏幕空间：

    ```kt
    <ScrollView

        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  作为`ScrollView`的唯一元素，声明一个`RelativeLayout`，它占据可用宽度，但只有所需的高度。`RelativeLayout`应在顶部和底部包含一些内边距，以提供一些“呼吸空间”，使其内容不会显得过于拥挤：

    ```kt
    <RelativeLayout android:layout_width="fill_parent"
                    android:layout_height="wrap_content"
                    android:paddingTop="10dip"
                    android:paddingBottom="10dip">
    ```

1.  `RelativeLayout`的第一个元素是专辑封面，这是一个固定大小的`ImageView`对象，它将适应可用空间中的专辑封面艺术：

    ```kt
    <ImageView android:id="@+id/artwork"
               android:scaleType="fitCenter"
               android:gravity="left"
               android:layout_alignParentTop="true"
               android:layout_alignParentLeft="true"
               android:layout_width="84dip"
               android:layout_height="84dip"/>
    ```

1.  专辑封面之后的第二个元素是艺术家的标志图像，也是一个`ImageView`。这个元素需要将标志在可用空间中居中显示：

    ```kt
    <ImageView android:id="@+id/artist_logo"
               android:adjustViewBounds="true"
               android:scaleType="center"
               android:layout_alignParentTop="true"
               android:layout_toRightOf="@id/artwork"
               android:layout_width="fill_parent"
               android:layout_height="wrap_content"/>
    ```

1.  在艺术家标志之后，我们需要一个简单的`TextView`对象，并应用一些字体样式来显示我们试图销售的专辑名称。我们将按照之前看到的图像，在用户界面中将此放置在艺术家标志下方：

    ```kt
    <TextView android:id="@+id/album_label"
              android:gravity="center"
              android:textSize="22dip"
              android:textColor="#ffffff"
              android:textStyle="bold"
              android:layout_below="@id/artist_logo"
              android:layout_toRightOf="@id/artwork"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  在带有专辑名称的`TextView`下方，我们有一个小的非样式的`TextView`来显示发行专辑的唱片公司名称：

    ```kt
    <TextView android:id="@+id/record_label"
              android:gravity="center"
              android:layout_below="@id/album_label"
              android:layout_toRightOf="@id/artwork"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
    ```

1.  如承诺的那样，在这些元素之后，我们使用一个`TableLayout`来保存可用的曲目信息。我们将`TableLayout`元素与专辑艺术相对齐，而不是与唱片公司`TextView`相对齐：

    ```kt
    <TableLayout android:id="@+id/track_listing"
                 android:stretchColumns="1"
                 android:layout_below="@id/artwork"
                 android:layout_width="fill_parent"
                 android:layout_height="wrap_content"/>
    ```

1.  在曲目列表下方，我们首先将**购买选定曲目**的按钮元素放置在屏幕左侧：

    ```kt
    <Button android:id="@+id/purchase"
            android:text="Buy Selected Tracks"
            android:layout_below="@id/track_listing"
            android:layout_alignParentLeft="true"
            android:layout_width="wrap_content"
            android:layout_height="wrap_content"/>
    ```

1.  最后，在屏幕右侧，我们添加了自定义的`AmountBox`小部件，在这里我们将告诉用户他们将支付多少费用：

    ```kt
    <com.packtpub.packttunes.AmountBox
        android:id="@+id/purchase_amount"
        android:layout_alignBaseline="@id/purchase"
        android:layout_alignParentRight="true"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content
    ```

## *刚才发生了什么？*

在前面的布局中，每个指定的部件都通过提供信息给用户或从用户那里收集新信息来发挥重要作用。尽可能的，我们只给用户提供了对他们来说重要的信息。封面艺术和艺术家标志通常是人们识别特定专辑的第一方式，而名称可能是第二识别方式。专辑封面艺术中的颜色和形状通常比表明专辑名称的文本更快被人的大脑识别。

所有顶部元素：封面艺术、艺术家标志、专辑名称和唱片公司，都可以做成交互式元素，将用户带到包含所选元素更多信息屏幕。链接的信息可能包括评论、讨论论坛和评分小部件。另一个很好的补充是将所选专辑或艺术家的音乐视频链接过来（如果有）。

还要注意我们在购买区域的底部。`AmountBox`已经与“购买按钮”小部件的“基线”对齐。在这种情况下，它将这些两个小部件中的文本基线对齐，使它们相互看起来居中，尽管这是一种美学上的居中，而不是精确的计算。

# 动手实践——开发主要用户界面 Java 代码

为了将这个例子完整地组合在一起，并拥有一个以内容为中心的屏幕（尽管仅在示例意义上），我们需要一些 Java 代码。这段代码将处理用`Album`对象填充用户界面布局。对于接下来的这段代码，你需要封面艺术和艺术家标志的图片。

1.  在编辑器或 IDE 中打开`ShopActivity` Java 源文件。

1.  在`onCreate`方法中，确保将`main.xml`布局资源设置为`ShopActivity`的内容视图：

    ```kt
    setContentView(R.layout.main);
    ```

1.  获取应用资源，并用你最喜欢的音乐专辑的内容调用一个新的`setAlbum`方法：

    ```kt
    Resources resources = getResources();
    setAlbum(new Album(
            resources.getDrawable(R.drawable.album_art),
            "The Android Quartet",
            new Artist(resources.getDrawable(R.drawable.sherlock),
            "Sherlock Peterson"),
            "Green Records",
            new Track("I was a robot", 208),
            new Track("Long is not enough time", 243),
            new Track("The rocket robot reel", 143),
            new Track("I love by bits", 188)));
    ```

1.  声明`setAlbum`方法以接受一个`Album`对象：

    ```kt
    private void setAlbum(Album album) {
    ```

1.  获取用户界面的`track_listing`部分，并使用新的`addTrackView`方法将每个音轨添加到显示中：

    ```kt
    ViewGroup tracks = (ViewGroup)findViewById(R.id.track_listing);
    for(Track t : album.getTracks()) {
        addTrackView(tracks, t);
    }
    ```

1.  获取专辑封面艺术部件并设置其内容：

    ```kt
    ImageView albumArt = (ImageView)findViewById(R.id.artwork);
    albumArt.setImageDrawable(album.getCover());
    ```

1.  获取艺术家的标志部件并设置其内容：

    ```kt
    ImageView artistLogo = (ImageView)findViewById(R.id.artist_logo);
    artistLogo.setImageDrawable(album.getArtist().getLogo());
    ```

1.  获取专辑名称部件并设置其内容：

    ```kt
    TextView albumLabel = (TextView)findViewById(R.id.album_label);
    albumLabel.setText(album.getName());
    ```

1.  获取唱片公司部件并设置其内容：

    ```kt
    TextView recordLabel =
            (TextView)findViewById(R.id.record_label);
    recordLabel.setText(album.getLabel());
    ```

1.  获取`AmountBox`部件，并将其格式设置为货币格式，然后将其值设置为`1.99`乘以音轨的数量：

    ```kt
    AmountBox amount =
            (AmountBox)findViewById(R.id.purchase_amount);
    amount.setFormat(new DecimalFormat("$ 0.##"));
    ```

1.  声明`addTrackView`方法，并像之前一样使用它：

    ```kt
    private void addTrackView(ViewGroup tracks, Track track) {
    ```

1.  使用`LayoutInflator`来填充`track`布局资源：

    ```kt
    LayoutInflater inflater = getLayoutInflater();
    ViewGroup line = (ViewGroup)inflater.inflate(
            R.layout.track,
            tracks,
            false);
    ```

1.  从新的`ViewGroup`中获取音轨名称部件，并设置其内容：

    ```kt
    TextView trackName =
            (TextView)line.findViewById(R.id.track_name);
    trackName.setText(track.getName());
    ```

1.  从新的`ViewGroup`中获取音轨时长部件，并创建一个`StringBuilder`用来显示音轨时长：

    ```kt
    TextView trackTime =
            (TextView)line.findViewById(R.id.track_time);
    StringBuilder builder = new StringBuilder();
    ```

1.  将分钟数和一个分隔符追加到`StringBuilder`中：

    ```kt
    builder.append(track.getMinutes());
    builder.append(':');
    ```

1.  如果秒数小于`10`，我们需要一个前缀`'0'`字符：

    ```kt
    if(track.getSeconds() < 10) {
        builder.append('0');
    }
    ```

1.  将时长中的秒数追加：

    ```kt
    builder.append(track.getSeconds());
    ```

1.  设置时长部件的文本，并将新行添加到“音轨”列表中：

    ```kt
    trackTime.setText(builder.toString());
    tracks.addView(line);
    ```

## *刚才发生了什么？*

前面的 Java 代码足以将`Album`对象中的数据复制到用户界面。一旦显示在屏幕上，它看起来像一个简单的音乐商店页面，但主题为 Android 应用程序。这提供了与网页在布局结构和易于维护方面的许多好处，同时完全集成到最终用户设备上可能存在的任何品牌和样式。一旦显示在屏幕上，之前的示例将呈现给你类似以下截图的东西：

![刚才发生了什么?](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_08_14.jpg)

## 动手英雄——更新总价

为了让之前的例子感觉更加真实，当用户从专辑列表中选择或取消选择音轨时，它需要更新屏幕底部的总金额。如果没有任何音轨被选择，它还应该禁用**购买选定音轨**按钮。

尝试为音轨布局中的每个`CheckBox`元素添加一个事件监听器，并跟踪哪些被选中。为了显示总金额，将`1.99`乘以被选中的音轨数量。

# 总结

在本章中，我们已经深入探讨了在向用户展示大量信息或内容时使用的许多重要领域和技术。在开始构建之前，仔细考虑你的界面是很重要的，但同时也不要在动手编码之前花费太多时间。有时，一个简单的用户界面运行起来能告诉你的东西，比你的图表和模型所能展示的要多得多。

我们已经使用`WebView`类完成了一个显示食谱给用户的示例，展示了在 Android 平台上使用 HTML 是多么简单。我们还通过构建一个在线音乐商店，使用`RelativeLayout`来显示内容，探讨了与 HTML 视图相对的原生替代方案。通过这两个示例，我们比较了两种机制之间的差异，并洞察了各自最佳使用场景。

在决定如何展示内容时，请务必考虑性能和用户体验。虽然`WebView`在某些方面可能更具灵活性，允许你根据显示的内容改变视图，但也可能导致不一致性，并让用户感到烦恼。`RelativeLayout`提供了更刚性的结构，并且还将确保代码库更加一致。

在下一章中，我们将更详细地探讨如何为你的 Android 应用程序添加更多样式。我们还将研究如何最佳地处理设备和配置的变化（例如语言变化或从竖屏模式切换到横屏模式）。
