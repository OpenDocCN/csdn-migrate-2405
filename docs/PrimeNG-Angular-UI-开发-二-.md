# PrimeNG：Angular UI 开发（二）

> 原文：[`zh.annas-archive.org/md5/F2BA8B3AB075A37F3A10CF12CD37157B`](https://zh.annas-archive.org/md5/F2BA8B3AB075A37F3A10CF12CD37157B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：增强输入和选择

本章介绍了增强功能的常用输入和选择组件，适用于任何类型的应用程序或网站。这些组件是每个 Web 应用程序的主要部分。每个组件的所有功能将涵盖您在开发项目时可能遇到的许多实时用例。在创建登录表单、注册表单或任何类型的表单填写应用程序时，输入和选择组件是首要考虑的因素。由于 Web 使用的快速革命和技术改进，需要各种增强的输入和选择组件，使 Web 更加强大。PrimeNG 提供了超过 20 个用于数据输入和选择的组件，这些组件通过皮肤能力和有用功能（如用户友好界面、验证等）扩展了标准或原生 HTML 组件。

在本章中，我们将涵盖以下主题：

+   使用 InputMask 进行格式化输入

+   自动完成的自动建议

+   使用芯片输入多个值

+   发现复选框-布尔、多个和三态

+   使用单选和多选组件选择项目

+   基本和高级日历场景

+   微调器和滑块-提供输入的不同方式

+   使用丰富和强大的编辑器进行文本编辑

+   密码和基于星级的评分输入

+   使用输入和选择组件进行验证

# 使用 InputMask 进行格式化输入

InputMask 是一种特殊类型的输入组件，可以最大程度地减少用户输入不正确数据的机会。它应用了提供的掩码模板的灵活验证。这对以特定格式输入数据特别有用，例如数字、字母数字、日期、货币、电子邮件和电话。电话号码输入的 InputMask 组件的基本示例如下：

```ts
<p-inputMask id="basic" name="basic" mask="99-999999"    
  [(ngModel)]="simple" placeholder="99-999999"/>

```

根据前面的示例，掩码值`(999) 999-9999`表示只能输入数字，括号和破折号结构。由于使用了相同掩码值的占位符，它建议提供的输入格式。输入的初始显示如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/20fb35dd-516b-4b16-95bc-db10403875b5.png)

一旦输入获得焦点，口罩格式中的数字将被空格替换，而其他字符将保持在初始阶段。口罩的默认占位符字符是下划线（`_`），因此它将为每个数字显示下划线字符。每次`keyPress`事件发生后，口罩字符（即`9`）将被实际字符填充。如果提供的输入不完整或模糊，则整个输入将自动清除（默认情况下，`autoClear`为`true`）。

在组件的 DOM 树中发生事件时，有些情况需要执行某些功能。`inputMask`组件支持`onComplete`回调，在用户完成口罩模式时调用。例如，当用户完成口罩输入时，用户将收到通知，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/0605e836-3009-4bcc-a3b5-37f2f1c214e1.png)

Growl 消息出现在页面顶部，带有关闭图标，这样我们可以随时删除粘性通知。

# 口罩格式选项

`mask`属性是使用输入口罩的必需属性。该组件不仅允许数字类型，还支持字母和字母数字字符，因此口罩格式可以是以下内置定义的组合：

+   `a`：字母字符（`A-Z，a-z`）

+   `9`：数字字符（`0-9`）

+   `*`：字母数字字符（`A-Z，a-z，0-9`）

让我们举个例子，我们可以根据单选按钮的选择显示具有不同口罩选项的输入口罩，如下所示：

```ts
<div>
 <div id="phoneformat" *ngIf="format == 'Option1'">
    <span>Phone:</span>
    <p-inputMask mask="(999) 999-9999" [(ngModel)]="phone" 
      placeholder="(999) 999-9999" name="phone">
    </p-inputMask>
  </div>
  <div id="dateformat" *ngIf="format == 'Option2'">
    <span>Date:</span>
    <p-inputMask mask="99/99/9999" [(ngModel)]="date" 
      placeholder="99/99/9999" name="date">
    </p-inputMask>
  </div>
  <div id="serialformat" *ngIf="format == 'Option3'">
    <span>Serial Number:</span>
    <p-inputMask mask="a*-999-a999" [(ngModel)]="serial" 
      placeholder="a*-999-a999" name="serial">
    </p-inputMask>
 </div>
</div>

```

根据前面的示例，只会显示一个带有定义口罩的输入元素。以下屏幕截图显示了日期口罩格式的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/76c545e9-f1a4-466b-a312-95c38063ae7d.png) `unmask`属性可用于控制值的掩码或未掩码输出。例如，如果`ngModel`将原始未掩码值或格式化的掩码值设置为组件的绑定值，则它非常有用。

# 使用占位符字符

如前所述，下划线（`_`）是口罩中默认的活动占位符。但是可以使用`slotChar`属性进行自定义，如下所示：

```ts
<p-inputMask mask="99/99/9999" [(ngModel)]="slot" placeholder="99/99/9999"
  slotChar="mm/dd/yyyy" name="slotchar"></p-inputMask> 

```

`slotChar`选项可以是单个字符或表达式。

# 将口罩的一部分设为可选项

到目前为止，所有输入掩码的示例都表明掩码中的所有字符都是必需的。也可以通过使用问号（`?`）字符使掩码的一部分变为可选。在掩码定义中问号后面列出的任何内容都将被视为可选输入。一个常见的用例是显示带有可选分机号码的电话号码，如下所示：

```ts
<span>Phone Ext</span>
<p-inputMask mask="(999) 999-9999? x99999" [(ngModel)]="optional"     
  name="optionalmask" placeholder="(999) 999-9999? x99999">
</p-inputMask>

```

一旦用户通过到达问号字符完成输入并模糊组件，其余的验证将被跳过。也就是说，直到那部分的输入不会被擦除。例如，电话号码输入，如`(666) 234-5678` 和 `(666) 234-5678? x1230` 将是掩码的可选情况的有效输入。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/inputmask.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/inputmask)

# AutoComplete 的自动建议

AutoComplete 是一个输入组件，它在用户输入到输入框时提供实时建议。这使用户能够在输入时快速查找并从查找的值列表中进行选择，从而利用了搜索和过滤功能。

AutoComplete 组件的基本用法包括`suggestions`属性，以提供所有结果项的列表，以及`completeMethod`，以根据输入的查询过滤项目。例如，以下 AutoComplete 组件根据用户查询显示国家列表：

```ts
<p-autoComplete [(ngModel)]="country" name="basic"
 [suggestions]="filteredCountries"
  (completeMethod)="filterCountries($event)"
  field="name" [size]="30"
  placeholder="Type your favourite Country" [minLength]="1">
</p-autoComplete>

```

在上面的示例中，`minLength="1"` 用作输入查询结果的最小字符数。这将呈现如下快照中所示的输出：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/e88eeb51-c9eb-469d-9613-dd666fb8bda4.png)

当用户在输入框中输入时，complete 方法将按需过滤项目。该方法必须在组件类中定义，如下所示：

```ts
filterCountries(event: any) {
 let query = event.query;
  this.countryService.getCountries().
 subscribe((countries: Country[]) => {
    this.filteredCountries = this.filterCountry(query, countries);
  });
}

```

上述方法允许根据用户查询对国家列表进行过滤。在这种情况下，它将过滤所有以 `query` 字符开头的国家。

为了改善用户体验，AutoComplete 通过`dropdown`属性提供了一个下拉选项。单击下拉图标，它将立即在向下弹出窗口中填充所有可能的项目。

# 多重选择

使用 AutoComplete，还可以通过将`multiple`属性设置为`true`来选择多个值。借助多选，可以将选定的文本作为数组（例如，`countries`属性）检索出来。在这种情况下，`ngModel`应该引用一个数组。

# 使用对象

到目前为止，AutoComplete 已经展示了它在原始类型上的强大功能，但它也可以处理对象类型。传递给模型的值将是一个对象实例，但`field`属性定义了要显示为建议的标签。也就是说，在这种情况下，`field`属性用于将对象的任何属性显示为标签。以下示例展示了对象使用的功能：

```ts
<p-autoComplete id="instance" [(ngModel)]="countryInstance" name="instance"
 [suggestions]="filteredCountryInstances"
 (completeMethod)="filterCountryInstances($event)" field="name">
</p-autoComplete>

```

在上面的例子中，`Country`对象被用作模型对象实例，显示的建议来自使用`name`字段属性的国家。

# 高级功能 - 定制内容显示

在许多情况下，普通字段填充是不够的；为了获得更好的体验，定制内容会更有力量。AutoComplete 使用`ng-template`提供了这个功能，它在建议面板内显示定制内容。传递给`ng-template`的本地`template`变量是`suggestions`数组中的一个对象。具有国家名称和国旗的 AutoComplete 的定制示例如下：

```ts
<p-autoComplete [(ngModel)]="customCountry" name="template"
 [suggestions]="filteredCustomCountries"
  field="name" (completeMethod)="filterCustomCountries($event)" 
  [size]="30" [minLength]="1" placeholder="Start your search">
  <ng-template let-country pTemplate="item">
    <div class="ui-helper-clearfix" class="template-border">
      <img src="/assets/data/images/country/
        {{country.code.toLowerCase()}}.png" class="country-image"/>
      <div class="country-text">{{country.name}}</div>
     </div>
 </ng-template>
</p-autoComplete>

```

对显示的数据类型没有限制。以下截图显示了定制国家信息的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/bdc965b3-f85c-4525-bde7-c698f512c396.png)

`item`模板用于定制建议面板内的内容，其中`selectedItem`用于定制多选中的选定项。

AutoComplete 组件支持许多事件，如下所述：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `completeMethod` |

+   `event.originalEvent`: 浏览器事件

+   `event.query`: 用于搜索的值

| 调用以搜索建议的回调函数。 |
| --- |
| `onFocus` | `event`: 浏览器事件 | 当 AutoComplete 获得焦点时调用的回调函数。 |
| `onBlur` | `event`: 浏览器事件 | 当 AutoComplete 失去焦点时调用的回调函数。 |
| `onSelect` | `value`: 选定的值 | 当选择建议时调用的回调函数。 |
| `onUnselect` | `value`: 多选模式下取消选定的值 | 当取消选定的值时调用的回调函数。 |
| `onDropdownClick` |

+   `event.originalEvent`: 浏览器事件

+   `event.query`: 输入字段的当前值

| 当下拉按钮被点击时调用的回调函数。 |
| --- |
| `onClear` | `event`: 浏览器事件 | 当`input`字段被清除时调用的回调函数。 |

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/autocomplete.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/autocomplete)

# 使用芯片输入多个值

芯片组件用于在输入字段中表示多个复杂实体，如联系信息，以小块的形式。芯片可以包含实体，如照片、标题、文本、规则、图标，甚至联系人。这对以紧凑的方式表示信息很有用。芯片组件的以下基本示例表示联系人姓名的顺序。默认情况下，每个实体都可以通过叉号图标或退格键删除：

```ts
<p-chips [(ngModel)]="contactnames" name="basic"></p-chips>

```

以下屏幕截图显示了公司联系人姓名作为芯片示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/dd0108f1-1fed-4351-85d6-c3d63c02c101.png)

芯片组件支持两个名为`onAdd`和`onRemove`的事件回调。这些事件回调将在向输入框添加和移除芯片时被调用。

# 使用模板显示复杂信息

使用`ng-template`元素自定义芯片，其中值作为隐式变量传递。`ng-template`的内容包括普通文本、图标、图片和任何其他组件。请记住，自定义芯片组件没有叉号图标，也就是说，我们只能通过退格键删除芯片条目。带有图标的芯片组件的自定义示例如下：

```ts
<p-chips [(ngModel)]="complexcontacts" name="template">
 <ng-template let-item pTemplate="item">
    <i class="fa fa-address-card"></i>-{{item}}
  </ng-template>
</p-chips>

```

在上面的示例中，使用公司标志和联系人姓名显示了自定义内容。以下屏幕截图显示了自定义芯片示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/9372e785-2633-4c4a-a944-244125d35968.png)

使用`max`和`disabled`属性来控制芯片的用户输入操作。可以使用`max`属性限制最大条目数。例如，如果我们设置`max="5"`，则不允许在输入中添加第六个条目。而`disabled="true"`会使输入框被禁用，从而限制芯片的输入。

PrimeNG 4.1 版本引入了用于自定义输入的`inputStyle`和`inputStyleClass`属性，以及用于控制重复输入的`allowDuplicate`属性。

完整的演示应用程序及说明可在 GitHub 上找到

请点击以下链接查看章节 3 中的 chips 示例代码：[`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/chips.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/chips)

# 发现复选框 - 布尔值，多个和三态

复选框是具有皮肤功能的标准复选框元素的扩展。复选框可以作为单个复选框来提供布尔值，也可以作为具有相同组名的多个复选框的多个选择。

# 布尔复选框 - 单选

默认情况下，复选框启用了多选功能，我们可以通过启用`binary`属性来进行单选。单选复选框的基本示例如下：

```ts
<p-checkbox name="single" [(ngModel)]="checked" binary="true">
</p-checkbox>

```

在上面的示例中，布尔复选框用于了解对 Angular 框架的兴趣。组件将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/16166cbd-2ff0-4d78-988b-77b8b339ca6b.png)

通过在模型中启用布尔属性，也可以实现复选框的预选。

# 复选框多选

如前所述，默认情况下启用了多选功能，多个复选框控件具有相同的组名。在这种情况下，`model`属性绑定到一个数组以保存所选值。通过将单个复选框的值分配给所选值，复选框组将显示预选项。选择不同的喜爱的 Angular 版本的多个复选框选择如下：

```ts
<div class="ui-g" class="multicheckbox-width">
 <div class="ui-g-12"><p-checkbox name="angulargroup"  
    value="AngularJS1.0" label="AngularJS V1.0" [(ngModel)]="selectedVersions"></p-checkbox>
  </div>
  <div class="ui-g-12"><p-checkbox name="angulargroup" 
    value="AngularV2.0" label="Angular V2.0"
 [(ngModel)]="selectedVersions"></p-checkbox>
  </div>
  <div class="ui-g-12"><p-checkbox name="angulargroup" 
    value="AngularV4.0" label="Angular V4.0"
 [(ngModel)]="selectedVersions"></p-checkbox>
  </div>
</div>

```

复选框组将显示默认选择，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/399a8289-e05d-4fc9-820e-eaac9d3fb1f5.png)

为了通知复选框选择，有一个名为`onChange`的事件回调，将在用户操作时被调用。同时，用户操作通过`disabled`属性被禁用。

# 多状态表示 - TriStateCheckbox

PrimeNG 超越了 Web 上“真/假”选择的普通复选框行为。在某些情况下，特别是表示任何实体的状态时，需要“真/假/空”组合。请记住，`model`属性分配给任何类型而不是`boolean`类型。用于输入对 Angular 4 的反馈的 TriStateCheckbox 的基本示例如下：

```ts
<p-triStateCheckbox name="tristate" [(ngModel)]="status">
</p-triStateCheckbox>

```

TriStateCheckbox 将显示三种不同的状态（优秀，良好和不好），如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/c6522e2d-69f8-4268-9ae5-9704c0cfb550.png)

此增强复选框还为任何用户交互提供了`onChange`事件回调。用户操作通过`disabled`属性禁用，就像普通的布尔复选框一样。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/checkbox.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/checkbox)

# 使用单选和多选组件选择项目

下拉提供了一种从可用选项集合中选择项目的方法。要列出所有可能的选项，我们应该使用定义标签值属性的`SelectItem`接口，并将此列表绑定到`options`属性。选定项目的双向绑定通过`model`属性进行定义。让我们为用户输入在下拉框中显示一个国家列表。下拉框的基本示例将如下所示：

```ts
<p-dropdown [options]="countries" [(ngModel)]="selectedCountry"
  [styleClass]="dropdown-width" placeholder="Select a Country">
</p-dropdown>

```

下拉框将显示如下所示的选项：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/9fe92969-59a4-468a-a080-77ce8e8664ee.png)

下拉组件提供了三个事件回调，如`onChange`，`onFocus`和`onBlur`。当下拉值发生变化时，分别获得焦点和失去焦点。有一个属性`editable`（即`editable="true"`）可以直接编辑输入，就像其他输入组件一样。

下拉视口的宽度和高度将通过`autoWidth`和`scrollHeight`属性进行控制。默认情况下，下拉框的宽度是根据选项的宽度计算的。而滚动高度通过`scrollHeight`选项以像素为单位进行控制，如果列表的高度超过此值，则定义滚动条。

# 自定义下拉框

下拉组件通过自定义内容比默认标签文本更强大。`filter`属性用于通过覆盖中的输入筛选所有可能的选项。下拉框的自定义示例，显示了代表国家名称和国旗图像的选项列表，将如下所示：

```ts
<p-dropdown [options]="countries" [(ngModel)]="selectedCountry"  
  [styleClass]="dropdown-width" filter="filter">
 <ng-template let-country pTemplate="item">
    <div class="ui-helper-clearfix" class="template-border">
      <img src="/assets/data/images/country/
        {{country.code.toLowerCase()}}.png" class="country-image"/>
      <div class="country-text">{{country.name}}</div>
    </div>
  </ng-template>
</p-dropdown>

```

下拉框将显示自定义内容和过滤，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/3ba4fa39-0ecc-48aa-bbfd-656a5eabb8d7.png)

不必向下滚动查看所有国家的列表，顶部有一个过滤输入选项，可以按其起始字母过滤国家名称。它还支持逗号分隔值的多属性过滤（例如，`filterBy="label, value.name"`）。默认情况下，过滤是针对`SelectItem` API 的标签进行的。

# 多选下拉框

多选组件用于从集合中选择多个项目，而不是提供单个项目选择的下拉组件。具有国家列表的多选组件的基本示例如下：

```ts
<p-multiSelect [options]="countries" [(ngModel)]="selectedCountries">
</p-multiSelect>

```

选项列表通过`SelectItem`接口的集合可用，该接口采用标签值对。选项列表通过多选组件的`options`属性绑定。多选将显示国家列表，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/9dc79414-33f0-468e-996f-346860b4f862.png)

在这种情况下，用户可以使用复选框选项选择多个国家，该选项适用于每个项目，并且可以过滤输入以选择特定选项。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/select.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/select)

# 基本和高级日历场景

日历是一种输入组件，以不同的定制方式选择日期输入，例如内联、本地化、限制特定日期和面向时间。在这种情况下，日历模型由日期类型属性支持。基本日期选择的最简单组件声明如下：

```ts
<p-calendar [(ngModel)]="basicDateInput" name="basic"></p-calendar>

```

这显示一个输入文本框，点击后会打开一个弹出式日期选择对话框，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/b4edf36c-ee34-4443-af12-f6e18e8c98b2.png)

除了基本的日期选择外，还可以通过顶部的左右箭头控件在每年的每个月之间进行导航。这将在高级功能部分进行解释。

日期选择很简单，可以通过点击弹出对话框中的特定日期来完成。默认情况下，日历显示为弹出式，但可以通过`inline`属性更改此行为。日历显示的内联版本如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/4adf4ae8-87b4-412f-96d8-5f1ef6245a57.png)

为了更好的用户体验，组件还提供了通过`showIcon`属性显示日历弹出窗口的另一个选项。使用图标按钮的日历输入示例如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/f80be38d-b441-4a7c-86df-316694ef16d3.png)

日历组件的可视显示，带有`icon`属性的将改变输入框旁边显示的默认图标。

# 本地化

不同语言和格式的本地化是通过将本地设置对象绑定到`locale`属性来定义的。默认的本地值是`英语`。要表示不同的区域设置，我们应该提供相应的语言文本标签。例如，德语区域应该为德语日历提供以下标签：

```ts
this.de = {
 firstDayOfWeek: 1,
  dayNames: ['Sonntag', 'Montag', 'Dienstag', 'Mittwoch', 'Donnerstag',  
 'Freitag', 'Samstag'],
  dayNamesShort: ['Son', 'Mon', 'Die', 'Mit', 'Don', 'Fre', 'Sam'],
  dayNamesMin: ['S', 'M', 'D', 'M ', 'D', 'F ', 'S'],
  monthNames: [
    'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni', 'Juli',
    'August', 'September', 'Oktober', 'November', 'Dezember'
  ],
  monthNamesShort: ['Jan', 'Feb', 'Mär', 'Apr', 'Mai', 'Jun', 'Jul',
                    'Aug', 'Sep', 'Okt', 'Nov', 'Dez']
};

```

带有德语区域标签的日历将显示如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/f7fd7d3e-11b9-4d55-b83f-133b82b2a593.png)

如前所示，区域特定的标签需要在后台组件中格式化为 JSON 以显示区域特定的日历。

# 时间选择器选项

除了标准的日历日期选择，我们还可以使用`showTime`和`hourFormat`来显示时间。这可以进一步限制为仅使用`timeOnly`属性来显示时间，这只是一个时间选择器。例如，`timeOnly`选项将显示时间选择器如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/9a164876-0b8b-4c04-b2d6-c17b4a1574bf.png)

两种时间格式（12 小时制和 24 小时制）将使用分割按钮分别显示。请注意，此时启用了`showTime`属性。

# 高级功能

日历组件的高级功能，如日期格式（使用`dateFormat`属性）、受限日期（使用`min`和`max`日期）、月份和年份导航器以便轻松访问（使用`monthNavigator`、`yearNavigator`和`yearRange`属性）、只读输入（使用`readOnlyInput`属性）以及有用的事件，如`onSelect`、`onFocus`、`onClear`和`onBlur`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/89c878d9-c334-489b-bfe4-97a672c8c2b4.png)

上述快照描述了可以与其特性的任何可能组合一起使用的日历。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/calendar.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/calendar)

# 旋转器和滑块-提供输入的不同方式

输入组件 Spinner 通过控件或按钮提供数字输入的增量和减量。但仍然有选项可以将其用作普通的`InputText`。Spinner 的基本示例如下：

```ts
<p-spinner  name="basic" size="30" [(ngModel)]="basicinput"></p-spinner>

```

如下截图所示，Spinner 将显示带有按钮控件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/f2d6f7ed-4541-46f7-bf67-fcbe2945f05b.png)

如快照所示，可以使用 Spinner 控件连续修改值。与任何其他输入组件一样，Spinner 支持`onChange`事件回调，该回调将在值更改时被调用。可以通过`maxlength`属性控制允许的最大字符数。用户交互将通过`readonly`和`disabled`属性受限。

# 高级功能-超越基本用法

Spinner 组件提供的功能不仅仅是具有增量和减量控件。它还可以提供诸如使用`min`和`max`属性的值边界，使用`step`属性自定义步进因子（默认步进因子为`1`）以及数字分隔符，例如`decimalSeparator`和`thousandSeparator`。Spinner 的自定义示例如下：

```ts
<p-spinner name="minmax" size="40" [(ngModel)]="customizedinput" [min]="0" [max]="100" [step]="0.50"
  placeholder="Enter your input or use spinner controls"></p-spinner>

```

如下截图所示，Spinner 将显示带有按钮控件：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/c09f0c40-f52e-4f69-a3dc-f200c2f5622b.png)

一旦用户输入达到`min`和`max`限制，值将无法通过控件或输入更改。

可以使用`formatInput`属性自定义输入的格式。

# 滑块

滑块组件提供了使用滑块条或拖动手柄输入值的能力。`model`属性绑定到一个数字类型，它保存输入值。可以通过为两者提供相同的模型值将输入附加到滑块。滑块的基本示例如下：

```ts
<p-slider [(ngModel)]="basicinput" name="basicinput"  
  styleClass="slider-width">
</p-slider>

```

如下截图所示，滑块将显示带有拖动手柄：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/b7cb7803-335c-458b-8ac6-7fda67c1d490.png)

每次拖动手柄穿过条时，输出值将更新。

# 高级功能-超越基本用法

滑块组件可以通过类似于具有输入边界的微调器的方式进行进一步定制，使用`min`和`max`属性或`range`属性同时提及两个边界，使用`step`属性定制步进因子（默认步进因子为`1`），以及使用`animate`属性在单击滑块时提供动画效果。

滑块输入的默认方向是水平的。可以使用`orientation`属性将滑块的方向或方向更改为垂直。

有时，除了滑块手柄之外，还可以使用常规输入，因为这样可以直接输入并且还可以通过拖动滑块手柄来显示输出。滑块的定制示例如下：

```ts
<input type="text" pInputText name="customizedinput"   
  [(ngModel)]="customizedinput"
 styleClass="input-width"/>
<p-slider [(ngModel)]="customizedinput" name="customizedinput"   
  styleClass="slider-width" [step]="20"
 [animate]="true" (onChange)="onChange()" (onSlideEnd)="onSlideEnd()">
</p-slider>

```

滑块将显示为以下截图所示的定制特性：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/c8ee31e2-a10b-4b19-97ea-a10d6000bb19.png)

滑块输入和滑块手柄值是相互依赖的。例如，更改一个值将反映另一个值。

完整的演示应用程序及说明可在 GitHub 上找到：

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/spinner`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/spinner)

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/slider`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/slider)

# 使用富文本编辑器进行文本编辑

编辑器是基于 Quill 编辑器的富文本编辑器（所见即所得）。它包含一个带有常见选项的默认工具栏，其控件可以使用标题元素进行定制。此处使用的是 Quill 1.0 的最新版本作为依赖项。具有默认工具栏的基本文本编辑器可以表示如下：

```ts
<p-editor name="basic" [(ngModel)]="basictext" 
  styleClass="editor-dimensions">
</p-editor>

```

具有常见选项的文本编辑器将如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/46809025-d217-419e-875e-8bdcf68b5982.png)1\. 在`package.json`中添加 Quill 1.0 依赖项并安装它，或者使用 CLI 工具安装它（`npm install quill --save`）。

2\. 还要在入口页面中添加 Quill 脚本和样式 URL：

`<script src="https://cdn.quilljs.com/

1.0.0-beta.3/quill.min.js"></script>`

`<link rel="stylesheet" type="text/css" href="https://cdn.quilljs.com/1.0.0-

beta.3/quill.snow.css">`

编辑器支持`onTextChange`和`onSelectionChange`事件，当编辑器的文本发生变化时，将调用`onTextChange`事件，当编辑器的选定文本发生变化时，将调用`onSelectionChange`事件。

# 自定义编辑器

如前所述，编辑器提供了一个带有常用选项的默认工具栏。可以通过在头部元素内定义元素来自定义工具栏。例如，使用文本样式控件创建的自定义工具栏如下所示：

```ts
<p-editor name="custom" [(ngModel)]="customtext" 
  styleClass="editor-dimensions">
 <p-header>
 <span class="ql-formats">
      <button class="ql-bold"></button>
      <button class="ql-italic"></button>
      <button class="ql-underline"></button>
      <button class="ql-clean"></button>
 </span>
 </p-header>
</p-editor>

```

带有自定义工具栏的文本编辑器将显示如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/bdbc87de-b4a2-42ed-a4d1-6b7329c7a485.png)

工具栏可以以不同的方式使用任意数量的工具栏控件进行自定义。请参考 Quill 文档以获取所有可用的控件。

完整的演示应用程序及说明可在 GitHub 上找到。

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/editor.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/editor)

# 密码和基于星级的评分输入

密码是一个增强型输入，具有字符的安全输入，就像网页上的其他密码字段一样，但它提供了强度指示器（弱、中、强），表示用户输入的安全强度。用户密码的基本示例可以写成如下形式：

```ts
<input pPassword name="basic" type="password" />

```

以下截图显示了基本密码示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/9c515c7c-83d4-49c8-a4ab-2bef29a881c3.png)

通过附加`pPassword`指令，密码应用于输入字段。`ngModel`属性用于绑定密码值。

默认情况下，密码将显示提示和强度指示标签。有一个选项可以使用诸如`promptLabel`、`weakLabel`、`mediumLabel`和`strongLabel`等属性来自定义所有强度指示标签。这将有助于根据需要本地化密码输入。默认情况下，`feedback`属性为`true`。一旦输入获得焦点或按键，指示标签就会出现。但是通过将反馈设置为`false`来改变这种行为，可以抑制输入的指示器。

# 评分输入

评分组件提供了基于星级的评分，具有选择和取消的功能。组件的基本声明如下：

```ts
<p-rating name="basic" [(ngModel)]="angular" ></p-rating>

```

在这里，评分限定值应该是一个数字类型。Angular 评分的默认视觉效果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/8179e89f-3cc3-452a-a243-35c028395ed6.png)

`star`属性帮助提供评分中的星星数量。星星的默认值为`5`。

选择和取消评分的行为可以更加交互，您可以通过`onRate`和`onCancel`回调来得到通知。在上面的快照中，评分值可以通过左侧的取消图标清除。这是因为，默认情况下`cancel`属性将被启用。如果该属性被禁用，则一旦选择评分就无法取消。通过禁用`cancel`属性，评分快照将显示为没有图标，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/c6316c54-a238-48fc-afac-f6255993b6fd.png)

由于这个特性，取消按钮不会出现来取消给定的评分。一次只能取消一个星级。

目前，评分组件不支持半个或四分之一的值。

通过在评分组件上启用`readonly`和`disabled`属性，无法选择或取消评分。这对于仅用于显示目的很有用。

完整的演示应用程序及说明可在 GitHub 上找到：

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/password`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/password) [](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/password)

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/rating`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/rating)

# 使用输入和选择组件进行验证

Angular 提供了三种不同的构建应用程序中表单的方式：

+   **基于模板的方法**：这种方法允许我们构建表单，几乎不需要或根本不需要应用程序代码

+   **基于模型驱动（或响应式）的低级 API 方法**：在这种方法中，我们创建的表单可以进行测试，而无需 DOM

+   **使用更高级 API 的基于模型驱动的方法**：这种方法使用一个称为`FormBuilder`的更高级 API。

PrimeNG 创建了大多数输入和选择组件，并支持基于模型驱动的表单。因此，所有输入和选择组件都可以进行验证。

让我们以一个带有`firstname`、`lastname`、`password`、`address`、`phone`和`gender`字段的带有验证支持的注册表单为例。PrimeNG 组件由一个模型驱动的 API 支持，使用`FormBuilder`将所有表单控件分组以创建一个注册表单，如下所示：

```ts
this.registrationform = this.formBuilder.group({
    'firstname': new FormControl('', Validators.required),
    'lastname': new FormControl('', Validators.required),
    'password': new FormControl('',   
      Validators.compose([Validators.required, 
      Validators.minLength(8)])),
    'address': new FormControl(''),
    'phone': new FormControl(''),
    'gender': new FormControl('', Validators.required)
});

```

然而，HTML 中包含了与注册表单绑定的`form`元素和`formGroup`。表单将包含一系列控件和验证条件以显示消息：

```ts
<form [formGroup]="registrationform" (ngSubmit)="onSubmit(registrationform.value)">
  ... </form>

```

具有无效输入的注册表单将导致错误消息，如下快照所示：

*![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/7a377c97-5548-4270-a8c4-231603d4dbdb.png)*

PrimeNG 组件通过模板驱动表单和模型驱动表单提供验证。用户可以灵活选择需要提供的验证类型。

完整的演示应用程序及说明可在 GitHub 上找到。

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter3/validation.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter3/validation)

# 总结

在本章的结尾，您将能够无缝地为任何给定的用例使用所有可用的输入和选择组件。最初，我们涵盖了各种输入组件。起初，我们从使用 InputMask 进行格式化输入，使用 AutoComplete 进行自动建议，以及使用 Chips 组件输入多个值开始。

之后，我们讨论了各种复选框组件，如布尔复选框、多选框和三态复选框变体。之后，我们讨论了常用的选择组件，如单选和多选组件。我们解释了特定用例的输入组件，如日历日期输入、滑块、微调器、密码、星号和使用丰富编辑器进行文本编辑，以及所有可能的功能。最后，我们通过查看输入和选择组件的验证来结束了本章。所有这些组件和所有可能的功能都是通过逐步方法进行解释的。

在下一章中，您将看到各种按钮和面板组件将如何使您的生活更轻松。


# 第四章：按钮和面板组件

在本章中，我们将首先涵盖各种按钮组件，如单选按钮、分割按钮、切换按钮和选择按钮，然后转向各种面板组件，如工具栏、基本面板、字段集、手风琴和选项卡视图。用户输入将以多种方式进行，其中按钮输入是最佳选项之一；另一方面，面板组件充当容器组件，允许对其他原生 HTML 或 PrimeNG 组件进行分组。PrimeNG 的每个功能——增强按钮和面板组件都涵盖了许多实时用例需求。本章详细介绍了配置按钮和面板组件的各种设置。

在本章中，我们将涵盖以下主题：

+   增强按钮、单选按钮和分割按钮

+   通过切换按钮和选择按钮选择值

+   使用工具栏对按钮进行分组

+   使用面板和字段集排列您的视图

+   垂直堆叠的手风琴面板

+   在 TabView 中使用选项卡对内容进行分组

# 增强按钮、单选按钮和分割按钮

按钮是任何网页设计中经常使用的元素。PrimeNG 通过出色的功能扩展了普通按钮的行为。

# 按钮

按钮组件是用于用户与图标和主题进行交互的标准输入元素的扩展。`pButton`指令将普通的 HTML 按钮变成 PrimeNG 增强按钮。具有定义的标签文本的按钮组件的基本示例将如下所示：

```ts
<button name="basic" pButton type="button" label="ClickMe"></button>

```

按钮的类型应为`button`类型。以下屏幕截图显示了基本按钮示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/2d068b5c-90ca-4d4e-9a40-27bcc531243e.png)

按钮组件支持一个名为`click`的事件回调，该事件将在单击按钮元素时被调用。请记住，按钮的点击事件基本上是来自 Angular 而不是特定于 PrimeNG 的。

# 图标和严重性

按钮组件在图标和严重性属性方面更有用。`icon`属性用于在按钮上方表示字体 awesome 图标。默认图标位置是左侧位置。可以使用`iconPos`属性自定义此位置，有效值为`left`和`right`。为了仅显示一个图标，将标签留空。按钮组件的示例，包括各种图标和标签的组合，将如下所示：

```ts
<button pButton type="button" icon="fa-close"></button>
<button pButton type="button" icon="fa-check" label="Yes"></button>
<button pButton type="button" icon="fa-check" iconPos="right" label="Yes"></button>

```

在上面的示例中，按钮被定义为没有标签，有标签，并且带有标签的右侧定位图标，依次排列。以下屏幕截图显示了带有图标的按钮的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/ffa0c0cc-81aa-4f86-9844-23bd99596668.png)

为了区分用户操作的不同严重级别，PrimeNG 提供了五种不同的类，即这些样式类与常规主题颜色不同：

+   `ui-button-secondary`

+   `ui-button-success`

+   `ui-button-info`

+   `ui-button-warning`

+   `ui-button-danger`

以下屏幕截图显示了带有所有严重情况的按钮的快照结果（与常规主题类进行比较）：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/655568e7-cd98-454c-b7f2-5636cc8aa024.png)

用户交互使用常规的`disabled`属性来阻止。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/button.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/button)

# RadioButton

RadioButton 是标准单选按钮元素的扩展，具有选择能力以一次只选择一个值。双向绑定通过`ngModel`指令提供，该指令使默认值可以作为已选或未选（预选）。以下是一个具有定义标签文本的 RadioButton 组件的基本示例：

```ts
<div class="ui-g">
 <div class="ui-g-12">
    <p-radioButton name="group1" value="Angular" label="Angular"
 [(ngModel)]="basic"></p-radioButton>
  </div>
  <div class="ui-g-12">
    <p-radioButton name="group1" value="React" label="React"
 [(ngModel)]="basic"></p-radioButton>
  </div>
  <div class="ui-g-12">
    <p-radioButton name="group1" value="Polymer" label="Polymer"
 [(ngModel)]="basic"></p-radioButton>
  </div>
</div>

```

在上面的示例中，所有单选按钮都映射到同一组（`name="group1"`），以便作为互斥的单选按钮组工作。以下屏幕截图显示了单选按钮示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/e0632ea3-9ad2-4d06-8bab-5e67ed039096.png)

单选按钮组件支持一个名为`onClick`的事件回调，该事件将在单选按钮元素被点击时被调用。`label`属性为单选按钮提供了标签文本。标签也是可点击的，并且选择值。与单选按钮相关的标签组件需要在点击时触发输入的焦点，这可以通过`inputId`属性实现。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/radio-button.`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/radio-button)

# SplitButton

SplitButton 将一组菜单项与默认命令按钮组合在一个覆盖中。此按钮使用常见的菜单模型 API 来定义其项目。因此，分割按钮是按钮和菜单组件的组合。使用定义的标签文本的 SplitButton 组件的基本示例将如下所示：

```ts
<p-splitButton label="Create" (onClick)="create()" [model]="items">
</p-splitButton>

```

标签仅适用于默认命令按钮。以下屏幕截图显示了分割按钮示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/940522dc-9797-4f69-ba74-656b4ed031fa.png)

分割按钮组件支持一个名为`onClick`的事件回调，该回调将在单击默认按钮元素时被调用。

PrimeNG 4.1 提供了`appendTo`选项，可以自定义覆盖的附加位置。

# 图标和主题

有许多选项可以自定义分割按钮的行为。图标可以分别应用于关联的默认命令按钮和菜单项，使用`icon`属性。默认情况下，图标对齐到左侧，但也可以使用`iconPos`属性应用到右侧，而组件和覆盖的皮肤行为可以通过`style`、`styleClass`、`menuStyle`和`menuStyleClass`类属性进行修改。使用定义的标签文本的 SplitButton 组件的基本示例将如下所示：

```ts
<p-splitButton label="Create" icon="fa-check" iconPos="right"  
  menuStyleClass="customized-menu" [model]="itemsIcons">
</p-splitButton>

```

在上面的示例中，通过`menuStyleClass`属性改变了覆盖菜单的默认样式。例如，在这种情况下，通过设置`menuStyleClass`类名来改变覆盖的默认宽度，如下所示：

```ts
.customized-menu {
  width: 140%;
}

```

以下屏幕截图显示了分割按钮示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/9a104867-c87c-4b6c-affe-709d6d27fe0a.png)

在上面的快照中，分割按钮定制了图标，创建命令按钮图标对齐到右侧，并且覆盖的宽度增加以容纳图标和文本。

完整的演示应用程序和说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/split-button`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/split-button)。

# 使用 ToggleButton 和 SelectButton 选择一个值

ToggleButton 提供了一种使用按钮选择布尔值的方法。`ngModel`指令用于将双向数据绑定到布尔属性。也就是说，通过启用布尔属性来实现切换按钮的预选。ToggleButton 使用的基本示例如下：

```ts
<p-toggleButton [(ngModel)]="basic" name="basic"></p-toggleButton>

```

以下屏幕截图显示了基本示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/fbd75010-8282-4eaa-9657-b691ed004ba9.png)

ToggleButton 还提供了自定义选项，如`onLabel`、`offLabel`、`onIcon`和`offIcon`，用于覆盖默认标签和图标。与切换按钮相关的标签组件需要在单击标签时触发按钮的焦点，这可以通过`inputId`属性实现。具有标签、图标和事件的自定义切换按钮如下：

```ts
<p-toggleButton [(ngModel)]="customized" name="custom" onLabel="I 
  confirm" offLabel="I reject" onIcon="fa-check-square" 
  offIcon="fa-window-close">
</p-toggleButton>

```

在上面的例子中，可以为`icon`属性使用各种 font-awesome 图标。以下屏幕截图显示了自定义示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/c55958c7-703a-4b2a-a64d-a370493a03ba.png)

用户使用`onChange`事件来通知用户操作。同时，使用`disabled`属性来阻止用户交互。

# SelectButton

SelectButton 组件用于从按钮形式的列表中选择单个或多个项目。选项列表中的每个项目都被定义为具有标签值对属性的`SelectItem`接口。选项通过`ngModel`属性进行绑定，实现双向绑定，这将根据后端组件数据进行默认选择。选择按钮使用的基本示例如下：

```ts
<p-selectButton [options]="types" [(ngModel)]="selectedType"   
  name="basic">
</p-selectButton>  

```

在上面的例子中，所有 Prime 库都被收集为`options`属性的数组。以下屏幕截图显示了选择按钮示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/472a7106-967d-4f86-b4d4-ab8f3273833e.png)

在上面的例子中，一次只能选择一个项目（单选），但也可以使用`multiple`属性选择多个项目（即`multiple="true"`）。在这种情况下，所选的数组列表不应指向空值或未定义的值。

选择按钮组件支持一个名为`onChange`的事件回调，该事件将在单击默认按钮元素时被调用。

完整的演示应用程序及说明可在 GitHub 上找到：

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/togglebutton`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/togglebutton)

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/selectbutton`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/selectbutton)

# 使用 Toolbar 分组按钮

Toolbar 是按钮和其他 Web 资源的分组或容器组件。Toolbar 内容包装在两个 `div` 元素中，一个用于使用 `.ui-toolbar-group-left` 类在左侧对齐内容，另一个用于使用 `.ui-toolbar-group-right` 类在右侧对齐内容。Toolbar 组件的示例，包括不同的按钮、输入控件和文本内容，如下所示：

```ts
<p-toolbar name="toolbar">
 <div class="ui-toolbar-group-left">
    <button pButton type="button" name="open" label="Open" 
      icon="fa-folder-open"></button>
    <button pButton type="button" name="new" label="New folder" 
      icon="fa-plus"></button>
    <p-splitButton name="organize" label="Organize" 
      icon="fa-check" name="organize"
 [model]="items"></p-splitButton>
  </div>

  <div class="ui-toolbar-group-right">
    <input name="search" type="text" size="30" pInputText 
    [(ngModel)]="search"
 placeholder="Search files here"/>
      <i class="fa fa-bars"></i>
      <button name="refresh" pButton type="button" 
      icon="fa-refresh"></button>
      <button name="help" pButton type="button" 
      icon="fa-question-circle"></button>
  </div>
</p-toolbar>

```

以下屏幕截图显示了 Toolbar 的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/941297a2-251d-4c2f-a16f-fbe77d4c6492.png)

在上述快照中，常用的 Toolbar 按钮放在左侧，次要（或附加信息）放在右侧。通过 `style` 和 `styleClass` 属性提供了皮肤特性。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/toolbar`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/toolbar).

# 使用 Panel 和 FieldSet 排列您的视图

大多数网站和仪表板需要分组或容器组件来突出标题和描述。PrimeNG 提供了许多容器组件的变体。

# Panel

作为 Web 内容的通用分组组件，Panel 具有切换和自定义内容等功能。Panel 的基本定义如下：

```ts
<p-panel header="PrimeNG">
  PrimeNG is a collection of rich UI components for Angular.
  PrimeNG is a sibling of the popular JavaServer Faces Component Suite,  
  PrimeFaces.
  All widgets are open source and free to use under MIT License.
  PrimeNG is developed by PrimeTek Informatics, a company with years of 
  expertise in developing open source UI components.
</p-panel>

```

Panel 的上述定义将在容器内显示 PrimeNG 详细信息，如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/29c6545e-9907-41bc-a3d9-ec4ac4673208.png)

Panel 将更加用户友好，具有可切换（`toggleable="true"`）和自定义标题内容功能。可切换功能将内容定义为展开或折叠。面板内容的初始状态（展开或折叠）由`collapsed`属性定义；默认情况下，内容部分将展开，而自定义的标题和页脚通过`p-header`和`p-footer`标签定义，可以接受文本、图像、图标等。例如，以下是以下拉列表形式显示 PrimeNG 资源列表的自定义标题的示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/a2425719-c412-4575-bb70-c9768ecd7ba9.png)

我们可以使用`onBeforeToggle`和`onAfterToggle`回调在切换之前和之后捕获用户操作。

# FieldSet

FieldSet 是一个带有内容切换功能的分组组件。在顶部，图例定义了标题并在主体内容周围绘制了一个框。具有`toggleable`功能的 FieldSet 示例如下：

```ts
 <p-fieldset legend="PrimeNG" [toggleable]="true" [collapsed]="true">
   PrimeNG is a collection of rich UI components for Angular.
   PrimeNG is a sibling of the popular JavaServer Faces Component  
   Suite, PrimeFaces.
   All widgets are open source and free to use under MIT License.
   PrimeNG is developed by PrimeTek Informatics, a company with years 
   of expertise in developing open source UI components.
</p-fieldset>

```

如下所示，前面的 FieldSet 的定义将显示为以下截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/fa2b66d1-e871-473e-9049-5d1d0762253a.png)

与 Panel 组件类似，FieldSet 通过`p-header`属性（即自定义的标题内容）提供了自定义的图例。

FieldSet 的标题文本由`legend`属性管理，而切换功能由`toggleable`和`collapsed`属性控制。有两个名为`onBeforeToggle`和`onAfterToggle`的事件回调可用于任何自定义逻辑实现。

完整的演示应用程序及说明可在 GitHub 上找到：

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/panel`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/panel)

+   [`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/fieldset`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/fieldset)

# 带有手风琴的垂直堆叠面板

手风琴是一个容器组件，可以以多个选项卡的形式对内容进行分组。内容可以是文本、图像或任何其他组件。所有选项卡内容都以垂直顺序堆叠。带有不同版本 Angular 细节的手风琴组件的基本定义如下：

```ts
<p-accordion>
 <p-accordionTab header="AngularJS">
    AngularJS (commonly referred to as "Angular.js" or "AngularJS 1.X")  
    is a JavaScript-based open-source front-end web application 
    framework mainly maintained by Google and by a community of  
    individuals and corporations to address many of the
    challenges encountered in developing single-page applications.
  </p-accordionTab>
  <p-accordionTab header="AngularV2.0">
    The successor to the older AngularJS web framework, now simply 
    known as "Angular". Angular takes a web component-based 
    approach to build powerful applications for the web. It is used  
    along with TypeScript which provides support for both older
    and new versions of JavaScript.
  </p-accordionTab>
  <p-accordionTab header="AngularV4.0">
    Angular version 4.0.0 is a major release following announced 
    adoption of Semantic Versioning, and is backwards compatible with   
    2.x.x for most applications.
  </p-accordionTab>
</p-accordion>

```

如下所示，前面的手风琴将显示为垂直面板：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/4ad75ae0-322c-4fca-807b-815bc554337d.png)

在上面的简单示例中，Accordion 将一次显示一个选项卡内容。组件中有一个选项可以通过启用`multiple`属性来显示多个选项卡内容。Accordion 可以通过强大的功能进行自定义，如自定义标题、选项卡事件、默认选定的选项卡和禁用行为。

自定义的 Accordion 组件定义如下：

```ts
<p-accordion>
 <p-accordionTab>
    <p-header>
      <img src="/assets/data/images/angularjs.png" 
        alt="Smiley face" width="42" height="42">
      AngularJS
    </p-header>
    AngularJS (commonly referred to as "Angular.js" or "AngularJS 1.X") 
    is a JavaScript-based open-source front-end web application 
    framework mainly maintained by Google and by a community
    of individuals and corporations to address many of the challenges  
    encountered in developing single-page applications.
  </p-accordionTab>
  <p-accordionTab header="AngularV2.0">
    <p-header>
      <img src="/assets/data/images/angular2.svg" 
        alt="Smiley face" width="42" height="42">
      AngularV2.0
    </p-header>
    The successor to the older AngularJS web framework, 
    now simply known as "Angular". Angular takes a web 
    component-based approach to build powerful 
    applications for the web. It is used along with TypeScript 
    which provides support for both older and new versions of  
    JavaScript.
  </p-accordionTab>
  <p-accordionTab header="AngularV4.0">
    <p-header>
      <img src="/assets/data/images/angular4.png" 
        alt="Smiley face" width="42" height="42">
      AngularV4.0
    </p-header>
    Angular version 4.0.0 is a major release 
    following announced adoption of Semantic Versioning,
    and is backwards compatible with 2.x.x for most applications.
 </p-accordionTab>
</p-accordion>

```

在上面的示例中，使用`p-header`标签创建了自定义标题，其中包含 Angular 标志和文本内容。Accordion 将显示带有自定义高级功能的内容，如下图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/6a6eb8c2-0a37-4dee-84c0-ba46a81007cb.png)

Accordion 组件支持两个名为`onOpen`和`onClose`的事件回调，分别在打开和关闭选项卡时调用。

PrimeNG 4.1 版本引入了`activeIndex`属性，用于定义活动选项卡或要以编程方式更改的索引数组。例如，`[activeIndex]="0,1"`。完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/accordion`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/accordion).

# 在 TabView 中使用选项卡对内容进行分组

TabView 是一个选项卡面板组件，用于以垂直和水平选项卡的形式对内容进行分组。默认的 TabView 将以水平方向显示选项卡，并且一次只能选择一个选项卡来查看内容。TabView 组件的基本定义如下：

```ts
<p-tabView name="basic">
 <p-tabPanel header="AngularJS">
    AngularJS (commonly referred to as "Angular.js" or
    "AngularJS 1.X") is a JavaScript-based open-source front-end web  
    application framework mainly maintained by Google and by a  
    community of individuals and corporations to address many of 
    the challenges encountered in developing single-page applications.
  </p-tabPanel>
  <p-tabPanel header="AngularV2.0">
    The successor to the older AngularJS web framework, 
    now simply known as "Angular". Angular takes a
    web component-based approach to build powerful 
    applications for the web. It is used along with
    TypeScript which provides support for both older 
    and new versions of JavaScript.
  </p-tabPanel>
  <p-tabPanel header="AngularV4.0">
    Angular version 4.0.0 is a major release following announced  
    adoption of Semantic Versioning, and is backwards compatible 
    with 2.x.x for most applications.
  </p-tabPanel>
</p-tabView>

```

前面的 TabView 将显示为水平面板，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/773c11f7-febc-43f3-ab45-40457f2dc336.png)

每个选项卡都用`p-tabPanel`表示。可以使用`orientation`属性改变选项卡的方向。它支持四种不同的方向：`top`、`bottom`、`left`和`right`。`top`是默认方向。

该组件还支持各种其他高级功能，如`closable`选项卡（`closable="true"`）、事件（`onChange`在选项卡更改时调用，`onClose`在选项卡关闭时调用）、使用`selection`属性进行默认选择，以及使用`disabled`属性禁用选项卡。

`onChange`事件对象公开了两个在组件类中可访问的属性：

| `onChange` |
| --- |

+   `event.originalEvent`: 原生点击事件

+   `event.index`: 选定选项卡的索引

|

```ts
onTabChange(event:any) {
 this.msgs = [];
 this.msgs.push({severity:'info', summary:'Tab Expanded', 
 detail: 'Target: '+ event.originalEvent.target+'Index: ' + event.index});

```

`onClose`事件对象公开了三个属性，在组件类中可以访问：

| `onClose` |
| --- |

+   `event.originalEvent`: 原生点击事件

+   `event.index`: 关闭选项卡的索引

+   `event.close`: 回调以实际关闭选项卡，仅在启用`controlClose`时可用

|

```ts
onTabClose(event:any) {
 this.msgs = [];
  this.msgs.push({severity:'info', summary:'Tab closed', 
 detail: 'Target: ' + event.originalEvent.target+'Index: ' + event.index});
}

```

TabView 组件的自定义定义如下：

```ts
<p-tabView (onChange)="onTabChange($event)"  
  (onClose)="onTabClose($event)">
 <p-tabPanel header="AngularJS" [closable]="true" [selected]="true">
    AngularJS (commonly referred to as "Angular.js" or "AngularJS 1.X") 
    is a JavaScript-based open-source front-end web application 
    framework mainly maintained by Google and by a community of
    individuals and corporations to address many of the challenges 
    encountered in developing single-page applications.
    </p-tabPanel>
 <p-tabPanel header="AngularV2.0" [closable]="true" 
   leftIcon="fa-bell-o" rightIcon="fa-bookmark-o">
    The successor to the older AngularJS web framework, 
    now simply known as "Angular". Angular takes a
    web component-based approach to build powerful applications 
    for the web. It is used along with TypeScript which provides  
    support for both older and new versions of JavaScript.
  </p-tabPanel>
  <p-tabPanel header="AngularV4.0" [disabled]="true">
    Angular version 4.0.0 is a major release following announced  
    adoption of Semantic Versioning, and is backwards compatible 
    with 2.x.x for most applications.
  </p-tabPanel>
</p-tabView>

```

前面的 TabView 将显示如下截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/7e400ef3-fe7a-427d-9b0d-f2f09e4ba243.png)

请记住，TabView 元素只应用`orientation`，`activeIndex`，`style`和`styleClass`属性，而所有其他属性都需要为选项卡面板元素定义。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter4/tabview`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter4/tabview).

# 摘要

在本章结束时，您将了解如何根据给定的用例处理各种按钮和面板组件。最初，我们涵盖了各种按钮组件。首先，我们从点击按钮变体开始，如 Button，RadioButton 和 SplitButton 组件；之后，我们转向选择值按钮变体，如 ToggleButton 和 SelectButton 组件，然后解释如何使用 Toolbar 组件将多个按钮分组。稍后，我们转向 PrimeNG 套件中提供的各种面板组件。面板组件之旅从有效地安排视图开始，使用 Panels 和 FieldSets，然后介绍如何使用垂直堆叠的 Accordion 组件，以及如何在 TabView 组件内部使用多个选项卡对内容进行分组。

下一章将详细介绍数据迭代组件，如 DataTable，导出 CSV 数据，DataList，OrderList，PickList，Schedule，以及树形分层组件，如 Tree 和 TreeTable 组件。所有这些组件都将以逐步的方式解释其所有可能的特性。


# 第五章：数据迭代组件

在本章中，我们将涵盖使用 PrimeNG 提供的数据迭代组件来可视化数据的基本和高级功能，其中包括 DataTable、DataList、PickList、OrderList、DataGrid、DataScroller、Tree 和 TreeTable。我们将从提供了诸多功能的 DataTable 组件开始，如过滤、排序、分页、选择、重新排序、列调整大小、切换等。然后我们将专注于其他各种组件，如 DataList，以列表格式呈现数据，并通过 PickList 和 OrderList 等列出的集合提供数据选择。

之后，我们还将看到两个更多的数据变化组件，如 DataGrid，它以网格导向布局排列大型数据集，以及 DataScroller，它根据用户滚动页面来懒加载数据。Tree 和 TreeTable 组件以树形式列出数据，并且它们大多基于相同的数据模型。在本章末尾，我们将讨论一个名为 Schedule 的复杂组件，用于可视化日历数据，并演示其懒加载功能的使用。

在本章中，我们将涵盖以下主题：

+   多功能 DataTable

+   在 DataTable 中选择行

+   在 DataTable 中对数据进行排序、过滤和分页

+   使用模板自定义单元格内容

+   在 DataTable 中调整、重新排序和切换列

+   使用 DataTable 进行单元格编辑

+   使 DataTable 响应式

+   使用列和行分组

+   使用懒加载 DataTable 处理大量数据

+   通过提供行模板进行行展开

+   以 CSV 格式导出数据

+   DataTable 事件和方法

+   使用 DataList 列出数据

+   使用 PickList 列出数据

+   使用 OrderList 列出数据

+   使用 DataGrid 进行网格化数据

+   使用 DataScroller 进行按需数据加载

+   使用 Tree 可视化数据

+   使用 TreeTable 可视化数据

+   使用 Schedule 管理事件

# 多功能 DataTable

DataTable 以表格格式显示数据。表格是数据按行和列排列，或者可能是更复杂的结构。它需要一个作为对象数组的值，通过`value`属性绑定，并且使用`p-column`组件定义列。一个基本的组件示例，用于显示在列表格式中的浏览器详情，将被写成如下形式：

```ts
<p-dataTable [value]="browsers">
 <p-column field="engine" header="Engine"></p-column>
  <p-column field="browser" header="Browser"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="grade" header="Grade"></p-column>
</p-dataTable>

```

`browsers`数组由具有`engine`、`browser`、`platform`和`grade`属性的对象组成。`field`属性将映射模型对象属性，而`header`属性用于显示列的标题。在实时应用程序中，我们使用服务从远程数据源获取数据。在这种情况下，服务被创建为可注入的服务，并且它使用 HTTP 模块来获取数据。浏览器服务将被定义为可观察对象，如下所示：

```ts
@Injectable()
export class BrowserService {

constructor(private http: Http) { }

getBrowsers(): Observable<Browser[]> {
 return this.http.get('/assets/data/browsers.json')
    .map(response => response.json().data as Browser[]);
  }
}

```

组件类必须为`value`属性定义一个`browser`对象（或项目）的数组。项目是从远程服务调用中检索的，如下所示：

```ts
browsers: Browser[];

constructor(private browserService: BrowserService) { }

ngOnInit() {
  this.browserService.getBrowsers().subscribe((browsers: any) 
    => this.browsers =  browsers);
}

```

以下屏幕截图显示了以表格格式呈现的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/cab55298-f1b0-47cc-b166-6effb9bb9ef1.png)

在前面的快照中，我们可以观察到行的替代颜色。这是一个特定于主题的行为。

PrimeNG 4.1 以更灵活的方式处理变更检测功能。

# 变更检测

DataTable 使用基于 setter 的检查或**ngDoCheck**来判断基础数据是否发生变化以更新**用户界面**（**UI**）。这是使用`immutable`属性进行配置的。如果启用（默认），则会使用基于 setter 的检测，因此数据更改（例如添加或删除记录）应始终创建一个新的数组引用，而不是操作现有数组。这个约束是由于 Angular，并且如果引用没有改变，就不会触发 setter。在这种情况下，删除项目时使用 slice 而不是 splice，或者在添加项目时使用扩展运算符而不是`push`方法。

另一方面，将`immutable`属性设置为`false`会移除使用 ngDoCheck 的限制，使用 IterableDiffers 来监听变化，而无需创建数据的新引用。基于 setter 的方法更快；然而，根据您的偏好，两种方法都可以使用。

# 动态列

在前面的用例中，列是使用`p-column`标签以静态表示定义的。还有另一种方法可以通过动态列在数据表中表示列。表列需要被实例化为一个数组。该数组将使用`ngFor`指令进行迭代，如下所示：

```ts
<p-dataTable [value]="basicBrowsers">
 <p-header>
    <div class="algin-left">
      <p-multiSelect [options]="columnOptions" [(ngModel)]="cols">
      </p-multiSelect>
    </div>
  </p-header>
  <p-column *ngFor="let col of cols" [field]="col.field" [header]="col.header"></p-column>
</p-dataTable>

```

`cols`属性描述了组件类中给定的列选项：

```ts
this.cols = [
  {field: 'engine', header: 'Engine'},
  {field: 'browser', header: 'Browser'},
  {field: 'platform', header: 'Platform'},
  {field: 'grade', header: 'Grade'}
];

```

以下屏幕截图显示了动态列在表格格式中的快照结果作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/a3408625-374d-4dc8-9d64-fa316e6432df.png)

在上面的快照中，列是使用多选下拉菜单动态添加或删除的。为了演示目的，我们从表格中删除了版本列字段。

# 在 DataTable 中选择行

为了在组件上执行 CRUD 操作，需要对表格行进行选择。PrimeNG 支持各种选择，如单选、多选、单选按钮和复选框，并带有不同的事件回调。

# 单选

在单选中，通过单击特定行上的单击事件来选择行。通过将`selectionMode`设置为`single`并将`selection`属性设置为所选行来启用此选择。默认情况下，可以通过 Meta 键（Windows 的 Ctrl 键或 macOS 的 Command 键）取消选择行。通过禁用`metaKeySelection`属性，可以在不按下 Meta 键的情况下取消选择行。

具有单选功能的组件，用于选择特定的浏览器记录，将如下所示编写：

```ts
<p-dataTable [value]="basicBrowsers" selectionMode="single"  
  [(selection)]="selectedBrowser">
  // Content goes here
</p-dataTable>

```

组件类必须定义`selectedBrower`对象来存储所选项目。以下屏幕截图显示了单选结果的快照：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/cb577df9-4538-4189-99c3-86c3eef404ae.png)

为了通知单选是否起作用，我们在页脚部分显示了所选记录的信息。页脚数据应始终与所选记录同步。

# 多选

在多选中，通过单击特定行上的单击事件来选择行，并且可以使用 Meta 键或*Shift*键选择多行。通过将`selectionMode`设置为`multiple`并将`selection`属性设置为以数组形式保存所选行来启用此选择。默认情况下，可以通过 Meta 键（Windows 的 Ctrl 键或 macOS 的 Command 键）取消选择行。通过禁用`metaKeySelection`属性，可以在不使用 Meta 键的情况下取消选择行。

具有多选功能的组件，用于选择多个浏览器记录，将如下所示编写：

```ts
<p-dataTable [value]="basicBrowsers" selectionMode="multiple" 
  [(selection)]="selectedBrowsers">
  // Content goes here
</p-dataTable>

```

组件类必须定义`selectedBrowers`数组对象来存储所选记录。以下屏幕截图显示了多选结果的快照：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/1d334d7f-706a-4aa3-bdb5-bb6eabcc5913.png)

为了通知多选是否起作用，我们在页脚部分显示了选定记录的信息。页脚数据应始终与选定的记录同步。

单选和多选都支持四个事件回调，`onRowClick`、`onRowDblClick`、`onRowSelect`和`onRowUnselect`，它们在事件对象中携带选定的数据信息。有关更多详细信息，请参阅事件部分。

# 单选按钮选择

单选可以通过单选按钮实现，每行都有单选按钮，而不是在特定行上使用单击事件。通过在列级别设置`selectionMode`为`single`（请记住，前面提到的普通选择是在表级别上工作的），并将`selection`属性设置为保存选定行的对象来启用选择。

具有单选按钮选择功能的组件，用于选择特定的浏览器记录，将如下编写：

```ts
<p-dataTable [value]="basicBrowsers" [(selection)]="selectedBrowser">
 <p-header> RadioButton selection (Single Selection)</p-header>
  <p-column [style]="{'width':'38px'}" selectionMode="single">
  </p-column>
  //Content goes here
</p-dataTable>

```

以下屏幕截图显示了单选按钮选择的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/495cc0c0-524b-4bee-b61e-31c6d095a8bc.png)

截至目前，单选按钮选择没有未选择的功能（也就是说，一旦选择了另一行，该行就会被取消选择）。

# 复选框选择

多选可以通过复选框实现，每行都有复选框，而不是在特定行上使用单击事件。通过在列级别设置`selectionMode`为`multiple`（请记住，普通选择在表级别提供此功能），并将`selection`属性设置为保存选定行的对象数组来启用选择。

具有复选框选择功能的组件，用于选择多个浏览器记录，将如下编写：

```ts
<p-dataTable [value]="basicBrowsers" [(selection)]="selectedBrowser">
 <p-header> Multiple Selection </p-header>
  <p-column [style]="{'width':'38px'}" selectionMode="multiple">
  </p-column>
  //Content goes here
</p-dataTable>

```

以下屏幕截图显示了复选框选择的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/aa4648a3-d61b-4d76-90d5-e7bead2a1093.png)

在这种选择中，选定的记录可以通过取消复选框来取消选择。复选框选择支持`onHeaderCheckboxToggle`事件，用于切换标题复选框。有关更多详细信息，请参阅事件部分。

启用选择时，请使用`dataKey`属性避免在比较对象时进行深度检查。如果无法提供`dataKey`，请使用`compareSelectionBy`属性设置为"equals"，它使用引用进行比较，而不是默认的"deepEquals"比较。深度比较不是一个好主意（特别是对于大量数据），因为它会检查所有属性。

例如，可以选择`browserId`属性的值作为`dataKey`，如下所示：

`<p-dataTable dataKey="browserId" selection="true">

...

</p-dataTable>`

# 在 DataTable 中对数据进行排序、过滤和分页

排序、过滤和分页功能对于任何类型的数据迭代组件来说都是非常重要的功能。在处理大型数据集时，这些功能将非常有帮助。

# 排序

通过在每一列上启用`sortable`属性来提供排序功能。默认情况下，组件支持单一排序（`sortMode="single"`）。我们可以通过设置`sortMode="multiple"`来实现多重排序。具有排序功能的 DataTable 组件，以按升序或降序对浏览器记录进行排序，将如下所示：

```ts
<p-dataTable [value]="browsers" (onSort)="onSort($event)">
  <p-column field="engine" header="Engine" [sortable]="true">
  </p-column>
  <p-column field="browser" header="Browser" [sortable]="true">
  </p-column>
  <p-column field="platform" header="Platform" [sortable]="true">
  </p-column>
  <p-column field="grade" header="Grade" [sortable]="true">
  </p-column>
</p-dataTable>

```

以下屏幕截图显示了对有限数量记录进行单一排序的快照结果：

！[](assets/a442c658-24dd-48c5-ae38-b47eab29d6ba.png)

我们需要使用 Meta 键（Windows 为 Ctrl，macOS 为 Command 键）来使用多列排序功能。还支持使用`sortFunction`函数进行自定义排序，而不是在`field`属性上进行常规排序。排序功能还提供了`onSort`事件回调，将在对列进行排序时调用。有关更多信息，请参阅事件详细信息部分。

# 过滤

通过在每一列上启用`filter`属性来提供过滤功能。过滤可以应用于列级别和整个表级别。表级别的过滤也称为全局过滤。要启用全局过滤，需要在`globalFilter`属性中引用输入的本地模板变量。全局过滤输入的`keyup`事件将被监听以进行过滤。

过滤功能支持可选的过滤属性，例如`filterMatchMode`，以提供不同类型的文本搜索。它有五种过滤匹配模式，如`startsWith`、`contains`、`endsWith`、`equals`和`in`，默认匹配模式是`startsWith`，而`filterPlaceholder`属性用于显示辅助占位文本。具有表列过滤功能的 DataTable 组件将如下所示：

```ts
<div class="ui-widget-header align-globalfilter">
 <i class="fa fa-search search-globalfilter"></i>
  <input #gb type="text" pInputText size="50" 
  placeholder="Global Filter">
</div>
<p-dataTable [value]="browsers" [rows]="10" [paginator]="true"   
  [globalFilter]="gb" #datatable (onFilter)="onFilter($event)">
  <p-header>List of Browsers</p-header>
  <p-column field="browser" header="Browser (contains)" [filter]="true" 
    [filterMatchMode]="contains"  filterPlaceholder="Search"></p-column>
  <p-column field="platform" header="Platform (startsWith)" 
    [filter]="true"
  filterPlaceholder="Search"></p-column>
  <p-column field="rating" header="Rating ({{browserFilter||'No 
    Filter'}}" 
    [filter]="true"  filterMatchMode="equals" [style]="
    {'overflow':'visible'}">
    <ng-template pTemplate="filter" let-col>
      <i class="fa fa-close"
  (click)="ratingFilter=null; 
        datatable.filter(null,col.field,col.filterMatchMode)"></i>
      <p-slider [styleClass]="'slider-layout'"
 [(ngModel)]="ratingFilter" [min]="1" [max]="10"
  (onSlideEnd)="datatable.filter
        ($event.value,col.field,col.filterMatchMode)">
      </p-slider>
    </ng-template>
  </p-column>
  <p-column field="engine" header="Engine (Custom)" [filter]="true"
 filterMatchMode="equals" [style]="{'overflow':'visible'}">
    <ng-template pTemplate="filter" let-col>
      <p-dropdown [options]="engines" [style]="{'width':'100%'}"
  (onChange)="datatable.filter($event.value,col.field,
        col.filterMatchMode)"  styleClass="ui-column-filter">
      </p-dropdown>
    </ng-template>
  </p-column>
  <p-column field="grade" header="Grade (Custom)" [filter]="true"
 filterMatchMode="in" [style]="{'overflow':'visible'}">
    <ng-template pTemplate="filter" let-col>
      <p-multiSelect [options]="grades" defaultLabel="All grades"
  (onChange)="datatable.filter($event.value,col.field,
        col.filterMatchMode)"  styleClass="ui-column-filter">
      </p-multiSelect>
    </ng-template>
  </p-column>
</p-dataTable>

```

过滤功能通常应用于普通输入组件，但也可以通过在各种其他输入上提供过滤器来自定义此行为，例如 Spinner、Slider、DropDown 和 MultiSelect 组件。自定义输入过滤器调用带有三个参数的`filter`函数。`filter`函数的签名将如下所示：

```ts
datatable.filter($event.value, col.field, col.filterMatchMode)

```

以下屏幕截图显示了一个具有过滤功能的快照结果，作为示例，记录数量有限：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/e53d5ecf-0d93-428e-9b70-13428f513f0c.png)

在前面的快照中，我们可以观察到数据是通过评分滑块和多选等级字段进行过滤的。过滤功能还提供了`onFilter`事件回调，该回调将在过滤输入时被调用。有关更多信息，请参阅事件详细信息部分。

# 分页

如果表格支持大型数据集，那么在单个页面上显示所有数据看起来很尴尬，当滚动数百万条记录时，对用户来说将是一场噩梦。DataTable 组件通过启用`paginator`属性和`rows`选项来支持分页功能，仅需显示页面中的记录数量。

除了上述必需的功能，它还支持各种可选功能，例如：

+   `pageLinks`属性显示了一次显示的页面链接数量。

+   `rowsPerPageOptions`属性允许更改在单个页面中显示的行数（作为数组的逗号分隔值）。

+   `totalRecords`属性显示了对于延迟加载功能有用的逻辑记录。

+   `paginatorPosition`属性显示分页器的可能值为`top`、`bottom`和`both`。分页器的默认位置是`bottom`。

用于显示大量浏览器信息的分页示例将如下所示：

```ts
<p-dataTable [value]="browsers" [rows]="10" [paginator]="true" 
  [pageLinks]="3" [rowsPerPageOptions]="[10,15,20]" 
  paginatorPosition="both"(onPage)="onPage($event)">
  <p-column field="engine" header="Engine"></p-column>
  <p-column field="browser" header="Browser"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="grade" header="Grade"></p-column>
</p-dataTable>

```

以下屏幕截图显示了一个具有分页功能的快照结果，作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/900610bd-c5df-41bc-9c74-f433a8db745f.png)

除了内置于 DataTable 中的分页器之外，我们还可以使用外部分页器来使用 Paginator 组件。分页功能还提供了`onPage`事件回调（而外部分页器提供了`onPageChange`回调），该回调将在分页时被调用。有关更多信息，请参阅事件详细信息部分。

# 使用模板自定义单元格内容

默认情况下，每列的`field`属性值用于显示表格内容。可以通过`ng-template`模板标签以各种可能的方式自定义内容，该模板标签可以应用于头部、主体和底部级别。传递给`ng-template`模板的`template`变量用于列定义，行数据由`rowData`属性使用。还可以通过`rowIndex`变量获得可选的行索引。

`ng-template`模板将具有`pTemplate`指令，其中包含了可能的值为`header`、`body`和`footer`的自定义类型。自定义的浏览器内容以各种文本颜色和行数据信息显示，并带有按钮选择，如下所示：

```ts
<p-dataTable [value]="basicBrowsers">
 <p-column field="engine" header="Engine"></p-column>
  <p-column field="browser" header="Browser"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="grade" header="Grade">
    <ng-template let-col let-browser="rowData" pTemplate="body">
      <span [style.color]="'Green'" *ngIf="browser[col.field]=='A'"> 
        {{browser[col.field]}}</span>
      <span [style.color]="'Blue'" *ngIf="browser[col.field]=='B'"> 
        {{browser[col.field]}}</span>
      <span [style.color]="'Red'" *ngIf="browser[col.field]=='C'">
        {{browser[col.field]}}</span>
    </ng-template>
  </p-column>
  <p-column styleClass="col-button">
    <ng-template pTemplate="header">
      <button type="button" pButton icon="fa-refresh"></button>
    </ng-template>
    <ng-template let-browser="rowData" pTemplate="body">
      <button type="button" pButton (click)="selectBrowser(browser)" 
        icon="fa-search"></button>
    </ng-template>
  </p-column>
</p-dataTable>

```

在上面的例子中，我们自定义了表格内容，根据成绩显示不同的颜色，使用 body 模板每行带有按钮选择，使用 header 模板在表头处有一个按钮。以下截图显示了自定义内容显示的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/22ba4594-3a72-4773-a293-2cf44be9615f.png)

根据上面的快照，`ng-template`模板标签用于不同类型，以提供完全灵活的自定义。

# 在 DataTable 中调整大小、重新排序和切换列

默认情况下，组件的所有列都是静态表示，没有交互。该组件为列提供了调整大小、重新排序和切换功能。

# 调整大小

可以通过将`resizableColumns`属性设置为`true`来使用拖放行为调整列的大小。有两种调整大小模式可用。一种是`fit`模式，另一种是`expand`模式。默认模式是`fit`模式。在此模式下，调整列时，表格的总宽度不会改变；而在`expand`模式下，表格的总宽度将会改变。

使用`expand`模式的调整功能将被编写如下：

```ts
<p-dataTable [value]="basicBrowsers" resizableColumns="true"  
  columnResizeMode="expand">
 <p-column field="engine" header="Engine"></p-column>
  <p-column field="browser" header="Browser"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="grade" header="Grade"></p-column>
</p-dataTable>

```

以下截图显示了使用`expand`调整大小模式的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/26c5545b-f4c5-442a-8f27-967a8ea38428.png)

在前面的快照中，我们可以观察到引擎和等级列都根据其内容大小调整大小，以优化屏幕区域。由于`expand`模式，表的总宽度也会改变。当列调整大小时，它还可以提供`onColumnResize`事件回调，该事件在列调整大小时传递调整大小的列标题信息。有关更多信息，请参阅事件详细信息部分。

# 重新排序

通常，表列的顺序将完全按照组件中定义的顺序显示。只需将`reorderableColumns`属性设置为`true`，即可使用拖放功能重新排序列。

重新排序功能将写成如下形式：

```ts
<p-dataTable [value]="browsers" reorderableColumns="true">
 <p-column field="engine" header="Engine"></p-column>
  <p-column field="browser" header="Browser"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="grade" header="Grade"></p-column>
</p-dataTable>

```

以下截图显示了重新排序功能的快照结果示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/d950ccd2-0ffb-4bab-aa79-c8a9a96987d4.png)

根据前面的快照，平台和浏览器列字段是相互重新排序的（即，初始列顺序为`engine`、`browser`、`platform`和`grade`。重新排序后，列的顺序将变为`engine`、`platform`、`browser`和`grade`）。每当列重新排序时，它还提供`onColReorder`事件回调。有关更多详细信息，请参阅事件部分。

# 切换

大多数情况下，屏幕空间不足以显示所有列。在这种情况下，切换表列将非常有助于节省可用的屏幕空间。由于此功能，只能显示必需或主要列。可以通过在动态列表上定义 MultiSelect 组件来实现此功能，以切换列。请参阅本章开头提到的动态列示例。

# 使用 DataTable 进行单元格内编辑

默认情况下，组件的内容将处于只读模式（即，我们无法编辑内容）。使用单元格编辑功能，UI 将更具交互性。只需在表和列级别上设置`editable`属性，即可启用单元格编辑功能。单击单元格时，将激活编辑模式。在单元格外部单击或按下“Enter”键后，将切换回查看模式并更新值。单元格编辑功能将写成如下形式：

```ts
<p-dataTable [value]="browsers" [editable]="true">
 <p-column field="browser" header="Browser" [editable]="true">
  </p-column>
  <p-column field="platfrom" header="Platform" [editable]="false">
  </p-column>
  <p-column field="engine" header="Engine" [editable]="true">
    <ng-template let-col let-browser="rowData" pTemplate="editor">
      <p-dropdown [(ngModel)]="browser[col.field]" [options]="engines"  
        [autoWidth]="false"  required="true"></p-dropdown>
    </ng-template>
  </p-column>
  <p-column field="grade" header="Grade" [editable]="true">
  </p-column>
</p-dataTable>

```

以下截图显示了在`engine`字段上使用单元格编辑功能的快照结果示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/921af400-6547-4e89-9417-004e2bc3b29e.png)

默认情况下，可编辑模式在单击特定单元格时启用输入组件。我们还可以使用其他输入组件，如 DropDown、MultiSelect、Calendar 等，进行自定义输入编辑。在前面的示例中，我们可以使用 Input 和 Dropdown 组件编辑单元格。

# 使 DataTable 响应式

响应功能对于 Web 和移动应用程序都非常有用。如果屏幕尺寸小于某个断点值，则组件列将以响应模式堆叠显示。通过将`responsive`属性设置为`true`来启用此功能。此堆叠行为也可以通过手动实现（不考虑屏幕尺寸）来实现，方法是启用`stacked`属性（即`stacked="true"`）。

Table 组件的响应模式功能将被编写如下：

```ts
<button pButton type="button" (click)="toggle()" 
  [class]="responsive-toggle"
 label="Toggle" icon="fa-list">
</button>
<p-dataTable [value]="browsers" [rows]="5" [paginator]="true" 
  [pageLinks]="3" [responsive]="true" [stacked]="stacked">
  <p-header>Responsive</p-header>
  <p-column field="engine" header="Engine"></p-column>
  <p-column field="browser" header="Browser"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="grade" header="Grade"></p-column>
</p-dataTable>

```

组件类定义了`toggle`方法，用于切换响应行为，如下所示：

```ts
toggle() {
 this.stacked = !this.stacked;
}

```

以下屏幕截图显示了 DataTable 组件具有堆叠列的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/3378e8e2-6fe8-4f3a-abf8-13caf0270c33.png)

在这种用例中，列通过手动切换按钮以堆叠的方式显示，该按钮放置在表格外部。响应模式或堆叠行为也可以通过减小或最小化屏幕尺寸来实现。

# 使用列和行分组

DataTable 组件在列级和行级都提供了分组功能。

# 列分组

可以使用`p-headerColumnGroup`和`p-footerColumnGroup`标签在表头和表尾区域对列进行分组，这些标签使用`colspan`和`rowspan`属性定义列的数组。表行使用`p-row`标签定义，其中包含列组件。具有列分组的组件将被编写如下：

```ts
<p-dataTable [value]="basicBrowsers">
 <p-headerColumnGroup>
    <p-row>
      <p-column header="Browser" rowspan="3"></p-column>
      <p-column header="Details" colspan="4"></p-column>
    </p-row>
    <p-row>
      <p-column header="Environment" colspan="2"></p-column>
      <p-column header="Performance" colspan="2"></p-column>
    </p-row>
    <p-row>
      <p-column header="Engine"></p-column>
      <p-column header="Platform"></p-column>
      <p-column header="Rating"></p-column>
      <p-column header="Grade"></p-column>
    </p-row>
  </p-headerColumnGroup>

  <p-column field="browser"></p-column>
  <p-column field="engine"></p-column>
  <p-column field="platform"></p-column>
  <p-column field="rating"></p-column>
  <p-column field="grade"></p-column>

  <p-footerColumnGroup>
    <p-row>
      <p-column footer="*Please note that Chrome browser 
        details not included"
 colspan="5"></p-column>
    </p-row>
  </p-footerColumnGroup>
</p-dataTable>

```

以下屏幕截图显示了列分组功能的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/b3c4eef3-4848-49f4-a753-4540361e5adc.png)

在前面的快照中，我们可以观察到特定于浏览器的信息是通过列分组进行分类的。

# 行分组

默认情况下，表行是单独的，并逐个显示以表示唯一记录。在许多情况下，需要将多个行分组为一行。

# 可展开的行分组

行可以根据特定字段进行分组，以便使用行展开器功能展开和折叠行。通过设置`rowGroupMode="subheader"`、`expandableRowGroups="true"`和`groupField="browser"`来启用此功能。`groupField`设置为特定的分类列。

具有可展开行组选项的行分组功能将被编写如下：

```ts
<p-dataTable [value]="browsers" sortField="browser"  
  rowGroupMode="subheader" groupField="browser"  
  expandableRowGroups="true" [sortableRowGroup]="false">
  <p-header>Toggleable Row Groups with Footers</p-header>
  <ng-template pTemplate="rowgroupheader" let-rowData> 
    {{rowData['browser']}}
 </ng-template>
  <p-column field="engine" header="Engine"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="rating" header="rating">
    <ng-template let-col let-browser="rowData" pTemplate="body">
      <span>{{browser[col.field]}} 'Stars'</span>
    </ng-template>
  </p-column>
  <ng-template pTemplate="rowgroupfooter" let-browser>
    <td colspan="3" style="text-align:right">Chrome browsers are not 
      included</td>
  </ng-template>
</p-dataTable>

```

以下截图显示了可展开的行分组功能的快照结果，作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/53bdc307-5891-4945-973e-21b59329cf01.png)

在这种情况下，我们展开了 Firefox 版本 3 组，以查看随时间变化的所有浏览器细节。

# 子标题

所有相关项目可以使用子标题功能分组在一个子组下。这个用例类似于展开的行组，但这些子标题不能被折叠。通过设置`rowGroupMode="subheader"`和`groupField="engine"`来启用此行为。`groupField`属性设置为特定的分类列。

具有子标题选项的行分组功能将被编写如下：

```ts
<p-dataTable [value]="browsers" sortField="engine"  
  rowGroupMode="subheader"
 groupField="engine" [styleClass]="'rowgroup-padding'">
  <p-header>Subheader</p-header>
  <ng-template pTemplate="rowgroupheader" let-rowData>
    {{rowData['engine']}}
 </ng-template>
  <p-column field="browser" header="Browser" sortable="true">
  </p-column>
  <p-column field="platform" header="Platform" sortable="true">
  </p-column>
  <p-column field="grade" header="Grade" sortable="true">
  </p-column>
</p-dataTable>

```

以下截图显示了具有子标题分组功能的表格的快照结果，作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/22b2b37a-eee9-4b12-b0f9-dd2ea123205a.png)子标题分组功能

在前面的用例中，所有浏览器细节都基于唯一的浏览器引擎进行分组，作为子标题。

# RowSpan 组

行可以根据`sortField`属性进行分组。通过将`rowGroupMode`属性值设置为`rowspan`（即`rowGroupMode="rowspan"`）来启用此功能。具有行跨度的行分组示例将被编写如下：

```ts
<p-dataTable [value]="browsers" sortField="engine"   
  rowGroupMode="rowspan"
 [styleClass]="'rowgroup-padding'">
  <p-header>RowSpan</p-header>
  <p-column field="engine" header="Engine" sortable="true"></p-column>
  <p-column field="platform" header="Platform" sortable="true">
  </p-column>
  <p-column field="browser" header="Browser" sortable="true">
  </p-column>
  <p-column field="grade" header="Grade" sortable="true"></p-column>
</p-dataTable>

```

以下截图显示了具有行跨度分组功能的组件的快照结果，作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/791fe8fc-8f0d-432e-a5ad-7f1236c98d59.png)行跨度分组功能

在这个版本的行分组中，浏览器的“引擎”字段用于跨越其所有相关项目的行分组。

# 使用延迟加载 DataTable 处理大量数据

延迟加载是处理大型数据集的非常关键的功能。此功能通过分页、排序和过滤操作加载数据块，而不是一次性加载所有数据。通过设置`lazy`模式（`lazy="true"）并使用`onLazyLoad`回调来进行用户操作，事件对象作为参数。事件对象保存了分页、排序和过滤数据。

还需要使用投影查询显示要用于分页配置的逻辑记录数量。这是因为在延迟加载中我们只能检索当前页的数据。没有关于剩余记录的信息可用。因此，需要根据数据源中的实际记录显示分页链接。这可以通过表组件上的`totalRecords`属性实现。

具有延迟加载功能的组件将被编写如下：

```ts
<p-dataTable [value]="browsers" [lazy]="true" [rows]="10" 
  [paginator]="true" [totalRecords]="totalRecords" 
  (onLazyLoad)="loadBrowsersLazy($event)">
  <p-header>List of browsers</p-header>
  <p-column field="engine" header="Engine" [sortable]="true" 
  [filter]="true">
  </p-column>
  <p-column field="browser" header="Browser" [sortable]="true" 
  [filter]="true">  
  </p-column>
  <p-column field="platform" header="Platform" [sortable]="true" 
  [filter]="true">
  </p-column>
 <p-column field="grade" header="Grade" [sortable]="true" 
  [filter]="true">
  </p-column>
</p-dataTable>

```

组件类定义了延迟加载回调，以根据需要检索数据，如下所示：

```ts
loadBrowsersLazy(event: LazyLoadEvent) {
 //event.first = First row offset //event.rows = Number of rows per page //event.sortField = Field name to sort with //event.sortOrder = Sort order as number, 1 for asc and -1 for dec //filters: FilterMetadata object having field as 
  //key and filter value, 
  //filter matchMode as value    this.browserService.getBrowsers().subscribe((browsers: any) =>
    this.browsers = browsers.slice(event.first, 
    (event.first + event.rows)));
}

```

作为延迟加载的演示，我们使用分页操作来检索数据。我们还可以使用排序和过滤功能。以下截图显示了一个快照结果，以便作为示例进行说明：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/a80bbff2-1e08-434a-9115-0dcfc73c468e.png)

在上面的快照中，我们可以清楚地观察到第 4 页的信息是动态从远程数据源检索的。有关延迟加载事件回调的更多详细信息，请参考事件部分。

总是更喜欢对大型数据集使用延迟加载以提高性能。

# 通过提供行模板进行行展开

在许多情况下，不可能容纳表中的所有数据。表数据的次要或附加信息需要以不同的表示形式填充。行展开功能允许为特定行显示详细内容（即，在请求时显示在单独的块中显示数据）。要使用此功能，请启用`expandableRows`属性，并使用`expander`属性作为单独列添加扩展列，以及常规列以切换行。要声明扩展内容，请使用`pTemplate`指令，并将`rowexpansion`作为值。从`ng-template`中使用本地模板引用变量来访问表数据。

具有行展开功能以显示浏览器的完整详细信息的组件将被编写如下：

```ts
<p-dataTable [value]="basicBrowsers" expandableRows="true"   
  [expandedRows]="expandedRows">
  <p-column expander="true" styleClass="col-icon" header="Toggle">
  </p-column>
  <p-column field="engine" header="Engine"></p-column>
  <p-column field="browser" header="Browser"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="grade" header="Grade"></p-column>
  <ng-template let-browser pTemplate="rowexpansion">
    <div class="ui-grid ui-grid-responsive ui-fluid 
      rowexpansion-layout">
      <div class="ui-grid-row">
        <div class="ui-grid-col-9">
          <div class="ui-grid ui-grid-responsive ui-grid-pad">
            <div class="ui-grid-row">
              <div class="ui-grid-col-2 label">Engine:</div>
              <div class="ui-grid-col-10">{{browser.engine}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2 label">Browser:</div>
              <div class="ui-grid-col-10">{{browser.browser}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2 label">Platform:</div>
              <div class="ui-grid-col-10">{{browser.platform}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2 label">Version:</div>
              <div class="ui-grid-col-10">{{browser.version}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2 label">Rating:</div>
              <div class="ui-grid-col-10">{{browser.rating}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2 label">Grade:</div>
              <div class="ui-grid-col-10">{{browser.grade}}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </ng-template>
</p-dataTable>

```

如果需要，可以使用`expandedRows`属性将展开的行存储在组件类内的数组变量中。以下截图显示了具有行展开功能的组件的快照结果作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/315ca686-6d19-4e77-b737-4038ecd4d17c.png)

默认情况下，可以一次展开多行。我们可以通过将`rowExpandMode`属性设置为`single`来进行严格的单行展开。

我们也可以为分组表格应用行展开行为：

+   该组件提供了一个`expandableRowGroups`布尔属性，用于创建切换行组的图标。

+   默认情况下，所有行都将被展开。`expandedRowGroups`属性用于保存要默认展开特定行组的行数据实例。

提供了名为`toggleRow`的方法，用于切换表格行与行数据。

# 以 CSV 格式导出数据

数据可以在在线模式下随时以表格格式查看。但是，也需要离线模式下的数据。此外，在许多情况下，我们需要从网站获取大量数据报告。PrimeNG DataTable 可以使用`exportCSV()`API 方法以 CSV 格式导出。放置在表格内部或外部的按钮组件可以触发此方法，以便以 CSV 格式下载数据。具有导出 API 方法调用的组件将被编写如下：

```ts
<p-dataTable #dt [value]="basicBrowsers" exportFilename="browsers"   
  csvSeparator=";">
 <p-header>
    <div class="ui-helper-clearfix">
    <button type="button" pButton icon="fa-file-o" iconPos="left" label="CSV" (click)="dt.exportCSV()" style="float:left"></button>
    </div>
  </p-header>
  <p-column field="engine" header="Engine"></p-column>
  <p-column field="browser" header="Browser"></p-column>
  <p-column field="platform" header="Platform"></p-column>
  <p-column field="grade" header="Grade"></p-column>
</p-dataTable>

```

默认情况下，导出的 CSV 使用逗号（`,`）作为分隔符。但是，可以使用 DataTable 组件上的`csvSeparator`属性更改此行为。

# DataTable 事件和方法

DataTable 组件针对每个功能提供了许多事件回调和方法。以下表格列出了所有表格事件回调的名称、参数详情和描述：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `onRowClick` |

+   `event.originalEvent`: 浏览器事件

+   `event.data`: 选定的数据

| 当点击行时调用的回调函数。 |
| --- |
| `onRowSelect` |

+   `event.originalEvent`: 浏览器事件

+   `event.data`: 选定的数据

+   `event.type`: 选择类型，有效值为`row`、`radiobutton`和`checkbox`

| 当选择行时调用的回调函数。 |
| --- |
| `onRowUnselect` |

+   `event.originalEvent`: 浏览器事件

+   `event.data`: 未选择的数据

+   `event.type`: 取消选择类型，有效值为`row`和`checkbox`

| 当使用 Meta 键取消选择行时调用的回调函数。 |
| --- |
| `onRowDblclick` |

+   `event.originalEvent`: 浏览器事件

+   `event.data`: 选定的数据

| 当双击选择行时调用的回调函数。 |
| --- |
| `onHeaderCheckboxToggle` |

+   `event.originalEvent`: 浏览器事件

+   `event.checked`: 头部复选框的状态

| 当头部复选框状态改变时调用的回调函数。 |
| --- |
| `onContextMenuSelect` |

+   `event.originalEvent`: 浏览器事件

+   `event.data`: 选定的数据

| 当右键选择行时调用的回调函数。 |
| --- |
| `onColResize` |

+   `event.element`: 调整列标题大小

+   `event.delta`：宽度变化的像素数

| 当列调整大小时调用的回调函数。 |
| --- |
| `onColReorder` |

+   `event.dragIndex`：拖动列的索引

+   `event.dropIndex`：放置列的索引

+   `event.columns`：重新排序后的列数组

| 当列重新排序时调用的回调函数。 |
| --- |
| `onLazyLoad` |

+   `event.first`：第一行偏移

+   `event.rows`：每页的行数

+   `event.sortField`：用于排序的字段名称

+   `event.sortOrder`：排序顺序作为数字，升序为`1`，降序为`-1`

+   `过滤器`：具有字段作为键和过滤器值、过滤器`matchMode`作为值的`FilterMetadata`对象

| 当在延迟模式下进行分页、排序或过滤时调用的回调函数。 |
| --- |
| `onEditInit` |

+   `event.column`：单元格的列对象

+   `event.data`：行数据

| 当单元格切换到编辑模式时调用的回调函数。 |
| --- |
| `onEdit` |

+   `event.originalEvent`：浏览器事件

+   `event.column`：单元格的列对象

+   `event.data`：行数据

+   `event.index`：行索引

| 当编辑单元格数据时调用的回调函数。 |
| --- |
| `onEditComplete` |

+   `event.column`：单元格的列对象

+   `event.data`：行数据

+   `event.index`：行索引

| 当单元格编辑完成时调用的回调函数（仅支持*Enter*键）。 |
| --- |
| `onEditCancel` |

+   `event.column`：单元格的列对象

+   `event.data`：行数据

+   `event.index`：行索引

| 当使用*Esc*键取消单元格编辑时调用的回调函数。 |
| --- |
| `onPage` |

+   `event.first`：页面中第一条记录的索引

+   `event.rows`：页面上的行数

| 当分页发生时调用的回调函数。 |
| --- |
| `onSort` |

+   `event.field`：已排序列的字段名称

+   `event.order`：排序顺序为 1 或-1

+   `event.multisortmeta`：多重排序模式中的排序元数据。有关此对象结构的多重排序部分，请参见多重排序部分。

| 当列排序时调用的回调函数。 |
| --- |
| `onFilter` | `event.filters`：具有`field`作为属性键和具有值、`matchMode`作为属性值的对象的过滤器对象。 | 当数据被过滤时调用的回调函数。 |
| `onRowExpand` |

+   `event.originalEvent`：浏览器事件

+   `data`：要展开的行数据

| 当行展开时调用的回调函数。 |
| --- |
| `onRowCollapse` |

+   `event.originalEvent`：浏览器事件

+   `data`：要折叠的行数据

| 当行折叠时调用的回调函数。 |
| --- |
| `onRowGroupExpand` |

+   `event.originalEvent`：浏览器事件

+   `group`：分组的值

| 当行组展开时调用的回调函数。 |
| --- |
| `onRowGroupCollapse` |

+   `event.originalEvent`：浏览器事件

+   `group`：组的值

| 折叠行组时调用的回调。 |
| --- |

以下表格列出了常用的表格方法及其名称、参数和描述：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `reset` | - | 重置排序、过滤和分页器状态 |
| `exportCSV` | - | 以 CSV 格式导出数据 |
| `toggleRow` | `data` | 切换给定行数据的行扩展 |

PrimeNG 版本 4.0.1 重新引入了`rowTrackBy`选项，用于迭代组件，如 DataTable、DataGrid 和 DataList，以改善 DOM 优化。也就是说，通过将决策委托给`ngForTrackBy`指令来优化每一行的 DOM 插入和更新。在 PrimeNG 中，这将通过`rowTrackBy`属性实现。如果未定义该属性，默认情况下算法会检查对象标识。例如，浏览器行通过 ID 属性标识为

`trackById(index, browser) { return browser.id; }`。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/datatable`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/datatable)。

# 使用 DataList 列出数据

DataList 组件用于以列表布局显示数据。它需要一个项目集合作为其值，并使用`ng-template`显示内容，其中每个项目都可以使用本地模板变量访问。该模板还使用`let-i`表达式表示每个项目的索引。将所有浏览器详细信息显示为列表格式的 DataList 组件的基本示例将如下所示：

```ts
<p-dataList [value]="basicBrowsers">
 <ng-template let-browser pTemplate="item">
    <div class="ui-grid ui-grid-responsive ui-fluid" 
      class="content-layout">
      <div class="ui-grid-row">
        <div class="ui-grid-col-3">
          <img src="/assets/data/images/{{browser.code}}.png" 
            width="100" height="80"/>
        </div>
        <div class="ui-grid-col-9">
          <div class="ui-grid ui-grid-responsive ui-fluid">
            <div class="ui-grid-row">
              <div class="ui-grid-col-2">Engine: </div>
              <div class="ui-grid-col-10">{{browser.engine}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2">Browser: </div>
              <div class="ui-grid-col-10">{{browser.browser}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2">Platform: </div>
              <div class="ui-grid-col-10">{{browser.platform}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2">Version: </div>
              <div class="ui-grid-col-10">{{browser.version}}</div>
            </div>
            <div class="ui-grid-row">
              <div class="ui-grid-col-2">Grade: </div>
              <div class="ui-grid-col-10">{{browser.grade}}</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </ng-template>
</p-dataList>

```

需要从外部服务中检索浏览器详细信息的列表。在这种情况下，`BrowserService`服务将被注入到组件类中，以检索浏览器信息。我们使用可观察对象使用 HTTP 模块获取数据。列表数据将在页面加载时检索如下：

```ts
basicBrowsers: Browser[];

constructor(private browserService: BrowserService) { }

ngOnInit() {
  this.browserService.getBrowsers().subscribe(
    (browsers:any) => this.basicBrowsers = browsers.slice(0,4));
}

```

出于演示目的，我们将记录数限制为五条。以下屏幕截图显示了 DataList 组件以列表格式的快照结果作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/08a0bc0e-a8e6-499a-83f8-ba98966c0d4a.png)

前面的快照只是以表格格式显示数据。在下一节中，您可以找到更多功能，使数据列表成为一个强大的组件。

# Facets 和分页

数据列表组件支持诸如标题和页脚之类的面板，使用 `p-header` 和 `p-footer` 标签。为了改善大型数据集上的用户体验，它支持分页功能。通过将 `paginator` 属性设置为 `true` 来启用此功能，并使用 `rows` 属性设置要显示的行数。除了这些必需的设置之外，分页还有一些可选的自定义设置。在所有这些可选属性中，`paginatorPosition` 用于在 `top`、`bottom` 或 `both` 位置显示分页器；`rowsPerPageOptions` 用于显示一个下拉菜单，其中包含要在一页中显示的可能行数；`emptyMessage` 用于在没有记录存在时显示数据列表主体。分页还支持 `onPage` 事件回调，该事件将在页面导航时被调用。有关更多详细信息，请参阅事件部分。

具有面板和分页功能的数据列表组件以显示浏览器信息如下：

```ts
<p-dataList [value]="advancedBrowsers" [paginator]="true" [rows]="5"
 (onPage)="onPagination($event)" [rowsPerPageOptions]="[5,10,15]"
 [paginatorPosition]="both" [emptyMessage]="'No records found'">
  <p-header>
    List of Browsers
  </p-header>
    .... // Content
 <p-footer>
    Note: Grades are 3 types.A,B and C.
 </p-footer> </p-dataList>

```

以下屏幕截图显示了带有分页的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/159ed065-ba9d-4de1-90db-3f45ecf1a3d7.png)

数据列表组件提供了可自定义的所有分页控件选项。

# 懒加载

懒加载是处理大型数据集的非常有用的功能。它不会一次加载所有数据，而是根据用户需求逐步加载。DataList 支持分页交互上的懒加载。通过启用 `lazy` 属性（即 `lazy="true"`）并调用 `onLazyLoad` 回调来实现此功能，从远程数据源检索数据。有关签名和更多详细信息，请参阅事件部分。

懒加载事件对象提供了页面中的第一条记录和当前页面中的行数，以获取下一组数据。此外，您应该通过投影查询提供总记录以进行分页配置。即使在页面加载时没有那么多记录可用（即，仅在懒惰模式下存在当前页面记录），这对基于可用记录总数显示分页链接非常有用。

让我们以此处显示的基本原型为例，来介绍数据列表组件的懒加载功能：

```ts
<p-dataList [value]="lazyloadingBrowsers" [paginator]="true" [rows]="5"   
  [lazy]="true"
 (onLazyLoad)="loadData($event)" [totalRecords]="totalRecords">
  ... // Content
</p-dataList>

```

组件类必须定义懒加载事件回调，以根据用户请求（在本例中，将是分页）检索记录，如下所示：

```ts
loadData(event:any) {
 let start = event.first;//event.first = First row offset
  let end = start + event.rows;//event.rows = Number of rows per page
  this.browserService.getBrowsers().subscribe((browsers: any) =>
 this.lazyloadingBrowsers = browsers.slice(start,end));
}

```

在上述代码片段中，您可以观察到事件的`first`和`rows`属性对于检索下一批记录非常有帮助。根据`rows`属性，它尝试在每个实例上获取下一个`rows`数量的记录。

# 事件

该组件提供两个事件回调，一个用于分页，另一个用于懒加载。两个事件都提供两个参数，以获取页面上第一条记录和行数。懒加载事件在启用懒加载模式的情况下，通过分页、过滤和排序功能来调用。

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `onLazyLoad` |

+   `event.first`：第一行偏移

+   `event.rows`：每页的行数

| 当分页、排序或过滤以懒加载模式发生时调用的回调函数。 |
| --- |
| `onPage` |

+   `event.first`：页面中第一条记录的索引

+   `event.rows`：页面上的行数

| 当分页发生时调用的回调函数。 |
| --- |

它还提供许多其他功能，例如用于页眉和页脚显示的 facets（`p-header`和`p-footer`），用于在多个页面之间导航的分页，以及用于根据需要检索数据的懒加载功能。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/datalist`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/datalist)。

# 使用 PickList 列出数据

PickList 组件用于在两个不同的列表之间移动项目。您还可以在每个列表内重新排序项目。这提供了所选项目的整体状态。项目可以使用默认按钮控件或拖放行为进行移动/重新排序。PickList 需要两个数组，一个用于源列表，另一个用于目标列表。使用`ng-template`模板标签来显示项目的内容，其中数组中的每个项目都可以使用本地`ng-template`变量访问。

使用国家信息的 PickList 组件的基本示例将如下所示：

```ts
<p-pickList [source]="sourceCountries" [target]="targetCountries"
 [sourceStyle]="{'height':'350px'}" [targetStyle]="{'height':'350px'}">
  <ng-template let-country pTemplate="item">
    <div class="ui-helper-clearfix">
      <img src="/assets/data/images/country/
        {{country.code.toLowerCase()}}.png" />
      <span>{{country.flag}} - {{country.name}}({{country.dial_code}})
 </span>
    </div>
 </ng-template>
</p-pickList>

```

在组件类中，让我们定义一个用于可用数据的源列表，以及一个用于表示尚未进行选择的空列表。需要注入国家服务以从外部资源访问国家信息：

```ts
sourceCountries: Country[];
targetCountries: Country[];

constructor(private countryService: CountryService) { }

ngOnInit() {
 this.countryService.getCountries().subscribe(
    (countries: Country[]) => 
  {
    this.sourceCountries = countries;
  });
  this.targetCountries = [];
}

```

默认情况下，源和目标面板都具有默认的`width`和`height`属性。但是可以使用`sourceStyle`和`targetStyle`属性来自定义此默认行为。以下屏幕截图显示了初始 PickList 的快照结果。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/1b53673b-98fa-4b8a-a683-d87d50f81115.png)

PickList 组件提供了六个事件回调，用于在两个列表之间移动项目和对源和目标区域中的项目进行排序。在这六个回调中，有四个用于移动项目，`onMoveToTarget`、`onMoveToSource`、`onMoveAllToSource`和`onMoveAllToSource`，而排序项目则由`onSourceReorder`和`onTargetReorder`执行。

该组件可以通过不同的方式进行自定义，如下所述：

+   可以使用`sourceHeader`和`targetHeader`作为属性来自定义标题。

+   网页将使用`responsive`属性（`responsive="true"`）变得响应式，根据屏幕大小调整按钮控件。

+   默认情况下，通过禁用`metaKeySelection`属性（`metaKeySelection="false"`）来防止默认的多重选择（借助 Meta 键）。

+   按钮控件的可见性通过`showSourceControls`和`showTargetControls`属性进行控制。例如，`showSourceControls="false"`和`showTargetControls="false"`。

PrimeNG 4.1 支持使用`filterBy`属性对项目字段进行过滤，这是一个新的功能。可以通过在`filterBy`属性中放置逗号分隔的字段来过滤多个字段：

```ts
<p-pickList [source]="sourceCountries"  [target]="targetCountries"   filterBy="name, code">
  ...
</p-pickList>

```

新的 4.1 版本还支持启用`dragdrop`属性来实现拖放功能（在同一列表内或跨列表）。它还提供了`dragdropScope`属性，用于保存唯一键以避免与其他拖放事件发生冲突。拖放功能示例如下：

```ts
<p-pickList [source]="sourceCountries" [target]="targetCountries"   
  sourceHeader="Available" targetHeader="Selected" [dragdrop]="true" 
  dragdropScope="name">
   ...
</p-pickList>

```

完整的演示应用程序及说明可在 GitHub 上找到。

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/picklist`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/picklist)。

# 使用 OrderList 列出数据。

OrderList 组件用于按不同方向（上下）对项目集合进行排序。该组件需要一个数组类型变量来存储其值，并使用`ng-template`来显示项目数组的内容。每个项目将在`ng-template`模板中使用本地`ng-template`变量进行访问。当项目位置发生变化时，后端数组也会更新以存储最新的项目顺序。

使用国家信息的 OrderList 组件的基本示例将如下编写：

```ts
<p-orderList [value]="countries" header="Favourite countries" >
 <ng-template let-country pTemplate="item">
    <div class="ui-helper-clearfix">
      <img src="/assets/data/images/country/
        {{country.code.toLowerCase()}}.png" />
      <span class="content-format">
        {{country.flag}} {{country.name}}({{country.dial_code}})
 </span>
    </div>
  </ng-template>
</p-orderList>

```

在组件类中，让我们定义一个国家列表来显示项目的集合。如下所示，需要注入国家服务以从外部资源或数据源访问国家信息：

```ts
countries: Country[];

constructor(private countryService: CountryService) { }

ngOnInit() {
 this.countryService.getCountries().subscribe((countries: Country[]) =>
  {
    this.countries = countries;
  });
}

```

默认情况下，列表面板具有默认的`width`和`height`属性。但是可以使用`listStyle`属性进行自定义。以下截图显示了初始顺序列表的快照结果作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/8876ef10-8734-4396-8a64-ff4338298a27.png)

OrderList 组件提供了三种不同的事件回调，如下所示：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `onReorder` | `event`：浏览器事件 | 重新排序列表时要调用的回调函数。 |
| `onSelectionChange` |

+   `originalEvent`：浏览器事件

+   `value`：当前选择

| 选择更改时要调用的回调函数。 |
| --- |
| `onFilterEvent` |

+   `originalEvent`：浏览器事件

+   `value`：当前过滤值

| 发生过滤时要调用的回调函数。 |
| --- |

可以按以下方式以不同方式自定义组件的默认行为：

+   可以使用`header`属性自定义标题

+   `responsive`属性（`responsive="true"`）用于应用响应式行为，根据屏幕大小调整按钮控件

+   通过禁用`metaKeySelection`属性（`metaKeySelection="false"`）来防止默认的多重选择（借助于 Meta 键）。

以下截图显示了具有前面提到的自定义的国家列表的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/1d2573f1-feb9-4aa7-b23f-cb1c58261d48.png)

在前面的快照中，您可以观察到由于其`responsive`特性（`responsive="true"`），控件出现在顶部。我们还可以观察到面板宽度已根据视口大小进行了调整（使用`listStyle`属性）。

PrimeNG 4.1 版本支持过滤和拖放功能作为新的添加。过滤功能可以使用`filterBy`属性应用于单个字段和多个字段，类似于 DataTable 组件。例如，对国家数据进行多重过滤的功能如下：

```ts
<p-orderList [value]="countries" filterBy="name, code">
 ...
</p-orderList>

```

新的 4.1 版本还支持通过启用`dragdrop`属性重新排序项目的拖放功能。它还提供了`dragdropScope`属性，用于保存唯一键以避免与其他拖放事件发生冲突。拖放功能示例如下：

```ts
<p-orderList [value]="countries" [dragdrop]="true" dragdropScope="name">
  ...
</p-orderList>

```

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/orderlist`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/orderlist)。

# 以 DataGrid 为例的网格化数据

DataGrid 以网格导向布局显示数据。数据以多个单元格以规律的方式排列的布局形式表示。它需要一个作为`value`属性的数组的项目集合和`ng-template`模板标签来显示其内容，其中每个项目都可以使用本地模板变量进行访问。模板内容需要包装在一个`div`元素中，以便使用任何网格 CSS 样式以网格布局格式化数据。

数据网格组件的基本示例与浏览器信息将如下所示：

```ts
<p-dataGrid [value]="basicBrowsers">
 <ng-template let-browser pTemplate="item">
    <div style="padding:3px" class="ui-g-12 ui-md-3">
      <p-panel [header]="browser.browser" [style]="{'text-
        align':'center'}">
        <img src="/assets/data/images/{{browser.code}}.png" 
          width="50"height="50"> 
        <div class="car-detail">{{browser.engine}} - 
          {{browser.version}}
 </div>
        <hr class="ui-widget-content" style="border-top:0">
        <i class="fa fa-search" (click)="selectBrowser(browser)"
 style="cursor:pointer"></i>
      </p-panel>
    </div>
  </ng-template>
</p-dataGrid>

```

组件类必须定义一个浏览器对象数组，这些对象是使用服务从远程数据源检索的。页面加载时访问的服务将如下所示：

```ts
basicBrowsers: Browser[];

constructor(private browserService: BrowserService) { }

ngOnInit() {
 this.browserService.getBrowsers().subscribe((browsers: any) =>
 this.basicBrowsers = browsers.slice(0, 12));
}

```

以下屏幕截图显示了数据网格组件在网格布局中的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/a4de2a0d-97d1-40e6-9a32-78a2667f48ec.png)

在上面的快照中，任何两个单元格之间的填充将保持一致。这可以通过该组件的皮肤类进行自定义。

# 基本用法之外 - 高级功能

在上面的快照中，浏览器数据以网格布局显示。但是，您可以观察到没有标题或页脚来总结上下文。标题和页脚方面可使用 `p-header` 和 `p-footer` 标签。

为了提高大型数据集的可用性，DataGrid 提供了分页功能，通过页面导航显示下一块数据。通过启用`paginator`属性并设置`rows`属性来提供此功能。与任何其他数据组件一样，分页功能如`pageLinks`、`rowsPerPageOptions`、`paginatorPosition`和`totalRecords`都可用于自定义。

为了处理大量数据，DataGrid 支持懒加载功能，以便以块的方式访问大量数据。通过启用`lazy`属性来提供此功能。同时，应该在分页操作中使用`onLazyLoad`事件调用懒加载方法。

以下是定义了懒加载事件回调的组件类，其中`event`对象作为参数显示在这里：

```ts
loadData(event: any) {
 let start = event.first; //event.first = First row offset
  let end = start + event.rows; //event.rows = Number of rows per page
  this.browserService.getBrowsers().subscribe((browsers: any) =>
 this.lazyloadingBrowsers = browsers.slice(start,end));
}

```

以下屏幕截图显示了懒加载功能的快照结果示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/2800c1ee-48f2-4565-a497-a3233f9ae432.png)

在上述快照中，它显示了外观（头部和页脚）、自定义分页选项，并在用户需求时延迟加载数据。关于浏览器的附加信息将通过单击每个单元格中可用的搜索图标在对话框中显示。默认情况下，DataGrid 组件在各种屏幕尺寸或设备上都是响应式的布局显示。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/datagrid`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/datagrid)。

# 使用 DataScroller 进行按需数据加载

DataScroller 使用滚动功能按需显示数据。它需要一个项目集合作为其值，要加载的行数，以及`ng-template`模板标签来显示内容，其中每个项目都可以使用隐式变量访问。使用各种浏览器信息的 DataScroller 组件的基本示例将如下所示（请记住，这里使用了流体网格来格式化浏览器记录的内容）：

```ts
<p-dataScroller [value]="basicBrowsers" [rows]="5">
 <ng-template let-browser pTemplate="item">
    <div class="ui-grid ui-grid-responsive ui-fluid" 
      class="content-layout">
      <div class="ui-grid-row">
        <div class="ui-grid-col-3">
          <img src="/assets/data/images/{{browser.code}}.png" 
            width="100" height="80"/>
        </div>
        <div class="ui-grid-col-9">
          <div class="ui-grid ui-grid-responsive ui-fluid">
            <div class="ui-grid-row">
              <div class="ui-grid-col-2">Engine: </div>
              <div class="ui-grid-col-10">{{browser.engine}}</div>
            </div>
            // Other content goes here
          </div>
        </div>
      </div>
    </div>
  </ng-template>
</p-dataScroller>

```

与任何其他数据组件一样，数据列表的组件类应该定义一个浏览器对象的数组。数据是通过对数据源进行远程调用来填充的。以下屏幕截图显示了一个示例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/bdc82140-661a-40fd-a445-5c65b46addb5.png)

如前面的快照所示，数据根据窗口滚动作为目标按需显示。为了使 DataScroller 元素更易读，它支持使用`p-header`和`p-footer`标签的头部和页脚等方面。默认情况下，DataScroller 组件侦听窗口的滚动事件。还有另一种选项，可以使用内联模式将组件的容器定义为事件目标。为此，我们应该将`inline`属性启用为`true`（即`inline="true"`）。

除了基于滚动的数据加载外，还可以使用显式按钮操作加载更多数据。组件应该定义一个引用 Button 组件的`loader`属性。带有加载器按钮的 DataScroller 组件将如下所示：

```ts
<p-dataScroller [value]="advancedBrowsers" [rows]="5" [loader]="loadButton">
  // Content goes here </p-dataScroller>
<p-dataScroller [value]="advancedBrowsers" [rows]="5" [loader]="loadButton">

```

以下屏幕截图显示了一个带有加载器显示的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/4b875e41-f344-47eb-98a0-83eb5f519678.png)

在上面的快照中，一旦用户在左侧点击搜索按钮，就会以对话框格式显示附加的浏览器信息。这可以展示如何在 DataScroller 组件中选择特定记录的能力。

# 惰性加载

为了处理大型数据集，该组件还支持惰性加载功能。它不是加载整个数据，而是在每次滚动操作时加载数据块。需要`lazy`和`onLazyLoad`属性来启用此行为。DataScroller 的惰性加载示例将如下所示：

```ts
<p-dataScroller [value]="lazyloadingBrowsers" [rows]="5"
 [lazy]="true" (onLazyLoad)="loadData($event)">
  //Content goes here </p-dataScroller>

```

组件类定义了惰性加载事件回调，以按块检索数据，如下所示：

```ts
loadData(event: any) {
 let start = event.first; //event.first = First row offset
  let end = start + event.rows; //event.rows = Number of rows per page
  this.browserService.getBrowsers().subscribe((browsers: any) =>
 this.lazyloadingBrowsers = browsers.slice(start, end));
}

```

在上面的代码片段中，您可以观察到`event`对象的`first`和`rows`属性对于检索下一批记录非常有用。根据`rows`属性，它尝试在每次获取时获取下一个`rows`数量的记录。

API 方法`reset`用于重置 DataScroller 组件的内容或数据。也就是说，组件将重置为其默认状态。

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/datascroller`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/datascroller)。

# 使用树形结构可视化数据

Tree 组件用于以图形格式显示数据的分层表示。它提供了`TreeNode`对象数组作为其值。`TreeNode` API 提供了许多属性来创建树节点对象。树结构基本上有三个主要组件，如下所示：

+   树元素称为**节点**

+   连接元素的线称为分支

+   没有子节点的节点称为叶节点或叶子节点

具有节点的 Tree 组件的基本示例将如下所示（节点将表示旅游景点）：

```ts
<p-tree [value]="basicTree"></p-tree>

```

Tree 组件的数据应以嵌套的父子层次结构提供。每个树节点都使用一组属性创建，例如`label`、`data`、`expandIcon`、`collapsedIcon`、`children`等等。`TreeNode`属性的完整列表如下所示：

| **名称** | **类型** | **默认** | **描述** |
| --- | --- | --- | --- |
| `label` | `string` | `null` | 节点的标签。 |
| `data` | `any` | `null` | 节点表示的数据。 |
| `icon` | `string` | `null` | 节点旁边显示的图标。 |
| `expandedIcon` | `string` | `null` | 展开状态下使用的图标。 |
| `collapsedIcon` | `string` | `null` | 折叠状态下使用的图标。 |
| `children` | `TreeNode[]` | `null` | 作为子节点的树节点数组。 |
| `leaf` | `boolean` | `null` | 指定节点是否有子节点。用于延迟加载。 |
| `style` | `string` | `null` | 节点的内联样式。 |
| `styleClass` | `string` | `null` | 节点的样式类。 |
| `expanded` | `boolean` | `null` | 节点是否处于展开或折叠状态。 |
| `type` | `string` | `null` | 与`ng-template`类型匹配的节点类型。 |
| `parent` | `TreeNode` | `null` | 节点的父节点。 |
| `styleClass` | `string` | `null` | 节点元素的样式类名称。 |
| `draggable` | `boolean` | `null` | 是否禁用特定节点的拖动，即使启用了`draggableNodes`。 |
| `droppable` | `boolean` | `null` | 是否禁用特定节点的放置，即使启用了`droppableNodes`。 |
| `selectable` | `boolean` | `null` | 用于禁用特定节点的选择。 |

`TreeNode`的所有属性都是可选的。

旅游景点示例的树节点结构如下：

```ts
"data":
[
  {
    "label": "Asia",
    "data": "Documents Folder",
    "expandedIcon": "fa-folder-open",
    "collapsedIcon": "fa-folder",
    "children": [{
      "label": "India",
      "data": "Work Folder",
      "expandedIcon": "fa-folder-open",
      "collapsedIcon": "fa-folder",
      "children": [{
 "label": "Goa", "icon": "fa-file-word-o",
 "data": "Beaches& Old Goa colonial architecture"},
          {"label": "Mumbai", "icon": "fa-file-word-o", "data": 
 "Shopping,Bollywood"},
          {"label": "Hyderabad", "icon": "fa-file-word-o", 
 "data": "Golconda Fort"}
      ]
    },
      {
        "label": "Singapore",
        "data": "Home Folder",
        "expandedIcon": "fa-folder-open",
        "collapsedIcon": "fa-folder",
        "children": [{
 "label": "Woodlands", "icon": "fa-file-word-o", 
 "data": "Parks,Sea food"}]
      },
    ]
  }
...
]

```

在实时应用程序中，位于远程数据源中的数据是通过服务检索的。以下服务将被注入到组件类中：

```ts
@Injectable()
export class TreeNodeService {

  constructor(private http: Http) { }

  getTouristPlaces(): Observable<any[]> {
    return this.http.get('/assets/data/cities.json')
      .map(response => response.json().data);
  }
}

```

组件类在页面加载时使用服务调用加载数据，如下所示：

```ts
basicTree: TreeNode[];

constructor(private nodeService: TreeNodeService) { }

ngOnInit() {
 this.nodeService.getTouristPlaces().subscribe(
    (places: any) => this.basicTree = places);
}

```

以下截图显示了分层树组件表示的快照结果，以示例为例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/4a5801dc-cbf4-496a-8468-0598b47e5799.png)

在前面的用例中，我们展开了印度和德国的国家树节点，以查看它们表示为旅游地点的子节点。

# 选择功能 - 单选、多选和复选框

树组件支持三种选择方式，包括单选、多选和复选框。单选是通过启用`selectionMode`属性和`selection`属性来实现的，后者保存了一个选定的树节点。

具有单选功能的树组件，以选择一个喜爱的旅游地点，将如下所示：

```ts
<p-tree [value]="singleSelectionTree" selectionMode="single" [(selection)]="selectedPlace"  (onNodeSelect)="nodeSelect($event)" (onNodeUnselect)="nodeUnselect($event)"></p-tree>
<div>Selected Node: {{selectedPlace ? selectedPlace.label : 'none'}}</div>

```

以下截图显示了树组件的快照结果，以单选为例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/c6ec7842-e873-4887-bb28-06bb93e0cc42.png)

在这里，通过将`selectionMode`设置为`multiple`（`selectionMode="multiple"`）来启用多重选择。在这种情况下，`selection`属性保存一个作为选定节点的对象数组。多重选择也可以通过复选框选择来实现，只需将`selectionMode="checkbox"`。

具有多个复选框选择功能的树组件，以选择多个旅游地点，将如下所示：

```ts
<p-tree [value]="checkboxSelectionTree" selectionMode="checkbox"
 [(selection)]="selectMultiplePlaces"></p-tree>
<div>Selected Nodes: <span *ngFor="let place of selectMultiplePlaces">{{place.label}} </span></div>

```

以下截图显示了树组件的快照结果，以复选框选择为例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/9b66a06d-0743-489e-be3d-61cdd6418065.png)

选择功能支持两个事件回调，如`onRowSelect`和`onRowUnselect`，提供了选定和取消选定的树节点。有关更多详细信息，请参阅事件部分。

选择节点的传播（向上和向下方向）通过`propagateSelectionUp`和`propagateSelectionDown`属性来控制，默认情况下是启用的。

# 超出基本用法 - 高级功能

树组件还支持许多高级功能：

+   自定义内容可以使用模板标签`ng-template`来显示。

+   可以使用`onNodeExpand`事件回调来实现延迟加载功能。

+   为每个树节点应用上下文菜单，使用本地模板引用变量。

+   使用`layout="horizontal"`表达式显示树组件的水平布局。

+   通过启用`draggableNodes`和`droppableNodes`属性，可以在源树组件和目标树组件之间实现拖放功能。`dragdropScope`属性用于将拖放支持限制在特定区域。

可以通过将 API 方法外部化来以编程方式实现行展开或折叠行为。例如，下面显示了一个带有外部按钮的树，这些按钮用于使用事件回调以编程方式展开或折叠树节点。

```ts
<p-tree #expandingTree [value]="programmaticTree"></p-tree>
<div>
 <button pButton type="text" label="Expand all" (click)="expandAll()">
   </button>
  <button pButton type="text" label="Collapse all" (click)="collapseAll()"></button>
</div>

```

在此处显示了使用事件回调函数定义的组件类，以递归方式切换树节点的示例：

```ts
expandAll() {
 this.programmaticTree.forEach( (node: any) => {
    this.expandRecursive(node, true);
  } );
}

collapseAll() {
 this.programmaticTree.forEach((node: any) => {
    this.expandRecursive(node, false);
  } );
}

expandRecursive(node: TreeNode, isExpand: boolean) {
  node.expanded = isExpand;
  if (node.children) {
    node.children.forEach( childNode => {
      this.expandRecursive(childNode, isExpand);
    } );
  }
}

```

该组件还支持四个事件回调，如`onNodeExpand`、`onNodeCollapse`、`onNodeDrop`和`onNodeContextMenuSelect`。以下事件表提供了事件、参数及其描述的完整详细信息：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `onNodeSelect` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 选定的节点实例

| 当选择节点时调用的回调函数。 |
| --- |
| `onNodeUnselect` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 取消选择的节点实例

| 当取消选择节点时调用的回调函数。 |
| --- |
| `onNodeExpand` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 展开的节点实例

| 当节点展开时调用的回调函数。 |
| --- |
| `onNodeCollapse` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 折叠的节点实例

| 当节点折叠时调用的回调函数。 |
| --- |
| `onNodeContextMenuSelect` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 选定的节点实例

| 当通过右键单击选择节点时调用的回调函数。 |
| --- |
| `onNodeDrop` |

+   `event.originalEvent`: 浏览器事件

+   `event.dragNode`: 被拖动的节点实例

+   `event.dropNode`: 被拖放的节点实例

| 当通过右键单击选择节点时调用的回调函数。 |
| --- |

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/tree`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/tree)。

# 使用 TreeTable 可视化数据

TreeTable 用于以表格格式显示分层数据。它需要一个`TreeNode`对象数组作为其值，并提供了许多可选属性的`TreeNode`API。TreeTable 将列组件定义为具有`header`、`footer`、`field`和`style`属性的子元素，类似于 DataTable 组件。

将旅游地点树节点作为信息的 TreeTable 组件的基本示例将如下编写：

```ts
<p-treeTable [value]="basicTreeTable">
 <p-header>Basic</p-header>
  <p-column field="name" header="Name"></p-column>
  <p-column field="days" header="Days"></p-column>
  <p-column field="type" header="Type"></p-column>
</p-treeTable>

```

该组件是通过以分层方式排列`TreeNode`对象来创建的。`TreeNode`对象包括许多属性，如下所列：

| **名称** | **类型** | **默认** | **描述** |
| --- | --- | --- | --- |
| `label` | `string` | `null` | 节点的标签。 |
| `data` | `any` | `null` | 由节点表示的数据。 |
| `icon` | `string` | `null` | 要显示在内容旁边的节点图标。TreeTable 不使用。 |
| `expandedIcon` | `string` | `null` | 用于展开状态的图标。TreeTable 不使用。 |
| `collapsedIcon` | `string` | `null` | 用于折叠状态的图标。TreeTable 不使用。 |
| `children` | `TreeNode[]` | `null` | 作为子节点的树节点数组。 |
| `leaf` | `boolean` | `null` | 指定节点是否有子节点。用于延迟加载。 |
| `style` | `string` | `null` | 节点的内联样式。 |
| `styleClass` | `string` | `null` | 节点的样式类。 |

旅游景点示例的`TreeNode`结构如下：

```ts
{
  "data": [
    {
      "data": {
        "name": "Asia",
        "days": "15",
        "type": "Continent"
  },
      "children": [
        {
          "data": {
            "name": "India",
            "days": "6",
            "type": "Country"
  },
          "children": [
            {
              "data": {
                "name": "Goa",
                "days": "2",
                "type": "City"
  }...
            }]
          }]
     } }
  ...
}

```

注入的服务和组件类中的相同服务调用表示几乎与前一节中解释的 Tree 组件相似。以下屏幕截图显示了以层次结构的旅游信息为例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/7698f874-f041-4990-ab56-8b7819a3b249.png)

该组件还支持动态列，其中每列都是通过循环`ngFor`指令创建的。

# 选择功能 - 单选、多选和复选框

TreeTable 组件支持三种选择功能，包括单选、多选和复选框。单选通过在树表上启用`selectionMode`属性和`selection`属性来实现，该属性保存了所选的树表节点。

具有单选功能的 TreeTable 组件，用于选择喜爱的旅游景点，将如下编写：

```ts
<p-treeTable [value]="singleSelectionTreeTable" selectionMode="single"   
  [(selection)]="selectedTouristPlace   
  (onNodeSelect)="nodeSelect($event)"   
  (onNodeUnselect)="nodeUnselect($event)" 
  (onRowDblclick)="onRowDblclick($event)" >
    <p-header>Singe Selection</p-header>
    <p-column field="name" header="Name"></p-column>
    <p-column field="days" header="Days"></p-column>
    <p-column field="type" header="Type"></p-column>
</p-treeTable>

```

以下屏幕截图显示了以单选为例的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/240a8ee6-f425-4e70-b0a3-ced6e5f16c32.png)

而多选功能是通过将`selectionMode`设置为多选（`selectionMode="multiple"`）来启用的。在这种情况下，`selection`属性保存了所选节点的对象数组。多选也可以通过复选框选择来实现。这可以通过设置`selectionMode="checkbox"`来实现。

具有多复选框选择功能的 TreeTable 组件，用于选择多个旅游景点，将如下所示：

```ts
<p-treeTable [value]="checkboxSelectionTreeTable" selectionMode="checkbox"
 [(selection)]="selectedMultiTouristPlaces">
  <p-header>Checkbox Selection</p-header>
  <p-column field="name" header="Name"></p-column>
  <p-column field="days" header="Days"></p-column>
  <p-column field="type" header="Type"></p-column>
</p-treeTable>

```

以下屏幕截图显示了复选框选择的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/a682056c-6579-4b50-94ce-8a0fb0816f0d.png)

选择功能支持两个事件回调，例如`onNodeSelect`和`onNodeUnselect`，它提供了选定和取消选定的树节点。有关更多详细信息，请参阅事件部分。

# 基本用法之外 - 高级功能

TreeTable 组件还支持各种高级功能，例如使用`onNodeExpand`回调进行延迟加载，使用`ng-template`模板标签进行自定义可编辑内容，以及上下文菜单实现，这与 DataTable 组件类似。它还支持使用`p-header`和`p-footer`标签为头部和底部添加外观。

TreeTable 的内容显示是使用`ng-template`进行自定义的。默认情况下，树节点的标签显示在树节点内。要自定义内容，请在获取列的列中定义`ng-template`作为隐式变量（`let-col`），并将`rowData`定义为节点实例（`let-node="rowData"`）。同样，我们可以自定义此组件的头部和底部。

让我们以可编辑的树节点为例，通过在每个模板中放置一个输入框来实现：

```ts
<p-treeTable [value]="templateTreeTable">
 <p-header>Editable Cells with Templating</p-header>
  <p-column field="name" header="Name">
    <ng-template let-node="rowData" pTemplate="body">
      <input type="text" [(ngModel)]="node.data.name" 
        class="edit-input">
    </ng-template>
  </p-column>
  <p-column field="days" header="Days">
    <ng-template let-node="rowData" pTemplate="body">
      <input type="text" [(ngModel)]="node.data.days" 
        class="edit-input">
    </ng-template>
  </p-column>
  <p-column field="type" header="Type">
    <ng-template let-node="rowData" pTemplate="body">
      <input type="text" [(ngModel)]="node.data.type" 
        class="edit-input">
    </ng-template>
  </p-column>
</p-treeTable>

```

以下屏幕截图显示了具有可编辑模板的快照结果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/15893d60-87e6-4251-983a-bf611a343771.png)

在上述快照中，我们可以编辑所有树节点字段。例如，我们将旅游套餐的天数从 9 天更新为 20 天。TreeTable 还支持扩展/折叠节点的事件回调，例如`onNodeExpand`、`onNodeCollapse`，以及上下文菜单的`onContextmenuSelect`事件。有关更多详细信息，请参阅事件部分。

PrimeNG 4.1 引入了`toggleColumnIndex`属性，用于定义包含`toggler`元素的列的索引。默认情况下，`toggleColumnIndex`的值为`0`（如果未定义`togglerColumnIndex`，TreeTable 始终在第一列显示`toggler`）。

以下事件表提供了事件、参数及其描述的完整详细信息：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `onNodeSelect` |

+   `event.originalEvent`：浏览器事件

+   `event.node`：选定的节点实例

| 调用节点被选中时的回调。 |
| --- |
| `onNodeUnselect` |

+   `event.originalEvent`：浏览器事件

+   `event.node`：取消选定的节点实例

| 当节点取消选定时要调用的回调函数。 |
| --- |
| `onNodeExpand` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 展开的节点实例

| 当节点展开时要调用的回调函数。 |
| --- |
| `onNodeCollapse` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 折叠的节点实例

| 当节点折叠时要调用的回调函数。 |
| --- |
| `onContextMenuSelect` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 选定的节点实例

| 当右键选择节点时要调用的回调函数。 |
| --- |
| `onRowDblclick` |

+   `event.originalEvent`: 浏览器事件

+   `event.node`: 选定的节点实例

| 双击行时要调用的回调函数。 |
| --- |

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/treetable`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/treetable).

# 使用日程安排管理事件

日程安排是基于`FullCalendar` jQuery 插件的全尺寸拖放事件日历。日程安排的事件应该形成一个数组，并使用`events`属性进行定义。日程安排组件依赖于`FullCalendar`库，因此它需要您页面中列出的以下资源： 

+   日程安排组件嵌入到网页中，使用样式表和 JavaScript 文件。因此，我们需要在 HTML 页面的`head`部分包含`FullCalendar`库的样式表（`.css`）和 JavaScript（`.js`）文件。

+   将`jQuery`和`Moment.js`库添加为完整日历的强制库。这两个库必须在加载`FullCalendar`库的 JavaScript 文件之前加载。

因此，我们在根`index.html`文件中包含了`FullCalendar`和其他依赖资源，如下所示：

```ts
<!-- Schedule CSS resources--> <link rel="stylesheet" type="text/css" href="https://cdnjs.cloudflare.com/ajax/libs/fullcalendar/3.1.0/
fullcalendar.min.css">
<!-- Schedule Javascript resources--> <script src="https://code.jquery.com/jquery-2.2.4.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/moment.js/2.13.0/moment.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/fullcalendar/3.1.0/
fullcalendar.min.js"></script>

```

为整个月份定义的日程安排组件的基本示例将如下所示编写：

```ts
<p-schedule [events]="events" [height]="700" 
  [styleClass]="'schedule-width'">
</p-schedule> 

```

基本上，所有类型的事件都有标题、持续时间（开始和结束日期）、日期类型（全天/部分天）等属性。因此，事件类将如下所示定义：

```ts
export class MyEvent {
 id: number;
  title: string;
  start: string;
  end: string;
  allDay: boolean = true;
}

```

日程安排事件的数据应该按照上述格式作为原型来定义。但在实时情况下，数据是通过远程服务调用获取的，并且在事件发生变化时立即更新到日程安排界面。用于从数据源检索数据的事件服务（在本例中，它使用 HTTP 模块和可观察对象从 JSON 事件文件中检索数据）定义如下：

```ts
@Injectable()
export class EventService {

  constructor(private http: Http) { }

  getEvents(): Observable<any> {
    return this.http.get('/assets/data/scheduleevents.json')
      .map(response => response.json().data);
  }
}

```

注入的服务在网页初始加载时获取数据。如下所示，组件类必须定义可观察对象的订阅：

```ts
events: any[];

constructor(private eventService: EventService) { }

ngOnInit() {
 this.eventService.getEvents().subscribe((events: any) => 
  {this.events = events;});
}

```

以下截图显示了嵌入式日程安排组件显示的快照结果作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/35e1cead-b355-417d-8ea0-066647e169bf.png)

根据前面的快照，标题显示为日期（月份和年份）、今天标签和月份导航控件。主体或内容区域包含了每个月的每一天以及特定日期上的事件，以蓝色覆盖区域显示。

# 标题定制

在前面的快照中，我们观察到了日程安排的内容区域以及默认标题文本和控件。日程安排元素的默认标题配置对象将被编写如下：

```ts
{
  left: 'title', 
  center: '',
  right: 'today prev,next' }

```

通过`header`属性修改了上述默认标题显示，该属性保存了标题配置对象，如下所示：

```ts
<p-schedule [events]="events" [header]="headerConfig" [height]="700"
 [styleClass]="'schedule-width'"></p-schedule>

```

让我们定义左侧的导航控件，中间的标题，以及右侧的视图类型（月、周、日），以将其表示为配置对象：

```ts
this.headerConfig = {
 left: 'prev,next today',
  center: 'title',
  right: 'month,agendaWeek,agendaDay' };

```

以下截图显示了自定义日程安排标题的快照结果作为示例：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng-ui-dev-primeng/img/5ef78c40-0dff-4d5d-9910-509454446dd2.png)

# 基本用法之外 - 高级功能

除了上述常规功能之外，日程安排组件还通过`onViewRender`事件回调支持懒加载，当新的日期范围被渲染或视图类型发生变化时将被调用。带有懒加载事件回调调用的日程安排组件将被编写如下：

```ts
<p-schedule [events]="events" (onViewRender)="loadEvents($event)" [height]="700" [styleClass]="'schedule-width'"></p-schedule>

```

组件类定义了一个懒加载回调，以便按需检索事件数据，并且将被编写如下：

```ts
loadEvents(event: any) {
 let start = event.view.start;
  let end = event.view.end;
  // In real time the service call filtered based on  
  //start and end dates
  this.eventService.getEvents().subscribe((events: any) =>
  {this.events = events;});
}

```

该组件还通过`locale`属性支持本地化。例如，通过设置`locale="de"`来表示德语标签。本地化标签应该在类似日历的组件中定义。

当事件数据发生任何变化时，UI 会自动更新。这对于在日程安排上实现 CRUD 操作非常有帮助。

# 事件和方法

日程安排组件提供了许多事件回调，包括点击、鼠标、调整大小和拖放用户操作，如下所列：

| **名称** | **描述** |
| --- | --- |
| `onDayClick` | 当用户点击某一天时触发 |
| `onEventClick` | 当用户点击事件时触发 |
| `onEventMouseover` | 当用户将鼠标悬停在事件上时触发 |
| `onEventMouseout` | 当用户鼠标移出事件时触发 |
| `onEventDragStart` | 当事件拖动开始时触发 |
| `onEventDragStop` | 当事件拖动停止时触发 |
| `onEventDrop` | 当拖动停止且事件已移动到*不同*的日期/时间时触发 |
| `onEventResizeStart` | 当事件调整大小开始时触发 |
| `onEventResizeStop` | 当事件调整大小停止时触发 |
| `onEventResize` | 当调整大小停止且事件持续时间发生变化时触发 |
| `onViewRender` | 当新的日期范围被渲染或视图类型切换时触发 |
| `onViewDestroy` | 当渲染的日期范围需要被销毁时触发 |
| `onDrop` | 当可拖动对象被放置到日程表上时触发 |

此外，它提供了许多 API 方法来处理不同的用例，如下所示：

| **名称** | **参数** | **描述** |
| --- | --- | --- |
| `prev()` | - | 将日程表向后移动一步（可以是一个月、一周或一天） |
| `next()` | - | 将日程表向前移动一步（可以是一个月、一周或一天） |
| `prevYear()` | - | 将日程表向后移动一年 |
| `nextYear()` | - | 将日程表向前移动一年 |
| `today()` | - | 将日程表移动到当前日期 |
| `gotoDate(date)` | `date`: 要导航的日期 | 将日程表移动到任意日期 |
| `incrementDate(duration)` | `duration`: 要添加到当前日期的持续时间 | 将日程表向前/向后移动任意时间量 |
| `getDate()` | - | 返回日历当前日期的时刻 |
| `changeView(viewName)` | `viewName`: 要切换到的有效视图字符串 | 立即切换到不同的视图 |

上述 API 方法将完全控制日程表。这些方法调用在许多用例中非常有帮助。例如，通过`.next()`方法访问日程表的下一个视图（月、周或日）如下所示：

```ts
<p-schedule [events]="events" #schedule></p-schedule>
<button type="button" pButton (click)="next(schedule)"></p-button>

```

组件类定义了点击事件回调，将调用下一个日期、周或月，如下所示：

```ts
next(schedule) {
  schedule.next();
}

```

完整的演示应用程序及说明可在 GitHub 上找到

[`github.com/ova2/angular-development-with-primeng/tree/master/chapter5/schedule`](https://github.com/ova2/angular-development-with-primeng/tree/master/chapter5/schedule).

# 摘要

此时，您将对所有数据迭代组件及其最常用的功能有一个概览，比如选择行、排序、分页、过滤数据等等。接下来，我们能够以表格、网格和列表格式显示（分层）数据。此外，您将了解如何在 DataTable 中实现调整大小、重新排序、切换和分组列，自定义单元格内容，并使用 Tree 和 TreeTable 组件可视化数据。在下一章中，您将看到一些令人惊叹的覆盖层，比如对话框、确认对话框、覆盖面板和通知组件，比如 growl 和消息，以及各种功能。
