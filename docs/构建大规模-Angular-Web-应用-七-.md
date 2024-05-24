# 构建大规模 Angular Web 应用（七）

> 原文：[`zh.annas-archive.org/md5/DA167AD27703E0822348016B6A3A0D43`](https://zh.annas-archive.org/md5/DA167AD27703E0822348016B6A3A0D43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十五章：Angular 应用程序设计和技巧

在本章中，我们将完成 LemonMart 的实现。作为先路由的方法的一部分，我将展示如何创建可重用的可路由组件，同时支持数据绑定——使用辅助路由布置组件的能力，使用 resolve guards 减少样板代码，并利用类、接口、枚举、验证器和管道来最大程度地重用代码。此外，我们将创建多步骤表单，并实现带分页的数据表格，并探索响应式设计。在本书中，我们将触及 Angular 和 Angular Material 提供的大部分主要功能。

在这一章，训练车轮已经卸下。我将提供一般指导来帮助您开始实施；然而，您将需要自己尝试并完成实施。如果需要帮助，您可以参考本书附带的完整源代码，或在[Github.com/duluca/lemon-mart](https://github.com/duluca/lemon-mart)上查看最新的示例。

在本章中，您将学习以下主题：

+   面向对象类设计

+   可复用的可路由组件

+   缓存服务响应

+   HTTP POST 请求

+   多步骤响应表单

+   解析守卫

+   使用辅助路由进行主/细节视图

+   带分页的数据表格

# 用户类和面向对象编程

到目前为止，我们只是使用接口来表示数据，并且当在各个组件和服务之间传递数据时，我们仍然希望继续使用接口。然而，我们需要创建一个默认对象来初始化`BehaviorSubject`。在**面向对象编程**（**OOP**）中，让`User`对象拥有这个功能而不是一个服务，这样做非常有意义。所以，让我们实现一个`User`类来实现这个目标。

在`user/user`文件夹内，定义一个`IUser`接口和`UserModule`中提供的`User`类：

```ts
src/app/user/user/user.ts
import { Role } from '../../auth/role.enum'

export interface IUser {
  id: string
  email: string
  name: {
    first: string
    middle: string
    last: string
  }
  picture: string
  role: Role
  userStatus: boolean
  dateOfBirth: Date
  address: {
    line1: string
    line2: string
    city: string
    state: string
    zip: string
  }
  phones: IPhone[]
}

export interface IPhone {
  type: string
  number: string
  id: number
}

export class User implements IUser {
  constructor(
    public id = '',
    public email = '',
    public name = { first: '', middle: '', last: '' },
    public picture = '',
    public role = Role.None,
    public dateOfBirth = null,
    public userStatus = false,
    public address = {
      line1: '',
      line2: '',
      city: '',
      state: '',
      zip: '',
    },
    public phones = []
  ) {}

  static BuildUser(user: IUser) {
    return new User(
      user.id,
      user.email,
      user.name,
      user.picture,
      user.role,
      user.dateOfBirth,
      user.userStatus,
      user.address,
      user.phones
    )
  }
}
```

请注意，在构造函数中使用默认值定义所有属性为`public`属性，我们一举两得；否则，我们将需要分别定义属性并初始化它们。这样，我们就实现了一个简洁的实现。

您还可以实现计算属性以在模板中使用，比如可以方便地显示用户的`fullName`：

```ts
src/app/user/user/user.ts  
get fullName() {
  return `${this.name.first} ${this.name.middle} ${this.name.last}`
}
```

使用`static BuildUser`函数，您可以快速用从服务器接收的数据填充对象。您还可以实现`toJSON()`函数来自定义对象在发送数据到服务器之前的序列化行为。

# 重用组件

我们需要一个能够显示给定用户信息的组件。这些信息最自然的呈现位置是当用户导航到`/user/profile`时。您可以看到`User`概要文件的模拟：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/eac254e3-0556-42ff-8841-6b44a5020fff.png)

用户概要模拟

用户信息也在应用程序的其他地方进行了模拟显示，在`/manager/users`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b9b855d5-243b-4cc0-b625-511856a1f3b8.png)

用户管理模拟

为了最大限度地提高代码重用率，我们需要确保设计一个能在两种情境下使用的`User`组件。

例如，让我们完成两个与用户资料相关的屏幕的实现。

# 带有多步鉴权功能的响应式表单的用户资料

现在，让我们实现一个多步输入表单来捕获用户资料信息。我们还将使用媒体查询使这个多步表单对移动设备具有响应性。

1.  让我们首先添加一些辅助数据，这些数据将帮助我们显示具有选项的输入表单：

```ts
src/app/user/profile/data.ts
export interface IUSState {
  code: string
  name: string
}

export function USStateFilter(value: string): IUSState[] {
  return USStates.filter(state => {
    return (
      (state.code.length === 2 && state.code.toLowerCase() === value.toLowerCase()) ||
      state.name.toLowerCase().indexOf(value.toLowerCase()) === 0
    )
  })
}

export enum PhoneType {
  Mobile,
  Home,
  Work,
}

const USStates = [
  { code: 'AK', name: 'Alaska' },
  { code: 'AL', name: 'Alabama' },
  { code: 'AR', name: 'Arkansas' },
  { code: 'AS', name: 'American Samoa' },
  { code: 'AZ', name: 'Arizona' },
  { code: 'CA', name: 'California' },
  { code: 'CO', name: 'Colorado' },
  { code: 'CT', name: 'Connecticut' },
  { code: 'DC', name: 'District of Columbia' },
  { code: 'DE', name: 'Delaware' },
  { code: 'FL', name: 'Florida' },
  { code: 'GA', name: 'Georgia' },
  { code: 'GU', name: 'Guam' },
  { code: 'HI', name: 'Hawaii' },
  { code: 'IA', name: 'Iowa' },
  { code: 'ID', name: 'Idaho' },
  { code: 'IL', name: 'Illinois' },
  { code: 'IN', name: 'Indiana' },
  { code: 'KS', name: 'Kansas' },
  { code: 'KY', name: 'Kentucky' },
  { code: 'LA', name: 'Louisiana' },
  { code: 'MA', name: 'Massachusetts' },
  { code: 'MD', name: 'Maryland' },
  { code: 'ME', name: 'Maine' },
  { code: 'MI', name: 'Michigan' },
  { code: 'MN', name: 'Minnesota' },
  { code: 'MO', name: 'Missouri' },
  { code: 'MS', name: 'Mississippi' },
  { code: 'MT', name: 'Montana' },
  { code: 'NC', name: 'North Carolina' },
  { code: 'ND', name: 'North Dakota' },
  { code: 'NE', name: 'Nebraska' },
  { code: 'NH', name: 'New Hampshire' },
  { code: 'NJ', name: 'New Jersey' },
  { code: 'NM', name: 'New Mexico' },
  { code: 'NV', name: 'Nevada' },
  { code: 'NY', name: 'New York' },
  { code: 'OH', name: 'Ohio' },
  { code: 'OK', name: 'Oklahoma' },
  { code: 'OR', name: 'Oregon' },
  { code: 'PA', name: 'Pennsylvania' },
  { code: 'PR', name: 'Puerto Rico' },
  { code: 'RI', name: 'Rhode Island' },
  { code: 'SC', name: 'South Carolina' },
  { code: 'SD', name: 'South Dakota' },
  { code: 'TN', name: 'Tennessee' },
  { code: 'TX', name: 'Texas' },
  { code: 'UT', name: 'Utah' },
  { code: 'VA', name: 'Virginia' },
  { code: 'VI', name: 'Virgin Islands' },
  { code: 'VT', name: 'Vermont' },
  { code: 'WA', name: 'Washington' },
  { code: 'WI', name: 'Wisconsin' },
  { code: 'WV', name: 'West Virginia' },
  { code: 'WY', name: 'Wyoming' },
]

```

1.  安装一个帮助库来以编程方式访问 TypeScript 枚举值

```ts
$ npm i ts-enum-util
```

1.  在`common/validations.ts`中添加新的验证规则

```ts
src/app/common/validations.ts
...

export const OptionalTextValidation = [Validators.minLength(2), Validators.maxLength(50)]
export const RequiredTextValidation = OptionalTextValidation.concat([Validators.required])
export const OneCharValidation = [Validators.minLength(1), Validators.maxLength(1)]
export const BirthDateValidation = [
  Validators.required,
  Validators.min(new Date().getFullYear() - 100),
  Validators.max(new Date().getFullYear()),
]
export const USAZipCodeValidation = [
  Validators.required,
  Validators.pattern(/^\d{5}(?:[-\s]\d{4})?$/),
]
export const USAPhoneNumberValidation = [
  Validators.required,
  Validators.pattern(/^\D?(\d{3})\D?\D?(\d{3})\D?(\d{4})$/),
]
```

1.  现在按照以下方式实现`profile.component.ts`：

```ts
src/app/user/profile/profile.component.ts
import { Role as UserRole } from '../../auth/role.enum'
import { $enum } from 'ts-enum-util'
...
@Component({
  selector: 'app-profile',
  templateUrl: './profile.component.html',
  styleUrls: ['./profile.component.css'],
})
export class ProfileComponent implements OnInit {
  Role = UserRole
  PhoneTypes = $enum(PhoneType).getKeys()
  userForm: FormGroup
  states: Observable<IUSState[]>
  userError = ''
  currentUserRole = this.Role.None

  constructor(
    private formBuilder: FormBuilder,
    private router: Router,
    private userService: UserService,
    private authService: AuthService
  ) {}

  ngOnInit() {
    this.authService.authStatus.subscribe(
      authStatus => (this.currentUserRole = authStatus.userRole)
    )

    this.userService.getCurrentUser().subscribe(user => {
      this.buildUserForm(user)
    })

    this.buildUserForm()
  }
  ...
}
```

加载时，我们从`userService`请求当前用户，但这可能需要一段时间，因此我们必须首先用`this.buildUserForm()`构建一个空表单。在这个函数中，您还可以实现一个 resolve 守卫，如后面将要讨论的，根据路由提供的`userId`加载用户，并将数据传递到`buildUserForm(routeUser)`，然后跳过加载`currentUser`以增加此组件的可重用性。

# 表单组

我们的表单有许多输入字段，因此我们将使用`FormGroup`，由`this.formBuilder.group`创建以容纳我们的各种`FormControl`对象。此外，子`FormGroup`对象将允许我们保持数据结构的正确形状。

开始构建`buildUserForm`函数，如下所示：

```ts
src/app/user/profile/profile.component.ts
...
  buildUserForm(user?: IUser) {
    this.userForm = this.formBuilder.group({
      email: [
        {
          value: (user && user.email) || '',
          disabled: this.currentUserRole !== this.Role.Manager,
        },
        EmailValidation,
      ],
      name: this.formBuilder.group({
        first: [(user && user.name.first) || '', RequiredTextValidation],
        middle: [(user && user.name.middle) || '', OneCharValidation],
        last: [(user && user.name.last) || '', RequiredTextValidation],
      }),
      role: [
        {
          value: (user && user.role) || '',
          disabled: this.currentUserRole !== this.Role.Manager,
        },
        [Validators.required],
      ],
      dateOfBirth: [(user && user.dateOfBirth) || '', BirthDateValidation],
      address: this.formBuilder.group({
        line1: [
          (user && user.address && user.address.line1) || '',
          RequiredTextValidation,
        ],
        line2: [
          (user && user.address && user.address.line2) || '',
          OptionalTextValidation,
        ],
        city: [(user && user.address && user.address.city) || '', RequiredTextValidation],
        state: [
          (user && user.address && user.address.state) || '',
          RequiredTextValidation,
        ],
        zip: [(user && user.address && user.address.zip) || '', USAZipCodeValidation],
      }),
      ...
    })
    ...
  }
...
```

`buildUserForm`可选择接受一个`IUser`以预填表单，否则所有字段都设置为默认值。`userForm`本身是顶层`FormGroup`。其中添加了各种`FormControls`，例如`email`，根据需要连接到它们的验证器。注意`name`和`address`是它们自己的`FormGroup`对象。这种父子关系确保表单数据的正确结构，在序列化为 JSON 时，这适配了`IUser`的结构，以保证我们应用程序和服务端代码的运用。

您将独立完成`userForm`的实现，按照章节提供的示例代码，并且在接下来的几个章节中我将逐步解释代码的某些关键功能。

# 分步表单和响应式布局

Angular Material Stepper 附带了`MatStepperModule`。该步骤条允许将表单输入分解为多个步骤，以便用户不会被一次性处理数十个输入字段而感到不知所措。用户仍然可以跟踪他们在过程中的位置，作为开发人员的副作用，我们将我们的`<form>`实现分解并逐步强制执行验证规则，或者创建可以跳过或必填的可选工作流程。与所有 Material 用户控件一样，步骤条已经设计成具有响应式 UX。在接下来的几节中，我们将实现包括不同表单输入技术的三个步骤：

1.  账户信息

    +   输入验证

    +   使用媒体查询进行响应式布局

    +   计算属性

    +   日期选择器

1.  联系信息

    +   自动完成支持

    +   动态表单数组

1.  评论

    +   只读视图

    +   数据保存和清除

让我们为用户模块准备一些新的 Material 模块：

1.  创建一个`user-material.module`，其中包含以下 Material 模块：

```ts
MatAutocompleteModule,
MatDatepickerModule,
MatDividerModule,
MatLineModule,
MatNativeDateModule,
MatRadioModule,
MatSelectModule,
MatStepperModule,
```

1.  确保`user.module`正确导入：

    1.  新的`user-material.module`

    1.  基线`app-material.module`

    1.  必须引入`FormsModule`，`ReactiveFormsModule`和`FlexLayoutModule`

当我们开始添加子 Material 模块时，将根`material.module.ts`文件重命名为`app-material.modules.ts`是合理的，与`app-routing.module.ts`的命名方式一致。今后，我将使用后一种约定。

1.  现在，开始实现“账户信息”步骤的第一行：

```ts
src/app/user/profile/profile.component.html <mat-toolbar color="accent"> <h5>User Profile</h5>
</mat-toolbar>

<mat-horizontal-stepper #stepper="matHorizontalStepper">
  <mat-step [stepControl]="userForm">
    <form [formGroup]="userForm">
      <ng-template matStepLabel>Account Information</ng-template>
      <div class="stepContent">
        <div fxLayout="row" fxLayout.lt-sm="column" [formGroup]="userForm.get('name')" fxLayoutGap="10px">
          <mat-form-field fxFlex="40%">
            <input matInput placeholder="First Name" aria-label="First Name" formControlName="first">
            <mat-error *ngIf="userForm.get('name').get('first').hasError('required')">
              First Name is required
            </mat-error>
            <mat-error *ngIf="userForm.get('name').get('first').hasError('minLength')">
              Must be at least 2 characters
            </mat-error>
            <mat-error *ngIf="userForm.get('name').get('first').hasError('maxLength')">
              Can't exceed 50 characters
            </mat-error>
          </mat-form-field>
          <mat-form-field fxFlex="20%">
            <input matInput placeholder="MI" aria-label="Middle Initial" formControlName="middle">
            <mat-error *ngIf="userForm.get('name').get('middle').invalid">
              Only inital
            </mat-error>
          </mat-form-field>
          <mat-form-field fxFlex="40%">
            <input matInput placeholder="Last Name" aria-label="Last Name" formControlName="last">
            <mat-error *ngIf="userForm.get('name').get('last').hasError('required')">
              Last Name is required
            </mat-error>
            <mat-error *ngIf="userForm.get('name').get('last').hasError('minLength')">
              Must be at least 2 characters
            </mat-error>
            <mat-error *ngIf="userForm.get('name').get('last').hasError('maxLength')">
              Can't exceed 50 characters
            </mat-error>
          </mat-form-field>
        </div>
       ...
      </div>
    </form>
   </mat-step>
...
</mat-horizontal-stepper>
```

1.  请注意理解当前步骤条和表单配置的工作原理，你应该看到第一行渲染，并从模拟数据中拉取：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/32843e4b-d12a-4a66-9b97-6c034e13732b.png)

多步表单 - 第 1 步

1.  为了完成表单的实现，请参考本章提供的示例代码或[GitHub.com/duluca/lemon-mart](https://github.com/duluca/lemon-mart)上的参考实现。

在你的实现过程中，你会注意到“评论”步骤使用名为`<app-view-user>`的指令。这个组件的最简版本在下面的 ViewUser 组件部分实现了。然而，现在可以自由地在页面内实现这个功能，并在“可绑定和路由数据”部分重构代码。

在下面的截图中，你可以看到在桌面端完成的多步表单的实现效果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/e9a485ac-1bb5-4881-9c2f-bffcee671f75.png)

桌面端多步表单

注意，在使用`fxLayout.lt-sm="column"`替代`fxLayout="row"`的情况下，使一行具有响应式布局形式，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/d8d82436-fc54-4675-8091-cf033e2123d3.png)

移动端多步表单

让我们看看下一节中日期选择器字段是如何工作的。

# 计算属性和日期选择器

如果你想根据用户输入显示已计算的属性，可以按照这里所示的模式进行：

```ts
src/app/user/profile/profile.component.ts ...
get dateOfBirth() {
  return this.userForm.get('dateOfBirth').value || new Date()
}

get age() {
  return new Date().getFullYear() - this.dateOfBirth.getFullYear()
}
...
```

模板中的计算属性使用如下所示：

```ts
src/app/user/profile/profile.component ...
<mat-form-field fxFlex="50%">
  <input matInput placeholder="Date of Birth" aria-label="Date of Birth" formControlName="dateOfBirth" [matDatepicker]="dateOfBirthPicker">
  <mat-hint *ngIf="userForm.get('dateOfBirth').touched">{{this.age}} year(s) old</mat-hint>
  <mat-datepicker-toggle matSuffix [for]="dateOfBirthPicker"></mat-datepicker-toggle>
  <mat-datepicker #dateOfBirthPicker></mat-datepicker>
  <mat-error *ngIf="userForm.get('dateOfBirth').invalid">
    Date must be with the last 100 years
  </mat-error>
</mat-form-field>
...
```

在下面的情况中，你可以看到它的实际效果：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/8aff43df-f604-43cf-9eed-4fb412b9163d.png)

使用 DatePicker 选择日期

选择日期后，将显示计算的年龄，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/65a05b6a-4266-4a78-816f-1749e2a0bab1.png)

计算年龄属性

现在，让我们继续下一步，联系信息，并看看我们如何实现方便的方式来显示和输入地址字段的州部分。

# Type ahead 支持

在`buildUserForm`中，我们设置了对`address.state`的监听器，以支持类型前输入下拉筛选体验：

```ts
src/app/user/profile/profile.component.ts ...
this.states = this.userForm
  .get('address')
  .get('state')
  .valueChanges.pipe(startWith(''), map(value => USStateFilter(value)))
...
```

在模板上，使用`mat-autocomplete`绑定到过滤后的州数组，并使用`async`管道：

```ts
src/app/user/profile/profile.component.html ...
<mat-form-field fxFlex="30%">
  <input type="text" placeholder="State" aria-label="State" matInput formControlName="state" [matAutocomplete]="stateAuto">
  <mat-autocomplete #stateAuto="matAutocomplete">
    <mat-option *ngFor="let state of states | async" [value]="state.name">
      {{ state.name }}
    </mat-option>
  </mat-autocomplete>
  <mat-error *ngIf="userForm.get('address').get('state').hasError('required')">
    State is required
  </mat-error>
</mat-form-field>
...
```

当用户输入`V`字符时，它是这样的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/efe44748-d14c-4d5e-b990-004fd345bd1f.png)

下拉框与 Typeahead 支持

在下一节中，让我们启用多个电话号码的输入。

# 动态表单数组

请注意`phones`是一个数组，可能允许多个输入。我们可以通过使用`this.formBuilder.array`构建`FormArray`及使用几个辅助函数来实现这一点：

```ts
src/app/user/profile/profile.component.ts
...
  phones: this.formBuilder.array(this.buildPhoneArray(user ? user.phones : [])),
...
  private buildPhoneArray(phones: IPhone[]) {
    const groups = []

    if (!phones || (phones && phones.length === 0)) {
      groups.push(this.buildPhoneFormControl(1))
    } else {
      phones.forEach(p => {
        groups.push(this.buildPhoneFormControl(p.id, p.type, p.number))
      })
    }
    return groups
  }

  private buildPhoneFormControl(id, type?: string, number?: string) {
    return this.formBuilder.group({
      id: [id],
      type: [type || '', Validators.required],
      number: [number || '', USAPhoneNumberValidation],
    })
  }
...
```

`BuildPhoneArray`支持使用单个电话输入初始化表单或使用现有数据填充表单，与`BuildPhoneFormControl`协同工作。当用户单击 Add 按钮创建新的条目行时，后一个函数非常有用：

```ts
src/app/user/profile/profile.component.ts
...  
  addPhone() {
    this.phonesArray.push(
      this.buildPhoneFormControl(this.userForm.get('phones').value.length + 1)
    )
  }

  get phonesArray(): FormArray {
    return <FormArray>this.userForm.get('phones')
  }
...
```

`phonesArray`属性 getter 是一个常见的模式，可以更轻松地访问某些表单属性。然而，在这种情况下，这也是必要的，因为我们必须将`get('phones')`转换为`FormArray`，以便我们可以在模板上访问它的`length`属性：

```ts
src/app/user/profile/profile.component.html
...
<mat-list formArrayName="phones">
  <h2 mat-subheader>Phone Number(s)</h2>
  <button mat-button (click)="this.addPhone()">
    <mat-icon>add</mat-icon>
    Add Phone
  </button>
  <mat-list-item *ngFor="let position of this.phonesArray.controls let i=index" [formGroupName]="i">
  <mat-form-field fxFlex="100px">
    <mat-select placeholder="Type" formControlName="type">
      <mat-option *ngFor="let type of this.PhoneTypes" [value]="type">
      {{ type }}
      </mat-option>
    </mat-select>
  </mat-form-field>
  <mat-form-field fxFlex fxFlexOffset="10px">
    <input matInput type="text" placeholder="Number" formControlName="number">
    <mat-error *ngIf="this.phonesArray.controls[i].invalid">
      A valid phone number is required
    </mat-error>
  </mat-form-field>
  <button fxFlex="33px" mat-icon-button (click)="this.phonesArray.removeAt(i)">
    <mat-icon>close</mat-icon>
  </button>
  </mat-list-item>
</mat-list>
...
```

`remove`函数是内联实现的。

我们来看看它应该如何工作：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/3fb49d34-6c03-4edb-86a6-43d3183d8068.png)

使用 FormArray 进行多个输入

现在我们已经完成了输入数据，我们可以继续进行步进器的最后一步：Review。然而，正如之前提到的，Review 步骤使用`app-view-user`指令来显示其数据。让我们先构建该视图。

# ViewUser 组件

这是`<app-view-user>`指令的最小实现，这是 Review 步骤的先决条件。

在`user`下创建一个新的`viewUser`组件，如下所示：

```ts
src/app/user/view-user/view-user.component.ts
import { Component, OnInit, Input } from '@angular/core'
import { IUser, User } from '../user/user'

@Component({
  selector: 'app-view-user',
  template: `
    <mat-card>
      <mat-card-header>
        <div mat-card-avatar><mat-icon>account_circle</mat-icon></div>
        <mat-card-title>{{currentUser.fullName}}</mat-card-title>
        <mat-card-subtitle>{{currentUser.role}}</mat-card-subtitle>
      </mat-card-header>
      <mat-card-content>
        <p><span class="mat-input bold">E-mail</span></p>
        <p>{{currentUser.email}}</p>
        <p><span class="mat-input bold">Date of Birth</span></p>
        <p>{{currentUser.dateOfBirth | date:'mediumDate'}}</p>
      </mat-card-content>
      <mat-card-actions *ngIf="!this.user">
        <button mat-button mat-raised-button>Edit</button>
      </mat-card-actions>
    </mat-card>
  `,
  styles: [
    `
    .bold {
      font-weight: bold
    }
  `,
  ],
})
export class ViewUserComponent implements OnChanges {
  @Input() user: IUser
  currentUser = new User()

  constructor() {}

  ngOnChanges() {
    if (this.user) {
      this.currentUser = User.BuildUser(this.user)
    }
  }
}
```

上面的组件使用`@Input`进行输入绑定，从外部组件获取符合`IUser`接口的用户数据。我们实现`ngOnChanges`事件，每当绑定的数据发生变化时触发。在此事件中，我们使用`User.BuildUser`将存储在`this.user`中的简单 JSON 对象填充为`User`类的实例，并将其分配给`this.currentUser`。模板使用此变量，因为像`currentUser.fullName`这样的计算属性只有在数据驻留在`User`类的实例中时才会起作用。

现在，我们准备完成多步表单。

# 检查组件并保存表单

在多步表单的最后一步，用户应该能够进行审查，然后保存表单数据。作为良好的做法，成功的`POST`请求将返回保存的数据到浏览器。然后我们可以使用从服务器收到的信息重新加载表单：

```ts
src/app/user/profile/profile.component 
...
async save(form: FormGroup) {
  this.userService
    .updateUser(form.value)
    .subscribe(res => this.buildUserForm(res), err => (this.userError = err))
 }
...
```

如果有错误，它们将被设置为`userError`来显示。在保存之前，我们将以紧凑的形式呈现数据，使用可重用组件将表单数据绑定到：

```ts
src/app/user/profile/profile.component.html
...
<mat-step [stepControl]="userForm">
  <form [formGroup]="userForm" (ngSubmit)="save(userForm)">
  <ng-template matStepLabel>Review</ng-template>
  <div class="stepContent">
    Review and update your user profile.
    <app-view-user [user]="this.userForm.value"></app-view-user>
  </div>
  <div fxLayout="row" class="margin-top">
    <button mat-button matStepperPrevious color="accent">Back</button>
    <div class="flex-spacer"></div>
    <div *ngIf="userError" class="mat-caption error">{{userError}}</div>
    <button mat-button color="warn" (click)="stepper.reset()">Reset</button>
    <button mat-raised-button matStepperNext color="primary" type="submit" [disabled]="this.userForm.invalid">Update</button>
  </div>
  </form>
</mat-step>
...
```

最终产品应该是这样的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/3f8afd93-786d-4ae7-b43b-d665971ae9a6.png)

审查步骤

注意重置表单的选项。添加一个警报对话框来确认重置用户输入数据将是良好的用户体验。

现在用户配置文件输入完成，我们正在逐渐地朝着最终目标迈进，即创建一个主/细节视图，其中经理可以点击用户并查看其个人资料详细信息。我们仍然需要添加更多的代码，并且在此过程中，我们已经陷入了一种向组件加载必要数据的样板代码模式。在下一部分中，我们将了解 resolve 守卫，以便我们可以简化我们的代码并减少样板内容。

# 解析守卫

解析守卫是路由守卫的一种类型，如 第十四章中所述，*设计身份验证和授权。* 解析守卫可以通过从路由参数中读取记录 ID 异步加载必要的数据，并在组件激活和初始化时准备好这些数据。

解析守卫的主要优势包括加载逻辑的可重用性，减少样板代码以及摆脱依赖关系，因为组件可以接收到其所需的数据而无需导入任何服务：

1.  在`user/user`下创建一个新的 `user.resolve.ts` 类：

```ts
src/app/user/user/user.resolve.ts
import { Injectable } from '@angular/core'
import { Resolve, ActivatedRouteSnapshot } from '@angular/router'
import { UserService } from './user.service'
import { IUser } from './user'

@Injectable()
export class UserResolve implements Resolve<IUser> {
  constructor(private userService: UserService) {}

  resolve(route: ActivatedRouteSnapshot) {
    return this.userService.getUser(route.paramMap.get('userId'))
  }
}

```

1.  您可以像这样使用 resolve 守卫：

```ts
example
{
  path: 'user',
  component: ViewUserComponent,
  resolve: {
    user: UserResolve,
  },
},
```

1.  `routerLink`将是这样的：

```ts
example
['user', {userId: row.id}]
```

1.  在目标组件的 ` ngOnInit` 挂钩中，您可以这样读取已解析的用户：

```ts
example
this.route.snapshot.data['user']
```

在我们更新`ViewUserComponent`和路由以利用 resolve 守卫后，您可以在接下来的两个部分中观察这种行为。

# 具有绑定和路由数据的可重用组件

现在，让我们重构`viewUser`组件，以便我们可以在多个上下文中重复使用它。一个是它可以使用 resolve 守卫加载自己的数据，适用于主/细节视图，另一个是可以将当前用户绑定到它上，在我们在前一节中构建的多步输入表单的审查步骤中已经完成了绑定：

1.  用以下更改更新`viewUser`组件：

```ts
src/app/user/view-user/view-user.component.ts
...
import { ActivatedRoute } from '@angular/router'

export class ViewUserComponent implements OnChanges, OnInit {
  ...
  constructor(private route: ActivatedRoute) {}

  ngOnInit() {
    if (this.route.snapshot && this.route.snapshot.data['user']) {
      this.currentUser = User.BuildUser(this.route.snapshot.data['user'])
      this.currentUser.dateOfBirth = Date.now() // for data mocking purposes only
    }
  }
  ...
```

现在我们有了两个独立的事件。一个用于`ngOnChanges`，它处理`this.user`已绑定的情况下`this.currentUser`被分配了哪个值。 `ngOnInit`只会在组件首次初始化或路由到达时触发一次。在这种情况下，如果路由的任何数据已被解析，那么它将被分配给`this.currentUser`。

要能够在多个延迟加载的模块中使用此组件，我们必须将其包装在自己的模块中。

1.  在`app`下创建一个新的`shared-components.module.ts`：

```ts
src/app/shared-components.module.ts
import { NgModule } from '@angular/core'
import { ViewUserComponent } from './user/view-user/view-user.component'
import { FormsModule, ReactiveFormsModule } from '@angular/forms'
import { FlexLayoutModule } from '@angular/flex-layout'
import { CommonModule } from '@angular/common'
import { MaterialModule } from './app-material.module'

@NgModule({
  imports: [
    CommonModule,
    FormsModule,
    ReactiveFormsModule,
    FlexLayoutModule,
    MaterialModule,
  ],
  declarations: [ViewUserComponent],
  exports: [ViewUserComponent],
})
export class SharedComponentsModule {}

```

1.  确保在你打算在`User`和`Manager`模块中使用`ViewUserComponent`时，将`SharedComponentsModule`模块引入到每个功能模块中。

1.  从`User`模块的声明中移除`ViewUserComponent`

我们现在已经具备开始实现主/细节视图的关键要素。

# 主/细节视图辅助路由

路由器优先架构的真正力量在于辅助路由的使用，通过仅通过路由器配置影响组件的布局，从而允许在不同布局中重新组合现有组件的丰富场景。辅助路由是彼此独立的路由，它们可以在标记中已定义的命名插座中呈现内容，例如`<router-outlet name="master">`或`<router-outlet name="detail">`。此外，辅助路由可以具有自己的参数、浏览器历史、子级和嵌套辅助路由。

在以下示例中，我们将使用辅助路由实现基本的主/细节视图：

1.  实现一个带有两个命名插座的简单组件：

```ts
src/app/manager/user-management/user-manager.component.ts
template: `
    <div class="horizontal-padding">
      <router-outlet name="master"></router-outlet>
      <div style="min-height: 10px"></div>
      <router-outlet name="detail"></router-outlet>
    </div>
  `
```

1.  在`manager`下创建一个`userTable`组件

1.  更新`manager-routing.module`以定义辅助路由：

```ts
src/app/manager/manager-routing.module.ts
  ...
      {
        path: 'users',
        component: UserManagementComponent,
        children: [
          { path: '', component: UserTableComponent, outlet: 
         'master' },
          {
            path: 'user',
            component: ViewUserComponent,
            outlet: 'detail',
            resolve: {
              user: UserResolve,
            },
          },
        ],
        canActivate: [AuthGuard],
        canActivateChild: [AuthGuard],
        data: {
          expectedRole: Role.Manager,
        },
      },
  ...
```

这意味着当用户导航到`/manager/users`时，他们将看到`UserTableComponent`，因为它是用`default`路径实现的。

1.  在`manager.module`中提供`UserResolve`，因为`viewUser`依赖于它

1.  在`userTable`中实现一个临时按钮

```ts
src/app/manager/user-table/user-table.component.html
<a mat-button mat-icon-button [routerLink]="['/manager/users', { outlets: { detail: ['user', {userId: 'fakeid'}] } }]" skipLocationChange>
  <mat-icon>visibility</mat-icon>
</a>
```

假设用户点击了上述定义的`View detail`按钮，那么`ViewUserComponent`将为具有给定`userId`的用户呈现。在下一张截图中，您可以看到在下一节中实现数据表后，`View Details`按钮将是什么样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/27e24385-6a13-4375-8905-4e0a4da346c9.png)

查看详情按钮

您可以为主和详细信息定义多种组合和备用组件，从而允许无限可能的动态布局。然而，设置`routerLink`可能是一个令人沮丧的体验。根据确切的条件，您必须在链接中提供或不提供所有或一些插座。例如，在上述场景中，如果链接是`['/manager/users', { outlets: { master: [''], detail: ['user', {userId: row.id}] } }]`，则路由将悄无声息地加载失败。预计这些怪癖将在未来的 Angular 版本中得到解决。

现在，我们已经完成了对`ViewUserComponent`的解析守卫的实现，你可以使用 Chrome Dev Tools 查看数据是否被正确加载。在调试之前，请确保我们在第十三章，*持续集成和 API 设计*中创建的模拟服务器正在运行。

1.  确保模拟服务器正在运行，通过执行 `docker run -p 3000:3000 -t duluca/lemon-mart-swagger-server` 或者 `npm run mock:standalone`。

1.  在 Chrome Dev Tools 中，在`this.currentUser` 赋值后设置断点，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/6af6ebd9-acd6-4797-acf2-f02135a7c6a9.png)

Dev 工具调试 ViewUserComponent

你会注意到，在 `ngOnInit` 函数中正确设置了`this.currentUser`，展示了解析守卫的真正好处。`ViewUserComponent` 是详细视图；现在让我们实现带有分页的数据表作为主视图。

# 带有分页的数据表

我们已经创建了铺设主/详细视图的脚手架。在主出口中，我们将有一个用户的分页数据表，因此让我们实现 `UserTableComponent`，其中包含一个名为 `dataSource` 的 `MatTableDataSource` 属性。我们需要能够使用标准分页控件（如 `pageSize` 和 `pagesToSkip`）批量获取用户数据，并且能够通过用户提供的 `searchText` 进一步缩小选择范围。

让我们先为 `UserService` 添加必要的功能。

1.  实现一个新的接口 `IUsers` 来描述分页数据的数据结构

```ts
src/app/user/user/user.service.ts
...
export interface IUsers {
  items: IUser[]
  total: number
}
```

1.  向 `UserService` 添加 `getUsers`

```ts
src/app/user/user/user.service.ts
...
getUsers(pageSize: number, searchText = '', pagesToSkip = 0): Observable<IUsers> {
  return this.httpClient.get<IUsers>(`${environment.baseUrl}/v1/users`, {
    params: {
      search: searchText,
      offset: pagesToSkip.toString(),
      limit: pageSize.toString(),
    },
  })
}
...
```

1.  设置带有分页、排序和过滤的`UserTable`：

```ts
src/app/manager/user-table/user-table.component
import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core'
import { FormControl } from '@angular/forms'
import { MatPaginator, MatSort, MatTableDataSource } from '@angular/material'
import { merge, of } from 'rxjs'
import { catchError, debounceTime, map, startWith, switchMap } from 'rxjs/operators'
import { OptionalTextValidation } from '../../common/validations'
import { IUser } from '../../user/user/user'
import { UserService } from '../../user/user/user.service'

@Component({
  selector: 'app-user-table',
  templateUrl: './user-table.component.html',
  styleUrls: ['./user-table.component.css'],
})
export class UserTableComponent implements OnInit, AfterViewInit {
  displayedColumns = ['name', 'email', 'role', 'status', 'id']
  dataSource = new MatTableDataSource()
  resultsLength = 0
  _isLoadingResults = true
  _hasError = false
  errorText = ''
  _skipLoading = false

  search = new FormControl('', OptionalTextValidation)

  @ViewChild(MatPaginator) paginator: MatPaginator
  @ViewChild(MatSort) sort: MatSort

  constructor(private userService: UserService) {}

  ngOnInit() {}

  ngAfterViewInit() {
    this.dataSource.paginator = this.paginator
    this.dataSource.sort = this.sort

    this.sort.sortChange.subscribe(() => (this.paginator.pageIndex = 0))

    if (this._skipLoading) {
      return
    }

    merge(
      this.sort.sortChange,
      this.paginator.page,
      this.search.valueChanges.pipe(debounceTime(1000))
    )
      .pipe(
        startWith({}),
        switchMap(() => {
          this._isLoadingResults = true
          return this.userService.getUsers(
            this.paginator.pageSize,
            this.search.value,
            this.paginator.pageIndex
          )
        }),
        map((data: { total: number; items: IUser[] }) => {
          this._isLoadingResults = false
          this._hasError = false
          this.resultsLength = data.total

          return data.items
        }),
        catchError(err => {
          this._isLoadingResults = false
          this._hasError = true
          this.errorText = err
          return of([])
        })
      )
      .subscribe(data => (this.dataSource.data = data))
  }

  get isLoadingResults() {
    return this._isLoadingResults
  }

  get hasError() {
    return this._hasError
  }
}

```

初始化分页、排序和筛选属性后，我们使用 `merge` 方法来监听所有三个数据流的更改。如果有一个发生了变化，整个 `pipe` 就会被触发，其中包含对 `this.userService.getUsers` 的调用。然后将结果映射到表的 `datasource` 属性，否则捕获和处理错误。

1.  创建一个包含以下 Material 模块的 `manager-material.module`：

```ts
MatTableModule, 
MatSortModule, 
MatPaginatorModule, 
MatProgressSpinnerModule
```

1.  确保 `manager.module` 正确导入：

    1.  新的 `manager-material.module`

    1.  基线的 `app-material.module`

    1.  必需的 `FormsModule` 、 `ReactiveFormsModule` 和 `FlexLayoutModule`

1.  最后，实现 `userTable` 模板：

```ts
src/app/manager/user-table/user-table.component.html
<div class="filter-row">
  <form style="margin-bottom: 32px">
    <div fxLayout="row">
      <mat-form-field class="full-width">
        <mat-icon matPrefix>search</mat-icon>
        <input matInput placeholder="Search" aria-label="Search" [formControl]="search">
        <mat-hint>Search by e-mail or name</mat-hint>
        <mat-error *ngIf="search.invalid">
          Type more than one character to search
        </mat-error>
      </mat-form-field>
    </div>
  </form>
</div>
<div class="mat-elevation-z8">
  <div class="loading-shade" *ngIf="isLoadingResults">
    <mat-spinner *ngIf="isLoadingResults"></mat-spinner>
    <div class="error" *ngIf="hasError">
      {{errorText}}
    </div>
  </div>
  <mat-table [dataSource]="dataSource" matSort>
    <ng-container matColumnDef="name">
      <mat-header-cell *matHeaderCellDef mat-sort-header> Name </mat-header-cell>
      <mat-cell *matCellDef="let row"> {{row.name.first}} {{row.name.last}} </mat-cell>
    </ng-container>
    <ng-container matColumnDef="email">
      <mat-header-cell *matHeaderCellDef mat-sort-header> E-mail </mat-header-cell>
      <mat-cell *matCellDef="let row"> {{row.email}} </mat-cell>
    </ng-container>
    <ng-container matColumnDef="role">
      <mat-header-cell *matHeaderCellDef mat-sort-header> Role </mat-header-cell>
      <mat-cell *matCellDef="let row"> {{row.role}} </mat-cell>
    </ng-container>
    <ng-container matColumnDef="status">
      <mat-header-cell *matHeaderCellDef mat-sort-header> Status </mat-header-cell>
      <mat-cell *matCellDef="let row"> {{row.status}} </mat-cell>
    </ng-container>
    <ng-container matColumnDef="id">
      <mat-header-cell *matHeaderCellDef fxLayoutAlign="end center">View Details</mat-header-cell>
      <mat-cell *matCellDef="let row" fxLayoutAlign="end center" style="margin-right: 8px">
        <a mat-button mat-icon-button [routerLink]="['/manager/users', { outlets: { detail: ['user', {userId: row.id}] } }]" skipLocationChange>
          <mat-icon>visibility</mat-icon>
        </a>
      </mat-cell>
    </ng-container>
    <mat-header-row *matHeaderRowDef="displayedColumns"></mat-header-row>
    <mat-row *matRowDef="let row; columns: displayedColumns;">
    </mat-row>
  </mat-table>

  <mat-paginator [pageSizeOptions]="[5, 10, 25, 100]"></mat-paginator>
</div>

```

只有主视图，表格看起来像这样的截图：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b9bdc8f6-da44-4279-bf37-70dcff4e8794.png)

UserTable

如果点击查看图标，`ViewUserComponent` 将在详细视图中渲染，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/b31311fa-24cf-44b1-884b-14d612c84a12.png)

主/详细视图

然后可以将 Edit 按钮连接起来，将 `userId` 传递给 `UserProfile`，以便编辑和更新数据。或者，您可以将 `UserProfile` 直接呈现在详细视图中。

带有分页的数据表完成了 LemonMart 的实现目的。现在让我们确保我们所有的测试都通过，然后再继续。

# 更新单元测试

由于我们引入了新的 `userService`，为其创建一个虚假实现，使用与 `authService` 和 `commonTestingProviders` 相同的模式。

1.  为 `UserService` 实现 `IUserService` 接口

```ts
src/app/user/user/user.service.ts
export interface IUserService {
  currentUser: BehaviorSubject<IUser>
  getCurrentUser(): Observable<IUser>
  getUser(id): Observable<IUser>
  updateUser(user: IUser): Observable<IUser>
  getUsers(pageSize: number, searchText: string, pagesToSkip: number): Observable<IUsers>
}
...
export class UserService extends CacheService implements IUserService {
```

1.  实现虚假用户服务

```ts
src/app/user/user/user.service.fake.ts
import { Injectable } from '@angular/core'
import { BehaviorSubject, Observable, of } from 'rxjs'

import { IUser, User } from './user'
import { IUsers, IUserService } from './user.service'

@Injectable()
export class UserServiceFake implements IUserService {
  currentUser = new BehaviorSubject<IUser>(new User())

  constructor() {}

```

```ts
  getCurrentUser(): Observable<IUser> {
    return of(new User())
  }

  getUser(id): Observable<IUser> {
    return of(new User((id = id)))
  }

  updateUser(user: IUser): Observable<IUser> {
    return of(user)
  }

  getUsers(pageSize: number, searchText = '', pagesToSkip = 0): Observable<IUsers> {
    return of({
      total: 1,
      items: [new User()],
    } as IUsers)
  }
}
```

1.  在 `commonTestingProviders` 中添加用户服务的虚假到

```ts
src/app/common/common.testing.ts
export const commonTestingProviders: any[] = [
  ...
  { provide: UserService, useClass: UserServiceFake },
]
```

1.  将`SharedComponentsModule`添加到`commonTestingModules`

```ts
src/app/common/common.testing.ts
export const commonTestingModules: any[] = [
  ...
  SharedComponentsModule
]
```

1.  实例化`UserTableComponent`的默认数据

在修复了提供者和导入后，您会注意到`UserTableComponent`仍然无法创建。这是因为，组件初始化逻辑要求定义`dataSource`。如果未定义，组件将无法创建。但是，我们可以在第二个`beforeEach`方法中轻松修改组件属性，该方法在`TestBed`注入了真实的、模拟的或伪造的依赖项到组件类之后执行。查看下面加粗的变化以进行测试数据设置：

```ts
src/app/manager/user-table/user-table.component.spec.ts ...
  beforeEach(() => {
    fixture = TestBed.createComponent(UserTableComponent)
    component = fixture.componentInstance
 component.dataSource = new MatTableDataSource()
 component.dataSource.data = [new User()]
 component._skipLoading = true
    fixture.detectChanges()
  })
...
```

到目前为止，您可能已经注意到通过更新我们的一些中心配置，一些测试通过了，并且其余的测试可以通过应用我们在整本书中一直在使用的各种模式来解决。例如`user-management.component.spec.ts`使用了我们创建的常用测试模块和提供者：

```ts
src/app/manager/user-management/user-management.component.spec.ts      
providers: commonTestingProviders,
imports: commonTestingModules.concat([ManagerMaterialModule]),
```

当您使用提供者和伪造品时，请记住正在测试哪个模块、组件、服务或类，并小心仅提供依赖项的伪造品。

`ViewUserComponent`是一个特殊情况，我们无法使用我们的常用测试模块和提供者，否则我们将最终创建一个循环依赖。在这种情况下，需要手动指定需要引入的模块。

1.  继续修复单元测试配置，直到所有测试都通过！

在本书中，我们没有涵盖任何功能单元测试，其中我们将测试一些业务逻辑以测试其正确性。相反，我们专注于保持自动生成的测试处于工作状态。我强烈建议使用 Angular 自带的优秀框架来实现单元测试，覆盖关键业务逻辑。

您始终可以选择进一步编写基本的单元测试，使用 Jasmine 在隔离环境中测试类和函数。Jasmine 具有丰富的测试双功能，能够模拟和监视依赖项。编写和维护这种基本单元测试更容易、更便宜。但是，这个主题本身是一个深入的主题，超出了本书的范围。

# 总结

在本章中，我们完成了所有主要的 Angular 应用程序设计考虑以及配方，以便能够轻松地实现业务应用程序。我们讨论了应用面向对象的类设计来使数据的填充或序列化更容易。我们创建了可以通过路由器激活或嵌入另一个带有数据绑定的组件的可重用组件。我们表明您可以将数据`POST`到服务器并缓存响应。我们还创建了一个响应屏幕尺寸变化的丰富多步输入表单。通过利用解析守卫从组件中删除样板代码，我们构建了一个主/细节视图。然后，使用辅助路由实现了数据表格分页。

总的来说，通过采用先路由设计、架构和实施方法，我们对应用程序的设计有了一个很好的高层次理解我们想要实现的目标。此外，通过及早识别重用机会，我们能够优化我们的实施策略，提前实现可重用组件，而不会面临过度设计解决方案的风险。

在下一章中，我们将在 AWS 上建立一个高可用的基础架构来托管 LemonMart。我们将更新项目，使用新的脚本来实现无停机蓝绿部署。


# 第十六章：在 AWS 上高可用的云基础架构

互联网是一个充满敌意的环境。有好的和坏的参与者。坏参与者可以试图攻击你的安全性，或者试图通过**分布式拒绝服务**（**DDoS**）攻击来使你的网站崩溃。如果你幸运的话，好的参与者会喜欢你的网站，并且不会停止使用它。他们会给你建议来改进你的网站，但也可能遇到 bug，并且他们可能会如此热情以至于你的网站因为高流量而变得非常缓慢。在互联网上进行真实世界的部署需要很多专业知识才能做到正确。作为一名全栈开发者，你只能了解关于硬件、软件和网络的一些微妙之处。幸运的是，随着云服务提供商的出现，许多这方面的专业知识已经被转化为软件配置，由提供商解决了繁琐的硬件和网络问题。

云服务提供商最好的功能之一是云可扩展性，指的是你的服务器可以自动扩展以响应意外的高流量，并在流量恢复到正常水平时缩减成本。**亚马逊云服务**（**AWS**）不仅仅实现了基本的云可扩展性，并且引入了高可用性和容错概念，允许在本地和全球进行弹性的部署。我选择介绍 AWS，是因为它的功能远远超出了我在本书中所涉及到的范围。通过 Route 53，你可以获得免费的 DDoS 保护；通过 API Gateway，你可以创建 API 密钥；通过 AWS Lambda，你可以处理成千上万的交易，每个月只需几美元；通过 CloudFront，你可以在世界各大城市的秘密边缘位置缓存你的内容。此外，蓝绿部署可以让你实现软件无停机部署。

总的来说，你将在本章学习到的工具和技术适用于任何云提供商，并且已经成为任何全栈开发者的关键知识。我们将讨论以下主题：

+   创建和保护 AWS 账户

+   右尺寸的基础设施

+   简单的负载测试以优化实例

+   配置和部署到 AWS ECS Fargate

+   脚本化的蓝绿部署

+   计费

# 右尺寸的基础设施

优化你的基础设施的目的是保护公司的收入，同时最大程度地减少操作基础设施的成本。你的目标应该是确保用户不会遇到高延迟，即性能不佳，或者更糟的是未完成或丢失的请求，同时使你的创业项目能够持续发展。

网页应用程序性能的三大支柱如下：

1.  CPU 利用率

1.  内存使用

1.  网络带宽

我故意将磁盘访问排除在关键考虑指标之外，因为只有在应用服务器或数据存储上执行的特定工作负载才会受到影响。只要应用资源由 **内容交付网络**（**CDN**）交付，磁盘访问很少会对提供 Web 应用程序的性能产生影响。也就是说，仍然要留意任何意外的磁盘访问，比如频繁创建临时和日志文件。例如，Docker 可能会产生可以轻松填满驱动器的大量日志。

在理想情况下，CPU、内存和网络带宽使用应该均匀地在可用容量的 60-80% 之间利用。如果由于磁盘 I/O、慢的第三方服务或低效的代码等各种其他因素导致性能问题，很可能其中一种指标会接近或达到最大容量，而另外两种指标则处于空转或严重未被利用。这是一个机会，可以使用更多的 CPU、内存或带宽来弥补性能问题，并且均匀利用可用资源。

将目标定在 60-80% 的利用率的原因是为了留出一些时间来为新实例（服务器或容器）进行配置并准备好为用户提供服务。在超出预定阈值后，当正在配置新实例时，您可以继续为日益增多的用户提供服务，从而最小化未满足的请求。

在本书中，我反对过度设计或完美解决方案。在当今复杂的 IT 环境中，几乎不可能预测您会在哪里遇到性能瓶颈。您的工程师可能很容易地花费 10 万美元以上的工程小时数，而解决问题的解决方案可能是几百美元的新硬件，无论是网络交换机、固态硬盘、CPU 还是更多内存。

如果您的 CPU 太忙，您可能需要向您的代码中引入更多的记账逻辑，比如索引、哈希表或字典，您可以将其缓存在内存中，以加速您逻辑的后续步骤或中间步骤。例如，如果您不断运行数组查找操作来定位记录的特定属性，您可以对该记录进行操作，将记录的 ID 和/或属性保存在内存中的哈希表中将能将您的运行成本从 *O(n)* 减少到 *O(1)*。

按照前面的例子，您可能会发现使用哈希表消耗了太多内存。在这种情况下，您可能希望更积极地将缓存转移到速度较慢但更充足的数据存储中，利用您的备用网络带宽，比如 Redis 实例。

如果您的网络利用率过高，您可能需要调查使用具有过期链接的 CDN、客户端缓存、限制请求速率、针对滥用其配额的客户设置 API 访问限制，或优化您的实例，让其网络容量相比 CPU 或内存容量不成比例更多。

# 优化实例

在早些时候的示例中，我演示了使用我的 `duluca/minimal-node-web-server` Docker 镜像来托管我们 Angular 应用程序。尽管 Node.js 是一个非常轻量级的服务器，但它简单地不能对只用作 Web 服务器进行优化。此外，Node.js 具有单线程执行环境，这使其成为为许多并发用户同时提供静态内容的贫乏选择。

您可以通过执行 `docker stats` 观察 Docker 镜像使用的资源：

```ts
$ docker stats
CONTAINER ID  CPU %  MEM USAGE / LIMIT    MEM %  NET I/O         BLOCK I/O  PIDS
27d431e289c9  0.00%  1.797MiB / 1.952GiB  0.09%  13.7kB / 285kB  0B / 0B       2
```

这里是 Node 和基于 NGINX 的服务器在空闲时利用的系统资源的比较结果：

| **服务器** | **              镜像大小** | **             内存使用** |
| --- | --- | --- |
| `duluca/minimal-nginx-web-server` | 16.8 MB | 1.8 MB |
| `duluca/minimal-node-web-server` | 71.8 MB | 37.0 MB |

然而，空闲状态值只能讲述故事的一部分。为了更好地理解，我们必须进行一项简单的负载测试，以查看内存和 CPU 在负载下的利用情况。

# 简单的负载测试

为了更好地了解我们服务器的性能特征，让我们为它们添加一些负载和压力：

1.  使用 `docker run` 启动您的容器：

```ts
$ docker run --name <imageName> -d -p 8080:<internal_port> <imageRepo>
```

如果您使用 `npm 脚本为 Docker`，执行以下命令来启动您的容器：

```ts
$ npm run docker:debug
```

1.  执行以下 bash 脚本以启动负载测试：

```ts
$ curl -L http://bit.ly/load-test-bash [](http://bit.ly/load-test-bash) | bash -s 100 "http://localhost:8080"
```

此脚本将向服务器发送 `100requests/second` 的请求，直到您终止它。

1.  执行 `docker stats` 以观察性能特征。

这里是 CPU 和内存利用的高层次观察：

| **CPU 利用率统计** | **        低** | **         中** | **          高** | **   最大内存** |
| --- | --- | --- | --- | --- |
| `duluca/minimal-nginx-web-server` | 2% |                    15% |                       60% |                   2.4 MB |
| `duluca/minimal-node-web-server` | 20% |                    45% |                     130% |                    75 MB |

正如您所见，两个服务器提供完全相同的内容，但性能存在显著差异。请注意，基于每秒请求的这种测试适用于比较分析，并不一定反映实际使用情况。

很明显，我们的 NGINX 服务器将为我们带来最高的性价比。有了最佳解决方案，让我们在 AWS 上部署应用程序。

# 部署到 AWS ECS Fargate

AWS **弹性容器服务**（**ECS**）Fargate 是在云中部署容器的一种经济高效且易于配置的方式。

ECS 由四个主要部分组成：

1.  容器仓库，**弹性容器注册表**（**ECR**），您可以在其中发布您的 Docker 镜像

1.  服务、任务和任务定义，您可以在其中为容器定义运行时参数和端口映射，服务作为任务运行

1.  群集，EC2 实例的集合，可以在其中调配和扩展任务

1.  Fargate 是一种托管的集群服务，它对 EC2 实例、负载均衡器和安全组问题进行了抽象。

在发表时，Fargate 仅在 AWS `us-east-1`区域可用。

我们的目标是创建高可用的蓝绿部署，意味着我们的应用程序至少在服务器故障或部署期间有一个实例在运行。

# 配置 ECS Fargate

你可以在 AWS 服务菜单下访问 ECS 函数，选择弹性容器服务链接。

如果这是你第一次登录，你必须通过一个教程，在这里你将被要求创建一个样本应用。我建议你完成教程后删除你的样本应用。为了删除服务，你需要更新你的服务任务的数量为 0。此外，删除默认集群以避免任何意外费用。

# 创建一个 Fargate 集群

让我们从配置 Fargate 集群开始，当配置其他 AWS 服务时，它将充当一个锚点。我们的集群最终将运行一个集群服务，在随后的章节中逐步构建。

在发布时，AWS Fargate 只在 AWS 美国东部地区可用，支持更多地区和即将推出对 Amazon Elastic Container Service for Kubernetes（Amazon EKS）的支持。Kubernetes 是一个广泛使用的开源替代品，相对于 AWS ECS 具有更丰富的容器编排能力，支持本地、云和混合部署。

让我们创建集群：

1.  导航到弹性容器服务

1.  点击 Clusters | Create Cluster

1.  选择仅具有网络...由 AWS Fargate 提供支持的模板

1.  点击下一步，你会看到创建集群的步骤，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/8e9ed9d5-8e00-4013-9fc3-36adc67976a9.png)

AWS ECS 创建集群

1.  输入集群名称为 `fargate-cluster`

1.  创建一个 VPC，将你的资源与其他 AWS 资源隔离开来

1.  点击创建集群完成设置

你将看到你的操作摘要，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/2b7b3180-2cb2-4b74-831d-67918e8d0e04.png)

AWS ECS Fargate 集群

现在，你已经在自己的**虚拟私有云**（**VPC**）中创建了一个集群，你可以在弹性容器服务 | 集群下查看它。

# 创建容器库

接下来，我们需要设置一个存储库，在这里我们可以发布我们在本地或 CI 环境中构建的容器映像：

1.  导航到弹性容器服务

1.  点击 Repositories | 创建存储库

1.  将存储库名称输入为 `lemon-mart`

1.  复制屏幕上生成的存储库 URI

1.  将 URI 粘贴在你的应用程序的`package.json`中，作为新的`imageRepo`变量：

```ts
package.json ...
"config": {
  “imageRepo”: “000000000000.dkr.ecr.us-east-1.amazonaws.com/lemon-mart”,
  ...
}
```

1.  点击创建存储库

1.  点击下一步，然后点击完成设置

在摘要屏幕中，你将得到进一步关于如何在 Docker 中使用你的存储库的指导。在本章的后面，我们将介绍如何使用脚本为我们处理这个问题。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/7e6be4a0-2e88-4bc4-abf7-b0f47b70eb93.png)

AWS ECS 仓库

你可以在弹性容器服务 | 存储库下查看你的新存储库。我们将在接下来的`npm 脚本 for AWS`部分介绍如何发布你的映像。

# 创建任务定义

在我们的仓库中定义了一个容器目标后，我们可以定义一个任务定义，其中包含运行我们的容器所需的元数据，例如端口映射、保留 CPU 和内存分配：

1.  转到 Elastic Container Service

1.  点击 Task Definitions | 创建新任务定义

1.  选择 Fargate 启动类型兼容性

1.  将任务定义名称设置为`lemon-mart-task`

1.  选择任务角色`none`（稍后可以添加一个以启用访问其他 AWS 服务）

1.  输入任务大小`0.5 GB`

1.  输入任务 CPU`0.25 CPU`

1.  点击添加容器：

    1.  将容器名称设置为`lemon-mart`

    1.  对于 Image，粘贴之前的镜像仓库 URI，但在其后追加`:latest`标签，以便始终拉取仓库中的最新镜像，例如`000000000000.dkr.ecr.us-east-1.amazonaws.com/lemon-mart:latest`

    1.  为 NGINX 设置软限制为`128 MB`，为 Node.js 设置为`256 MB`

    1.  在端口映射下，为 NGINX 指定容器端口为`80`，为 Node.js 指定为`3000`。

1.  接受剩下的默认值

1.  点击添加；这是在创建任务定义之前您的任务定义将看起来像的样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/d7124065-4598-41fa-a919-bb23363ca313.jpg)

AWS ECS 任务定义

1.  点击创建以完成设置

在 Elastic Container Service | Task Definitions 下查看您的新任务定义。

请注意，默认设置将启用 AWS CloudWatch 日志记录，这是您可以在后期访问容器实例的控制台日志的一种方式。在此示例中，将创建名为`/ecs/lemon-mart-task`的 CloudWatch 日志组。

在 Cloud Watch | Logs 下查看您的新日志组。

如果您正在添加需要持久数据的容器，则任务定义允许您定义卷并将文件夹挂载到您的 Docker 容器中。我已发布了一篇关于在您的 ECS 容器中配置 AWS **弹性文件系统** (**EFS**)的指南，网址为[bit.ly/mount-aws-efs-ecs-container](http://bit.ly/mount-aws-efs-ecs-container)。

# 创建弹性负载均衡器

在高可用部署中，我们将希望在两个不同的**可用区**（**AZs**）上运行两个容器实例，如我们刚刚创建的任务定义所定义的那样。对于这种动态扩展和收缩，我们需要配置一个**应用负载均衡器**（**ALB**）来处理请求路由和排空：

1.  在另一个选项卡上，导航至 EC2 | 负载均衡器 | 创建负载均衡器

1.  创建一个应用负载均衡器

1.  输入名称`lemon-mart-alb`：

为了支持监听器下的 SSL 流量，你可以在端口`443`上添加一个新的 HTTPS 监听器。通过 AWS 服务和向导，可以方便地设置 SSL。在 ALB 配置过程中，AWS 提供了链接到这些向导以创建你的证书。然而，这是一个复杂的过程，取决于你现有的域名托管和 SSL 证书设置。在本书中，我将跳过与 SSL 相关的配置。你可以在我发布的指南[bit.ly/setupAWSECSCluster](http://bit.ly/setupAWSECSCluster)中找到 SSL 相关的步骤。

1.  在可用区中，选择为您的 fargate-cluster 创建的 VPC

1.  选择所有列出的可用区

1.  展开标签，添加一个键/值对以便识别 ALB，比如``"App": " LemonMart"``

1.  点击下一步

1.  选择默认的 ELB 安全策略

1.  点击下一步

1.  创建一个新的集群特定安全组，`lemon-mart-sg`，仅允许端口`80`入站或`443`（如果使用 HTTPS）。

在下一节中创建集群服务时，请确保此处创建的安全组是在服务创建期间选择的那个。否则，您的 ALB 将无法连接到您的实例。

1.  点击下一步

1.  将新的目标组命名为`lemon-mart-target-group`

1.  将协议类型从`instance`更改为`ip`

1.  在健康检查下，保持默认路由`/`，如果在 HTTP 上提供网站

健康检查对于扩展和部署操作至关重要。这是 AWS 用来检查实例是否已成功创建的机制。

如果部署 API 和/或将所有 HTTP 调用重定向到 HTTPS，请确保你的应用定义了一个不重定向到 HTTPS 的自定义路由。在 HTTP 服务器 GET `/healthCheck` 返回简单的`I'm healthy`消息，并验证这不会重定向到 HTTPS。否则，你将通过许多痛苦和痛苦来试图弄清楚问题所在，因为所有的健康检查都失败了，而部署却莫名其妙地失败了。`duluca/minimal-node-web-server`提供 HTTPS 重定向功能，以及开箱即用的仅 HTTP `/healthCheck`端点。使用`duluca/minimal-nginx-web-server`，你将需要提供自己的配置。

1.  点击下一步

1.  *不*注册任何目标或 IP 范围。如果这是由 ECS Fargate 魔法般地为您管理的，如果您自己这样做，您将为半破碎的基础设施提供。

1.  点击下一步:审核;您的 ALB 设置应该与所示的类似：

![示图](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/2e42b62b-1efa-45dd-a56f-c39ea39b1674.png)

AWS 应用负载均衡器设置

1.  点击创建完成设置

在下一节中创建集群服务时，您将使用 lemon-mart-alb。

# 创建集群服务

现在，我们将通过使用任务定义和我们创建的 ALB 在我们的集群中创建一个服务，将它们整合起来：

1.  转到弹性容器服务

1.  点击集群 | fargate-cluster

1.  在服务选项卡下，点击创建

1.  选择启动类型`Fargate`

1.  选择您之前创建的任务定义

请注意，任务定义是有版本的，比如 `lemon-mart-task:1`。如果要对任务定义进行更改，AWS 将创建 `lemon-mart-task:2`。您需要使用此新版本更新服务，以使更改生效。

1.  输入服务名称 `lemon-mart-service`

1.  任务数量 `2`

1.  最小可用百分比 `50`

1.  最大百分比 `200`

1.  点击下一步

为了确保在部署过程中保持高可用性，将最小健康百分比设置为 100。Fargate 的定价是按秒计费的，因此在部署应用程序时，您将额外支付额外的实例费用，而旧实例正在被取消。

1.  在配置网络下，选择与之前集群相同的 VPC

1.  选择所有现有的子网；应至少有两个以保证高可用性

1.  选择在上一部分中创建的安全组—`lemon-mart-sg`

1.  将负载均衡器类型选择为应用负载均衡器

1.  选择 lemon-mart-alb 选项

1.  通过点击“添加到负载均衡器”按钮，为 ALB（应用负载均衡器）添加容器端口，例如 `80` 或 `3000`

1.  选择您已经定义的监听端口

1.  选择您之前定义的目标组

1.  取消勾选“启用服务发现集成”

1.  点击下一步

1.  如果您希望实例在达到一定限制时能够自动扩展和缩减，则设置自动缩放

我建议在服务的初始设置过程中跳过自动扩展的设置，以便更容易排除任何潜在的配置问题。您可以随后再回来进行设置。自动任务缩放策略依赖于警报，如 CPU 利用率。

1.  点击下一步，并审查您所做的更改，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/2667f438-d9ae-46dd-a7d3-d750321987ce.png)

AWS Fargate 集群服务设置

1.  最后，点击“保存”完成设置

观察您在 Elastic Container Service | Clusters | fargate-cluster | lemon-mart-service 下的新服务。在将图像发布到容器存储库之前，您的 AWS 服务将无法启动实例，因为健康检查将持续失败。发布图像后，您将希望确保服务的事件标签中没有错误。

AWS 是一个复杂的系统，通过 Fargate，您可以避免很多复杂性。然而，如果您有兴趣使用自己的 Ec2 实例建立自己的 ECS 集群，您可以通过 1-3 年的保留实例获得重大折扣。我有一份完整的设置指南，可在 [bit.ly/setupAWSECSCluster](http://bit.ly/setupAWSECSCluster) 上找到。

我们手动执行了许多步骤来创建我们的集群。AWS CloudFormation 可以通过提供可定制的配置模板或从头开始编写模板来解决这个问题。如果您希望认真对待 AWS，这种代码即基础设施的设置绝对是上策。

对于生产部署，请确保您的配置由 CloudFormation 模板定义，这样就可以轻松地重新配置，而不是在部署相关的意外失误发生时。

# 配置 DNS

如果您使用 AWS Route 53 来管理您的域名，那么很容易将域名或子域名分配给 ALB：

1.  转到 Route 53 | 托管区域

1.  选择您的域名，例如`thejavascriptpromise.com`

1.  点击创建记录集

1.  将名称输入为`lemonmart`

1.  将别名设置为`是`

1.  从负载均衡器列表中选择 lemon-mart-alb

1.  点击创建以完成设置

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/73962f56-148b-48e2-8930-428db0754ce7.png)

Route 53 - 创建记录集

现在，您的站点将通过您刚刚定义的子域名可达，例如`http://lemonmart.thejavascriptpromise.com`。

如果不使用 Route 53，不必惊慌。在您的域名提供商的网站上，编辑`Zone`文件以创建`A`记录到 ELB 的 DNS 地址，完成后即可。

# 获取 DNS 名称

为了获得负载均衡器的 DNS 地址，请执行以下步骤：

1.  转到 EC2 | 负载均衡器

1.  选择 lemon-mart-alb

1.  在描述标签中记录 DNS 名称；考虑以下示例：

```ts
DNS name:
lemon-mart-alb-1871778644.us-east-1.elb.amazonaws.com (A Record)
```

# 准备 Angular 应用

本节假设您已经根据第十章*，为生产发布准备 Angular 应用*的详细说明设置了 Docker 和`npm Scripts for Docker`。您可以在[bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker)获取这些脚本的最新版本。

实现优化的`Dockerfile`：

```ts
Dockerfile 
FROM duluca/minimal-nginx-web-server:1.13.8-alpine
COPY dist /var/www
CMD 'nginx'
```

请注意，如果您正在使用`npm Scripts for Docker`，请将内部图像端口从`3000`更新到`80`，如下所示：

```ts
"docker:runHelper": "cross-conf-env docker run -e NODE_ENV=local --name $npm_package_config_imageName -d -p $npm_package_config_imagePort:80 $npm_package_config_imageRepo",
```

# 添加 npm Scripts for AWS

就像`npm Scripts for Docker`一样，我开发了一组脚本，称为`npm Scripts for AWS`，适用于 Windows 10 和 macOS。这些脚本将使您能够以出色、无停机时间、蓝绿色方式上传和发布您的 Docker 镜像。您可以在[bit.ly/npmScriptsForAWS](http://bit.ly/npmScriptsForAWS)获取这些脚本的最新版本：

1.  确保您的项目已经设置了[bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker)

1.  创建`.env`文件并设置`AWS_ACCESS_KEY_ID`和`AWS_SECRET_ACCESS_KEY`：

```ts
.env
AWS_ACCESS_KEY_ID=your_own_key_id
AWS_SECRET_ACCESS_KEY=your_own_secret_key
```

1.  确保您的`.env`文件在您的`.gitignore`文件中，以保护您的秘密信息

1.  安装或升级到最新的 AWS CLI：

    +   在 macOS 上 `brew install awscli`

    +   在 Windows 上`choco install awscli`

1.  使用您的凭证登录 AWS CLI：

    1.  运行`aws configure`

    1.  您将需要从配置 IAM 账户时获得的访问密钥 ID 和访问密钥 Commands 的各位。

    1.  设置默认区域名称，如`us-east-1`

1.  更新`package.json`，添加新的`config`属性，其中包含以下配置属性：

```ts
package.json
  ...
  "config": {
    ...
    "awsRegion": "us-east-1",
    "awsEcsCluster": "fargate-cluster",
    "awsService": "lemon-mart-service"
  },
 ...
```

确保您从配置`npm Scripts for Docker`时更新了`package.json`，以便`imageRepo`属性具有您新的 ECS 存储库的地址。

1.  向`package.json`添加 AWS `scripts`，示例如下：

```ts
package.json
...
"scripts": {
  ...
  "aws:login": "run-p -cs aws:login:win aws:login:mac",
  "aws:login:win": "cross-conf-env aws ecr get-login --no-include-email --region $npm_package_config_awsRegion > dockerLogin.cmd && call dockerLogin.cmd && del dockerLogin.cmd",
 "aws:login:mac": "eval $(aws ecr get-login --no-include-email --region $npm_package_config_awsRegion)"
}
```

`npm run aws:login` 调用特定于平台的命令,自动执行从 AWS CLI 工具获取 Docker 登录命令的多步操作,如下所示:

```ts
example
$ aws ecr get-login --no-include-email --region us-east-1
docker login -u AWS -p eyJwYXl...3ODk1fQ== https://073020584345.dkr.ecr.us-east-1.amazonaws.com
```

你首先需要执行 `aws ecr get-login`,然后复制粘贴得到的 `docker login` 命令并执行它,以便你的本地 Docker 实例指向 AWS ECR:

```ts
package.json
...
"scripts": {
  ...
  "aws:deploy": "cross-conf-env docker run --env-file ./.env duluca/ecs-deploy-fargate -c $npm_package_config_awsEcsCluster -n $npm_package_config_awsService -i $npm_package_config_imageRepo:latest -r $npm_package_config_awsRegion --timeout 1000"
  }
...
```

`npm run aws:deploy` 拉取一个 Docker 容器,该容器本身执行蓝绿部署,使用你通过 `aws ecr` 命令提供的参数。这是如何运作的细节超出了本书的范围。要查看更多使用本地 `aws ecr` 命令的示例,请参考 `aws-samples` 存储库 [github.com/aws-samples/ecs-blue-green-deployment](https://github.com/aws-samples/ecs-blue-green-deployment)。

请注意, `duluca/ecs-deploy-fargate` 蓝绿部署脚本是原始 `silintl/ecs-deploy` 镜像的一个分支,经过修改以支持使用 PR `https://github.com/silinternational/ecs-deploy/pull/129` 的 AWS ECS Fargate。一旦 `silintl/ecs-deploy` 合并了这个变更,我建议你使用 `silintl/ecs-deploy` 进行蓝绿部署:

```ts
package.json
...
"scripts": {
  ...
  "aws:release": "run-s -cs aws:login docker:publish aws:deploy"
}
...
```

最后, `npm run aws:release` 只需按正确的顺序运行 `aws:login`、`docker:publish` 和 `aws:deploy` 命令。

# 发布

你的项目已配置为部署在 AWS 上。你主要需要使用我们创建的两个命令来构建和发布镜像:

1.  执行 `docker:debug` 来测试、构建、标记、运行、跟踪并在浏览器中启动你的应用程序来测试镜像:

```ts
$ npm run docker:debug
```

1.  执行 `aws:release` 配置 Docker 登录 AWS,发布最新的镜像构建,并将其发布到 ECS:

```ts
 $ npm run aws:release
```

1.  验证你的任务在服务级别正在运行: 

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/5a8b7712-bc0f-49bd-b908-5a18033ae11a.png)

AWS ECS 服务

确保运行计数和期望计数相同。

1.  验证你的实例在任务级别正在运行:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/5c618d29-9ac5-47b9-be02-d4f9129fde8b.png)

AWS ECS 任务实例

记下公网 IP 地址并导航到它; 例如 `http://54.164.92.137`，你应该能看到你的应用程序或正在运行的 LemonMart。

1.  验证负载均衡器在 DNS 级别的设置是否正确。

1.  导航到 ALB DNS 地址,例如 `http://lemon-mart-alb-1871778644.us-east-1.elb.amazonaws.com`,确认应用程序呈现如下:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/d0f9a4d3-180d-467e-b7c9-31fff9d22ff8.png)

LemonMart 运行在 AWS Fargate 上

瞧!你的网站应该已经启动并运行了。

在后续版本发布中,你将能够观察到蓝绿部署的进行,如下所示:

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/bd-lgscl-webapp-ng/img/e8f25e27-ecbe-4a4a-9709-0d98df5c1666.png)

AWS 服务在蓝绿部署期间

有两个任务正在运行,另外两个新任务正在预配置。在新任务得到验证的同时,运行数量会上升到四个任务。在新任务得到验证并从旧任务中排出连接后,运行数量将恢复为两个。

你可以通过配置 CircleCI 与你的 AWS 凭据，使用已安装了`awscli`工具的容器，并运行`npm Scripts for AWS`来自动化你的部署。使用这种技术，你可以实现对暂存环境的持续部署或对生产环境的持续交付。

# 摘要

在本章中，你了解了正确保护你的 AWS 账户的微妙之处和各种安全考虑。我们讨论了调整基础架构的概念。你以隔离的方式进行了简单的负载测试，以找出两个 Web 服务器之间性能的相对差异。拥有了一个经过优化的 Web 服务器，你配置了 AWS ECS Fargate 集群，实现了高可用的云基础架构。通过使用 AWS 的 npm 脚本，你学会了如何编写可重复和可靠的无停机蓝绿部署。最后，你了解了在 AWS 和其他云提供商（如 Heroku、Zeit Now 和 Digital Ocean）上运行基础架构的基本成本。
