# Angular6 面向企业级的 Web 开发（五）

> 原文：[`zh.annas-archive.org/md5/87CFF2637ACB075A16B30B5AA7A68992`](https://zh.annas-archive.org/md5/87CFF2637ACB075A16B30B5AA7A68992)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：Angular 应用程序设计和示例

在这一章中，我们将完成 LemonMart 的实现。作为路由器优先方法的一部分，我将演示创建可重用的可路由组件，这些组件还支持数据绑定 - 使用解析守卫来减少样板代码，并利用类、接口、枚举、验证器和管道来最大程度地重用代码。此外，我们将创建多步骤表单，实现带分页的数据表，并探索响应式设计。在本书中，我们将涉及 Angular 和 Angular Material 提供的大部分主要功能。

在这一章中，我们将放开训练轮。我会提供一般指导来帮助你开始实现；然而，完成实现将取决于你自己的努力。如果你需要帮助，你可以参考本书提供的完整源代码，或者参考 GitHub 上最新的示例：[Github.com/duluca/lemon-mart](https://github.com/duluca/lemon-mart)。

在这一章中，你将学习以下主题：

+   面向对象类设计

+   可路由复用组件

+   缓存服务响应

+   HTTP POST 请求

+   多步骤响应式表单

+   解析守卫

+   使用辅助路由的主/细节视图

+   带分页的数据表

# 用户类和面向对象编程

到目前为止，我们只使用接口来表示数据，并且我们仍然希望在各种组件和服务之间传递数据时继续使用接口。然而，需要创建一个默认对象来初始化`BehaviorSubject`。在**面向对象编程**（**OOP**）中，让`User`对象拥有这个功能比让一个服务拥有更有意义。因此，让我们实现一个`User`类来实现这个目标。

在`user/user`文件夹中，定义一个`IUser`接口和一个在`UserModule`中提供的`User`类：

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

```

```ts
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

请注意，通过在构造函数中将所有属性定义为`public`属性并赋予默认值，我们一举两得；否则，我们将需要分别定义属性并初始化它们。这样，我们实现了简洁的实现。

你还可以为模板实现计算属性，比如方便地显示用户的`fullName`：

```ts
src/app/user/user/user.ts  
get fullName() {
  return `${this.name.first} ${this.name.middle} ${this.name.last}`
}
```

使用`static BuildUser`函数，您可以快速为对象填充从服务器接收到的数据。您还可以实现`toJSON()`函数，以在将数据发送到服务器之前自定义对象的序列化行为。

# 重用组件

我们需要一个能够显示特定用户信息的组件。这些信息被呈现的自然位置是当用户导航到`/user/profile`时。您可以看到`User`配置文件的模拟。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/ef9ce93e-84a3-4d59-a6f4-66d2d327507e.png)用户配置文件模拟

用户信息还在应用程序的其他位置模拟显示，位于`/manager/users`：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/8de496e4-644b-4d38-bac6-7d4507a186ed.png)管理用户管理模拟

为了最大程度地重用代码，我们需要确保设计一个`User`组件，可以在两个上下文中使用。

例如，让我们完成两个与用户配置文件相关的屏幕的实现。

# 带缓存、GET 和 POST 的用户服务

为了实现用户配置文件，我们必须首先实现一个可以对`IUser`执行 CRUD 操作的`UserService`。在创建服务之前，您需要运行`lemon-mart-swagger-server`，这样您就可以在开发过程中使用它来拉取虚假数据：

1.  在`package.json`中添加一个名为`mock:standalone`的新脚本

```ts
package.json
"mock:standalone": "docker run -p 3000:3000 -t duluca/lemon-mart-swagger-server",
```

请注意，此脚本假定您已经在本地计算机上独立构建了您的 swagger 服务器和/或从您可以拉取的存储库中发布了它。

1.  执行脚本

1.  在`environment.ts`和`environment.prod.ts`中创建一个`baseUrl`属性，其中包含到您的模拟服务器的 url

```ts
src/environments/environment.ts
export const environment = {
  production: false,
  baseUrl: 'http://localhost:3000'
}
```

1.  在`user/user`下创建一个`UserService`，如下所示：

```ts
src/app/user/user/user.service.ts
@Injectable({
  providedIn: 'root'
})
export class UserService extends CacheService {
  currentUser = new BehaviorSubject<IUser>(this.getItem('user') || new User())
  private currentAuthStatus: IAuthStatus
  constructor(private httpClient: HttpClient, private authService: AuthService) {
    super()
    this.currentUser.subscribe(user => this.setItem('user', user))
    this.authService.authStatus.subscribe(
      authStatus => (this.currentAuthStatus = authStatus)
    )
  }

  getCurrentUser(): Observable<IUser> {
    const userObservable = this.getUser(this.currentAuthStatus.userId).pipe(
      catchError(transformError)
    )
    userObservable.subscribe(
      user => this.currentUser.next(user),
      err => Observable.throw(err)
    )
    return userObservable
  }

```

```ts
  getUser(id): Observable<IUser> {
    return this.httpClient.get<IUser>(`${environment.baseUrl}/v1/user/${id}`)
  }

  updateUser(user: IUser): Observable<IUser> {
    this.setItem('draft-user', user) // cache user data in case of errors
    const updateResponse = this.httpClient
      .put<IUser>(`${environment.baseUrl}/v1/user/${user.id || 0}`, user)
      .pipe(catchError(transformError))

    updateResponse.subscribe(
      res => {
        this.currentUser.next(res)
        this.removeItem('draft-user')
      },
      err => Observable.throw(err)
    )

    return updateResponse
  }
}
```

在`UserService`中，`currentUser`将作为锚定`BehaviorSubject`。为了保持我们的缓存最新，我们在`constructor`中订阅`currentUser`的变化。此外，我们订阅`authStatus`，因此当用户加载其自己的配置文件时，`getProfile`可以使用经过身份验证的用户的`userId`执行`GET`调用。

此外，我们单独提供了一个`getUser`函数，以便管理员可以加载其他用户配置文件的详细信息，这在我们稍后在本章实现主/细节视图时将会需要。最后，`updateUser`接受一个实现`IUser`接口的对象，因此数据可以发送到`PUT`端点。重要的是要强调，当传递数据时，您应始终坚持接口而不是像`User`这样的具体实现。这是 SOLID 原则中的 D-依赖反转原则。依赖具体实现会带来很多风险，因为它们经常变化，而像`IUser`这样的抽象很少会改变。毕竟，你会直接把灯焊接到墙上的电线吗？不，你会先把灯焊接到插头上，然后使用插头来获取你需要的电力。

`UserService`现在可以用于基本的 CRUD 操作。

# 用户配置文件与多步鉴权启用的响应式表单

现在，让我们实现一个多步输入表单，以捕获用户配置文件信息。我们还将使用媒体查询使这个多步表单对移动设备具有响应性。

1.  让我们从添加一些辅助数据开始，这些数据将帮助我们显示一个带有选项的输入表单：

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

1.  安装一个辅助库以以编程方式访问 TypeScript 枚举值

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

在加载时，我们从`userService`请求当前用户，但这将需要一些时间，因此我们必须首先用`this.buildUserForm()`构建一个空表单。在这个函数中，您还可以实现一个解析守卫，如后面的部分所讨论的那样，根据路由提供的`userId`加载用户，并将该数据传递到`buildUserForm(routeUser)`中，跳过加载`currentUser`以增加此组件的可重用性。

# 表单组

我们的表单有许多输入字段，因此我们将使用`FormGroup`，由`this.formBuilder.group`创建，来容纳我们的各种`FormControl`对象。此外，子`FormGroup`对象将允许我们维护正确的数据结构形状。

按照以下方式开始构建`buildUserForm`函数：

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

`buildUserForm` 可选地接受一个 `IUser` 来预填表单，否则所有字段都设置为它们的默认值。`userForm` 本身是顶级 `FormGroup`。各种 `FormControls` 被添加到其中，例如 `email`，并根据需要附加验证器。请注意 `name` 和 `address` 是它们自己的 `FormGroup` 对象。这种父子关系确保了表单数据的正确结构，当序列化为 JSON 时，它符合 `IUser` 的结构，以便我们的应用程序和服务器端代码可以利用。

您将独立完成 `userForm` 的实现，按照本章提供的示例代码，并且我将在接下来的几节中逐步解释代码的某些关键功能。

# 步进器和响应式布局

Angular Material Stepper 需要使用 `MatStepperModule`。该步进器允许将表单输入分解为多个步骤，以便用户不会一次处理大量的输入字段。用户仍然可以跟踪他们在流程中的位置，并且作为开发人员，我们可以分解 `<form>` 实现并逐步强制执行验证规则，或者创建可选的工作流，其中某些步骤可以被跳过或必需的。与所有 Material 用户控件一样，步进器是根据响应式 UX 设计的。在接下来的几节中，我们将实现三个步骤，涵盖流程中的不同表单输入技术：

1.  账户信息

+   输入验证

+   使用媒体查询的响应式布局

+   计算属性

+   日期选择器

1.  联系信息

+   类型提前支持

+   动态表单数组

1.  回顾

+   只读视图

+   保存和清除数据

让我们为用户模块准备一些新的 Material 模块：

1.  创建一个 `user-material.module`，其中包含以下 Material 模块：

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

1.  确保 `user.module` 正确导入：

1.  新的 `user-material.module`

1.  基线 `app-material.module`

1.  需要 `FormsModule`、`ReactiveFormsModule` 和 `FlexLayoutModule`

当我们开始添加子 Material 模块时，将根 `material.module.ts` 文件重命名为 `app-material.modules.ts` 是有意义的，与 `app-routing.module.ts` 的命名方式一致。今后，我将使用后一种约定。

1.  现在，开始实现账户信息步骤的第一行：

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

1.  请注意了解步进器和表单配置的工作方式，到目前为止，您应该看到第一行呈现，提取模拟数据：

！[](Images/c97a1ab4-0f09-4ffa-988c-7653e3d2fac7.png)多步骤表单 - 步骤 1

1.  为了完成表单的实现，请参考本章提供的示例代码或[GitHub.com/duluca/lemon-mart](https://github.com/duluca/lemon-mart)上的参考实现

在您的实现过程中，您会注意到 Review 步骤使用了一个名为`<app-view-user>`的指令。这个组件的最小版本在下面的 ViewUser 组件部分中实现了。但是，现在可以随意实现内联功能，并在可重用组件与绑定和路由数据部分重构代码。

在下面的截图中，您可以看到桌面上多步骤表单的完成实现是什么样子的：

！[](Images/57c7a762-3c76-479f-8631-9aea9fe153f0.png)桌面上的多步骤表单

请注意，在带有`fxLayout="row"`的行上添加`fxLayout.lt-sm="column"`可以启用表单的响应式布局，如下所示：

！[](Images/b81c87cc-c4d2-47b6-b535-0d4ee3487d63.png)移动设备上的多步骤表单让我们看看出生日期字段在下一节中是如何工作的。

# 计算属性和日期选择器

如果您想根据用户输入显示计算属性，可以按照这里显示的模式进行操作：

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

模板中计算属性的使用如下所示：

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

这就是它的作用：

！[](Images/32973f3a-9310-4b3f-a27a-576e3ae49b15.png)使用日期选择器选择日期

选择日期后，将显示计算出的年龄，如下所示：

！[](Images/4af6873a-d130-449b-a01d-96b82b2c4fb2.png)计算年龄属性

现在，让我们继续下一步，联系信息，并看看我们如何能够方便地显示和输入地址字段的州部分。

# 输入提示支持

在`buildUserForm`中，我们设置了一个监听器`address.state`来支持类型向前筛选下拉体验：

```ts
src/app/user/profile/profile.component.ts ...
this.states = this.userForm
  .get('address')
  .get('state')
  .valueChanges.pipe(startWith(''), map(value => USStateFilter(value)))
...
```

在模板上，使用`mat-autocomplete`实现绑定到过滤后的州数组的`async`管道：

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

当用户输入`V`字符时，它是什么样子：

！[](Images/3ffccda5-771e-4671-afee-6fe029507a19.png)带有输入提示支持的下拉菜单在下一节中，让我们启用多个电话号码的输入。

# 动态表单数组

请注意，`phones`是一个数组，可能允许多个输入。我们可以通过使用`this.formBuilder.array`构建一个`FormArray`和几个辅助函数来实现这一点：

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

`BuildPhoneArray`支持使用单个电话输入初始化表单，或者使用现有数据填充它，与`BuildPhoneFormControl`协同工作。当用户点击添加按钮创建新的输入行时，后者函数非常有用：

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

`phonesArray`属性的 getter 是一种常见的模式，可以更容易地访问某些表单属性。然而，在这种情况下，它也是必要的，因为必须将`get('phones')`强制转换为`FormArray`，这样我们才能在模板上访问它的`length`属性：

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

让我们看看它应该如何工作：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/e6301bb9-df06-4398-92f8-e04509c99dd3.png)使用 FormArray 的多个输入

现在我们已经完成了输入数据，可以继续进行步进器的最后一步，审查。然而，正如之前提到的，审查步骤使用`app-view-user`指令来显示其数据。让我们先构建那个视图。

# ViewUser 组件

以下是`<app-view-user>`指令的最小实现，这是审查步骤的先决条件。

按照下面的示例在`user`下创建一个新的`viewUser`组件：

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

上面的组件使用输入绑定与`@Input`来获取用户数据，符合`IUser`接口，来自外部组件。我们实现了`ngOnChanges`事件，每当绑定的数据发生变化时就会触发。在这个事件中，我们使用`User.BuildUser`将存储在`this.user`中的简单 JSON 对象实例化为`User`类的实例，并将其赋值给`this.currentUser`。模板使用这个变量，因为像`currentUser.fullName`这样的计算属性只有在数据驻留在`User`类的实例中时才能工作。

现在，我们准备完成多步表单。

# 组件审查和保存表单

在多步表单的最后一步，用户应该能够审查然后保存表单数据。作为一个良好的实践，成功的`POST`请求将返回保存的数据到浏览器。然后我们可以使用从服务器接收到的信息重新加载表单：

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

如果有错误，它们将被设置为`userError`以供显示。在保存之前，我们将以紧凑的形式呈现数据，使用一个可重用的组件将表单数据绑定到其中：

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

这是最终产品应该是什么样子的：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/f3c684b9-b4c6-47c2-9900-482c14ad0fc7.png)审查步骤请注意重置表单的选项。添加一个警报对话框来确认重置用户输入数据将是良好的用户体验。

现在用户配置文件输入已完成，我们已经完成了创建主/细节视图的最终目标的一半，其中经理可以点击用户并查看其配置文件详细信息。我们仍然有很多代码要添加，在这个过程中，我们已经陷入了添加大量样板代码来加载组件所需数据的模式。在下一节中，我们将学习解析守卫，以便简化我们的代码并减少样板代码。

# 解析守卫

解析守卫是一种路由守卫，如第九章中所述，*设计身份验证和授权*。解析守卫可以通过从路由参数中读取记录 ID 来加载组件所需的数据，异步加载数据，并在组件激活和初始化时准备好。

解析守卫的主要优势包括加载逻辑的可重用性、减少样板代码以及减少依赖性，因为组件可以接收到所需的数据而无需导入任何服务：

1.  在`user/user`下创建一个新的`user.resolve.ts`类：

```ts
**src/app/user/user/user.resolve.ts**
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

1.  您可以使用解析守卫，如下所示：

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

1.  `routerLink`将如下所示：

```ts
example
['user', {userId: row.id}]
```

1.  在目标组件的`ngOnInit`钩子中，您可以这样读取已解析的用户：

```ts
example
this.route.snapshot.data['user']
```

您可以在接下来的两个部分中观察到这种行为，之后我们将更新`ViewUserComponent`和路由以利用解析守卫。

# 可重用的组件与绑定和路由数据

现在，让我们重构`viewUser`组件，以便我们可以在多个上下文中重用它。一个是可以使用解析守卫加载自己的数据，适用于主/细节视图，另一个是可以将当前用户绑定到它，就像我们在之前部分构建的多步输入表单的审阅步骤中所做的那样：

1.  使用以下更改更新`viewUser`组件：

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

现在我们有两个独立的事件。一个是`ngOnChanges`，它处理了如果`this.user`已经绑定，则将值分配给`this.currentUser`。`ngOnInit`只会在组件首次初始化或路由到达时触发。在这种情况下，如果路由的任何数据已经解析，它将被分配给`this.currentUser`。

为了能够在多个惰性加载模块中使用该组件，我们必须将其包装在自己的模块中。

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

1.  确保将`SharedComponentsModule`模块导入到您打算在其中使用`ViewUserComponent`的每个功能模块中。在我们的情况下，这将是`User`和`Manager`模块。

1.  从`User`模块声明中删除`ViewUserComponent`

我们现在已经准备好开始实现主/细节视图了。

# 主/细节视图辅助路由

路由器优先架构的真正力量在于使用辅助路由，我们可以仅通过路由器配置影响组件的布局，从而实现丰富的场景，我们可以将现有组件重新组合成不同的布局。辅助路由是彼此独立的路由，它们可以在已在标记中定义的命名出口中呈现内容，例如`<router-outlet name="master">`或`<router-outlet name="detail">`。此外，辅助路由可以有自己的参数、浏览器历史、子级和嵌套辅助。

在以下示例中，我们将使用辅助路由实现基本的主/细节视图：

1.  实现一个具有两个命名出口的简单组件：

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

考虑用户点击上面定义的查看详情按钮，然后`ViewUserComponent`将为具有给定`userId`的用户呈现。在下一个截图中，您可以看到在我们在下一节中实现数据表后，查看详情按钮将是什么样子：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/42796437-7b97-4925-a3b6-4c5ba91b85e5.png)查看详情按钮您可以为主和细节定义许多组合和替代组件，从而允许无限可能的动态布局。然而，设置`routerLink`可能是一种令人沮丧的体验。根据确切的条件，您必须在链接中提供或不提供所有或一些出口。例如，对于前面的情况，如果链接是`['/manager/users', { outlets: { master: [''], detail: ['user', {userId: row.id}] } }]`，路由将悄悄地无法加载。预计这些怪癖将在未来的 Angular 版本中得到解决。

现在，我们已经完成了对`ViewUserComponent`的解析守卫的实现，您可以使用 Chrome Dev Tools 来查看数据是否被正确加载。在调试之前，请确保我们在第八章中创建的模拟服务器正在运行。

1.  确保模拟服务器正在运行，通过执行`docker run -p 3000:3000 -t duluca/lemon-mart-swagger-server`或`npm run mock:standalone`。

1.  在 Chrome Dev Tools 中，设置一个断点，就在`this.currentUser`被分配后，如下所示：

Dev Tools 调试 ViewUserComponent

您将观察到`this.currentUser`在`ngOnInit`函数内部正确设置，而无需加载数据的样板代码，显示了解析守卫的真正好处。`ViewUserComponent`是细节视图；现在让我们将主视图实现为带分页的数据表。

# 带分页的数据表

我们已经创建了用于布置主/细节视图的脚手架。在主输出中，我们将拥有一个用户的分页数据表，因此让我们实现`UserTableComponent`，其中将包含一个名为`dataSource`的`MatTableDataSource`属性。我们需要能够使用标准分页控件（如`pageSize`和`pagesToSkip`）批量获取用户数据，并能够通过用户提供的`searchText`进一步缩小选择范围。

让我们从向`UserService`添加必要的功能开始。

1.  实现一个新的接口`IUsers`来描述分页数据的数据结构

```ts
src/app/user/user/user.service.ts
...
export interface IUsers {
  items: IUser[]
  total: number
}
```

1.  在`UserService`中添加`getUsers`

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

1.  设置`UserTable`的分页、排序和过滤：

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

初始化分页、排序和过滤属性后，我们使用`merge`方法来监听所有三个数据流的变化。如果有一个变化，整个`pipe`就会被触发，其中包含对`this.userService.getUsers`的调用。然后将结果映射到表格的`datasource`属性，否则会捕获和处理错误。

1.  创建一个包含以下 Material 模块的`manager-material.module`：

```ts
MatTableModule, 
MatSortModule, 
MatPaginatorModule, 
MatProgressSpinnerModule
```

1.  确保`manager.module`正确导入：

1.  新的`manager-material.module`

1.  基线`app-material.module`

1.  必需的`FormsModule`、`ReactiveFormsModule`和`FlexLayoutModule`

1.  最后，实现`userTable`模板：

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

只有主视图时，表格看起来像这个截图：

用户表

如果您点击查看图标，`ViewUserComponent`将在详细信息输出中呈现，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/75a8fe77-4da9-4413-b850-b147affe3c90.png)主/细节视图

然后，您可以连接编辑按钮并将`userId`传递给`UserProfile`，以便可以编辑和更新数据。或者，您可以在详细信息输出中直接呈现`UserProfile`。

带分页的数据表完成了 LemonMart 的实现，以便在本书中使用。现在让我们确保所有的测试都通过，然后再继续。

# 更新单元测试

自从我们引入了新的`userService`，为它创建一个伪装实现，使用与`authService`和`commonTestingProviders`相同的模式。

1.  为`UserService`实现`IUserService`接口

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

1.  实现伪装用户服务

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

1.  将用户服务的伪装添加到`commonTestingProviders`

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

1.  为`UserTableComponent`实例化默认数据

修复提供者和导入后，您会注意到`UserTableComponent`仍然无法创建。这是因为组件初始化逻辑需要定义`dataSource`。如果未定义，组件将无法创建。但是，我们可以在第二个`beforeEach`方法中轻松修改组件属性，该方法在`TestBed`将真实的、模拟的或伪装的依赖项注入到组件类之后执行。查看下面加粗的更改以进行测试数据设置：

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

到目前为止，您可能已经注意到，只需更新一些我们中央配置，一些测试就通过了，其余的测试可以通过应用我们在整本书中一直在使用的各种模式来解决。例如`user-management.component.spec.ts`使用了我们创建的常用测试模块和提供者：

```ts
src/app/manager/user-management/user-management.component.spec.ts      
providers: commonTestingProviders,
imports: commonTestingModules.concat([ManagerMaterialModule]),
```

当您使用提供者和伪装时，请记住正在测试的模块、组件、服务或类，并小心只提供依赖项的伪装。

`ViewUserComponent`是一个特殊情况，我们不能使用我们的常用测试模块和提供者，否则我们将最终创建循环依赖。在这种情况下，手动指定需要导入的模块。

1.  继续修复单元测试配置，直到所有测试都通过！

在本书中，我们没有涉及任何功能单元测试，其中我们会测试一些业务逻辑以测试其正确性。相反，我们专注于保持自动生成的测试处于工作状态。我强烈建议使用 Angular 开箱即用提供的优秀框架来实现单元测试，以覆盖关键业务逻辑。

您始终可以选择进一步编写基本单元测试，使用 Jasmine 来隔离测试类和函数。Jasmine 具有丰富的测试双功能，能够模拟和监视依赖关系。编写和维护这种基本单元测试更容易、更便宜。然而，这个话题本身非常深入，超出了本书的范围。

# 总结

在本章中，我们完成了所有主要的 Angular 应用程序设计考虑，以及配方，以便能够轻松实现一款业务应用程序。我们讨论了应用面向对象的类设计，以使数据的填充或序列化更容易。我们创建了可由路由器激活或嵌入到另一个具有数据绑定的组件中的可重用组件。我们展示了您可以将数据`POST`到服务器并缓存响应。我们还创建了一个响应屏幕尺寸变化的丰富多步输入表单。我们通过利用解析守卫从组件中删除样板代码来加载用户数据。然后，我们使用辅助路由实现了主/详细视图，并演示了如何构建带有分页的数据表。

总的来说，通过使用路由器优先设计、架构和实现方法，我们以对我们想要实现的内容有很好的高层次理解来处理我们应用程序的设计。此外，通过及早识别重用机会，我们能够优化我们的实现策略，提前实现可重用组件，而不会冒过度设计解决方案的风险。

在下一章中，我们将在 AWS 上设置一个高可用的基础架构来托管 LemonMart。我们将使用新的脚本更新项目，以实现无停机的蓝绿部署。


# 第十一章：在 AWS 上实现高可用云基础设施

网络是一个充满敌意的环境。有好人和坏人。坏人可能会试图找到您安全漏洞，或者试图通过**分布式拒绝服务**（**DDoS**）攻击来使您的网站崩溃。如果幸运的话，好人会喜欢您的网站并且不会停止使用它。他们会给您提出改进网站的建议，但也可能遇到错误，并且可能因为高流量而使您的网站变得非常缓慢。在网络上进行真实部署需要大量的专业知识才能做到正确。作为全栈开发人员，您只能了解硬件、软件和网络的许多微妙之处。幸运的是，随着云服务提供商的出现，许多这些专业知识已经被转化为软件配置，由提供商来处理困难的硬件和网络问题。

云服务提供商最好的特性之一是云可伸缩性，这指的是您的服务器在面对意外高流量时自动扩展，而在流量恢复到正常水平时自动缩减成本。**亚马逊网络服务**（**AWS**）不仅具备基本的云可伸缩性，还引入了高可用性和容错概念，允许弹性的本地和全球部署。我选择介绍 AWS，是因为它的广泛功能远远超出了我在本书中所涉及的范围。通过 Route 53，您可以获得免费的 DDoS 防护；通过 API Gateway，您可以创建 API 密钥；通过 AWS Lambda，您可以以每月仅几美元的成本处理数百万次的交易；通过 CloudFront，您可以在世界主要城市周围的秘密边缘位置缓存您的内容。此外，蓝绿部署将允许您实现无停机部署您的软件。

总的来说，你将在本章学习的工具和技术适用于任何云服务提供商，并且正在迅速成为任何全栈开发人员的关键知识。我们将讨论以下主题：

+   创建和保护 AWS 账户

+   合适的基础设施规模

+   简单的负载测试以优化实例

+   配置和部署到 AWS ECS Fargate

+   脚本化的蓝绿部署

+   计费

# 创建安全的 AWS 账户

帐户访问和控制在任何云服务中都至关重要，AWS 也不例外。在初始帐户创建后，您将拥有您的根凭据，即您的电子邮件和密码组合。

让我们从创建 AWS 帐户开始：

1.  首先导航到`https://console.aws.amazon.com`

1.  如果您没有帐户，请创建一个新帐户

1.  如果您是 AWS 的新用户，您可以在此注册屏幕上获得 12 个月的免费服务访问权限：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/9e286392-91c9-4518-ae4f-7215ac2426db.png)AWS 帐户注册

您的 AWS 计费与您的根凭据相关联。如果遭到破坏，您的帐户可能会受到很大的损害，而在您重新获得访问权限之前可能会发生很多损害。

1.  确保您在根凭据上启用了双因素认证：

为了增加安全层，从现在开始，您需要停止使用根凭据登录到您的 AWS 帐户。您可以使用 AWS 身份和访问管理（IAM）模块创建用户帐户。如果这些帐户遭到破坏，与您的根帐户不同，您可以轻松快速地删除或替换它们。

1.  导航到`IAM`模块

1.  创建一个具有全局管理员权限的新用户帐户

1.  使用这些凭据登录到 AWS 控制台

1.  您还应该为这些凭据启用双因素认证

1.  安全的帐户设置如下，每个状态都报告为绿色：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a42157c6-6389-42d0-be5a-d9295095a7da.png)安全设置后的 AWS IAM 模块

与用户帐户一起工作的主要好处是程序化访问。对于每个用户帐户，您可以创建一个公共访问 ID 和私有访问密钥对。当您与第三方合作，例如托管的持续集成服务、您自己的应用程序代码或 CLI 工具时，您使用您的程序化访问密钥连接到您的 AWS 资源。当访问密钥不可避免地泄漏时，快速方便地禁用对旧密钥的访问并创建新密钥。

此外，用户帐户访问可以通过非常细粒度的权限进行严格控制。您还可以创建具有一组权限的角色，并进一步控制 AWS 服务和一些外部服务之间的通信。

在创建用户帐户和角色时，始终要在最小权限方面犯错误。当与不熟悉 AWS 的客户、承包商或同事合作时，这可能是一种令人沮丧的练习，但这是一种值得的练习。

你的安全性和可靠性取决于最薄弱的环节，因此你必须计划应对故障，并且最重要的是，定期实践恢复计划。

# 保护秘密

密码和私钥泄漏比你想象的更常见。你的密钥可能会在不安全的公共 Wi-Fi 网络中被泄露；你可能会意外地将它们提交到你的代码仓库中，或者使用极不安全的通信方法，比如电子邮件。然而，意外的代码提交是最大的问题，因为大多数初级开发者并不意识到在源代码控制系统中删除并不是一个选项。

作为开发者，有一些值得注意的最佳实践可以遵循以保护你的秘密：

1.  始终在公共 Wi-Fi 上使用 VPN 服务，比如[tunnelbear.com](https://www.tunnelbear.com/)

1.  利用位于用户`home`文件夹下的`.aws/credentials`文件，创建配置文件并存储访问密钥

1.  在项目的根目录中创建一个`.env`文件，并将其列入`.gitignore`，以存储你的 CI 服务器可能会后续注入的任何秘密作为团队规范

1.  始终在推送之前审查提交

每次遵循这些惯例都会养成一个好习惯，永远不要将你的秘密提交到代码仓库中。在下一节中，我们将深入探讨云环境的资源考虑。

# 合适的基础设施规模

优化基础设施的目的是保护公司的收入，同时最大限度地减少基础设施的运营成本。你的目标应该是确保用户不会遇到高延迟，也就是不良性能，或者更糟糕的是未完成或丢弃的请求，同时使你的企业保持可持续的努力。

Web 应用程序性能的三大支柱如下：

1.  CPU 利用率

1.  内存使用量

1.  网络带宽

我故意将磁盘访问排除在关键考虑指标之外，因为只有在应用服务器或数据存储上执行特定工作负载时才会受到影响。只要应用程序资产由内容交付网络（CDN）提供，磁盘访问很少会影响提供 Web 应用程序的性能。也就是说，仍然要注意任何意外的磁盘访问，比如高频率创建临时和日志文件。例如，Docker 可能会输出日志，这些日志很容易填满驱动器。

在理想的情况下，CPU、内存和网络带宽的使用应该均匀地在可用容量的 60-80%左右。如果您遇到性能问题，由于诸如磁盘 I/O、慢的第三方服务或低效的代码等各种其他因素，很可能您的某个指标会接近或达到最大容量，而另外两个指标则处于空闲或严重未被充分利用的状态。这是一个利用更多 CPU、内存或带宽来补偿性能问题并均匀利用可用资源的机会。

将 60-80%的利用率作为目标的原因是为了为新实例（服务器或容器）提供一些时间来进行配置，并准备好为用户提供服务。在您预定义的阈值被突破后，当新实例被配置时，您可以继续为日益增长的用户提供服务，从而最小化未满足的请求。

在本书中，我已经反对过度设计或完美的解决方案。在当今复杂的 IT 环境中，几乎不可能预测您将遇到性能瓶颈的地方。您的工程师很容易花费 10 万美元以上的工程时间，而解决您的问题可能只需要几百美元的新硬件，无论是网络交换机、固态硬盘、CPU 还是更多内存。

如果您的 CPU 太忙，您可能希望在您的代码中引入更多的记账逻辑，通过索引、哈希表或字典，您可以将其缓存在内存中，以加快逻辑的后续或中间步骤。例如，如果您不断地运行数组查找操作来定位记录的特定属性，您可以对该记录执行一个操作，将记录的 ID 和/或属性保存在内存中的哈希表中，将您的运行成本从*O(n)*降低到*O(1)*。

根据前面的例子，您可能会在哈希表中使用过多的内存。在这种情况下，您可能希望更积极地将缓存卸载或转移到速度较慢但更丰富的数据存储中，利用您多余的网络带宽，比如一个 Redis 实例。

如果您的网络利用率过高，您可能希望调查使用具有过期链接的 CDN、客户端缓存、限制请求速度、滥用配额的客户的 API 访问限制，或者优化您的实例，使其具有与其 CPU 或内存容量相比不成比例的更多网络容量。

# 优化实例

在之前的示例中，我演示了使用我的 `duluca/minimal-node-web-server` Docker 镜像来托管我们的 Angular 应用程序。尽管 Node.js 是一个非常轻量级的服务器，但它并不仅仅是一个优化的 Web 服务器。此外，Node.js 具有单线程执行环境，这使得它不适合同时为许多并发用户提供静态内容。

您可以通过执行 `docker stats` 来观察 Docker 镜像正在使用的资源：

```ts
$ docker stats
CONTAINER ID  CPU %  MEM USAGE / LIMIT    MEM %  NET I/O         BLOCK I/O  PIDS
27d431e289c9  0.00%  1.797MiB / 1.952GiB  0.09%  13.7kB / 285kB  0B / 0B       2
```

以下是 Node 和基于 NGINX 的服务器在空闲时利用的系统资源的比较结果：

| **服务器** | **              镜像大小** | **             内存使用** |
| --- | --- | --- |
| `duluca/minimal-nginx-web-server` |                                     16.8 MB |                                         1.8 MB |
| `duluca/minimal-node-web-server` |                                     71.8 MB |                                       37.0 MB |

然而，空闲时的值只能讲述故事的一部分。为了更好地了解情况，我们必须进行简单的负载测试，以查看在负载下的内存和 CPU 利用率。

# 简单的负载测试

为了更好地了解我们服务器的性能特征，让我们对它们施加一些负载和压力：

1.  使用 `docker run` 来启动您的容器：

```ts
$ docker run --name <imageName> -d -p 8080:<internal_port> <imageRepo>
```

如果您正在使用 `npm Scripts for Docker`，执行以下命令来启动您的容器：

```ts
$ npm run docker:debug
```

1.  执行以下 bash 脚本来开始负载测试：

```ts
$ curl -L http://bit.ly/load-test-bash [](http://bit.ly/load-test-bash) | bash -s 100 "http://localhost:8080"
```

该脚本将向服务器发送 100 个请求/秒，直到您终止它。

1.  执行 `docker stats` 来观察性能特征。

以下是 CPU 和内存利用的高级观察：

| **CPU 利用率统计** | **        低** | **         中** | **          高** | **   最大内存** |
| --- | --- | --- | --- | --- |
| `duluca/minimal-nginx-web-server` |                   2% |                    15% |                       60% |                   2.4 MB |
| `duluca/minimal-node-web-server` |                 20% |                    45% |                     130% |                    75 MB |

正如您所看到的，两个服务器提供完全相同内容之间存在显著的性能差异。请注意，基于每秒请求的这种测试适用于比较分析，并不一定反映实际使用情况。

很明显，我们的 NGINX 服务器将为我们带来最佳性价比。有了最佳解决方案，让我们在 AWS 上部署应用程序。

# 部署到 AWS ECS Fargate

AWS **弹性容器服务**（**ECS**）Fargate 是一种在云中部署容器的成本效益高且易于配置的方式。

ECS 由四个主要部分组成：

1.  容器仓库，**弹性容器注册表**（**ECR**），您可以在其中发布 Docker 镜像

1.  服务、任务和任务定义，您可以在其中定义容器的运行时参数和端口映射，作为服务运行的任务定义。

1.  集群，一个包含 EC2 实例的集合，可以在其中配置和扩展任务

1.  Fargate 是一个托管的集群服务，它抽象了 EC2 实例、负载均衡器和安全组的问题

在发布时，Fargate 仅在 AWS`us-east-1`地区可用。

我们的目标是创建一个高可用的蓝绿部署，这意味着在服务器故障甚至部署期间，我们的应用程序至少会有一个实例在运行。这些概念在第十二章中进行了详细探讨，*Google Analytics 和高级云运维*，在*可扩展环境中的每用户成本*部分。

# 配置 ECS Fargate

您可以在 AWS 服务菜单下访问 ECS 功能，选择弹性容器服务链接。

如果这是您第一次登录，您必须通过教程，其中您将被强制创建一个示例应用程序。我建议您完成教程后删除示例应用程序。为了删除服务，您需要将服务的任务数量更新为 0。此外，删除默认集群以避免任何意外费用。

# 创建 Fargate 集群

让我们从配置 Fargate 集群开始，这将在配置其他 AWS 服务时充当锚点。我们的集群最终将运行一个集群服务，在接下来的章节中我们将逐渐构建起来。

在发布时，AWS Fargate 仅在 AWS 美国东部地区可用，支持更多地区和即将推出对 Amazon 弹性容器服务 Kubernetes（Amazon EKS）的支持。Kubernetes 是 AWS ECS 的广泛首选开源替代方案，具有更丰富的容器编排能力，可用于本地、云和混合云部署。

让我们创建集群：

1.  转到弹性容器服务

1.  单击集群|创建集群

1.  选择仅网络...由 AWS Fargate 提供支持的模板

1.  单击“下一步”，您将看到创建集群步骤，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/d610cb50-7264-4010-9ba0-abab9bddc018.png)AWS ECS 创建集群

1.  将集群名称输入为`fargate-cluster`

1.  创建一个 VPC 来将您的资源与其他 AWS 资源隔离开来

1.  单击创建集群以完成设置

您将看到您的操作摘要，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/63465452-62ae-46e0-bd8b-e841b681dcdc.png)AWS ECS Fargate Cluster

现在您已经在其自己的**虚拟私有云**（**VPC**）中创建了一个集群，您可以在弹性容器服务 | 集群下查看它。

# 创建容器存储库

接下来，我们需要设置一个存储库，我们可以在其中发布我们在本地或 CI 环境中构建的容器映像：

1.  转到弹性容器服务

1.  单击 Repositories | Create Repository

1.  将存储库名称输入为`lemon-mart`

1.  复制屏幕上生成的存储库 URI

1.  将 URI 粘贴到您的应用程序的`package.json`中作为新的`imageRepo`变量：

```ts
package.json ...
"config": {
  “imageRepo”: “000000000000.dkr.ecr.us-east-1.amazonaws.com/lemon-mart”,
  ...
}
```

1.  单击创建存储库

1.  单击下一步，然后单击完成以完成设置

在摘要屏幕上，您将获得有关如何在 Docker 中使用存储库的进一步说明。在本章的后面，我们将介绍将为我们处理此事的脚本。

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/45094246-8522-48b8-a9b0-84c8bcbfd782.png)AWS ECS 存储库

您可以在弹性容器服务 | 存储库下查看您的新存储库。我们将在即将到来的`npm Scripts for AWS`部分介绍如何发布您的镜像。

# 创建任务定义

在我们的存储库中定义了一个容器目标后，我们可以定义一个任务定义，其中包含运行容器所需的元数据，例如端口映射、保留的 CPU 和内存分配：

1.  转到弹性容器服务

1.  单击任务定义 | 创建新任务定义

1.  选择 Fargate 启动类型兼容性

1.  将任务定义名称输入为`lemon-mart-task`

1.  选择任务角色`none`（您可以稍后添加一个以启用访问其他 AWS 服务）

1.  输入任务大小`0.5 GB`

1.  输入任务 CPU `0.25 CPU`

1.  单击添加容器：

1.  将容器名称输入为`lemon-mart`

1.  对于 Image，粘贴之前的镜像存储库 URI，但是在末尾添加`:latest`标签，以便它始终拉取存储库中的最新镜像，例如`000000000000.dkr.ecr.us-east-1.amazonaws.com/lemon-mart:latest`

1.  为 NGINX 设置`128 MB`的软限制，为 Node.js 设置`256 MB`

1.  在端口映射下，指定 NGINX 的容器端口为`80`，Node.js 的端口为`3000`

1.  接受其余默认值

1.  单击添加；这是在创建之前查看任务定义的方式：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/19d28a70-feb5-4322-972c-4b458cba7888.jpg)AWS ECS 任务定义

1.  点击“创建”完成设置

在 Elastic Container Service | 任务定义下查看您的新任务定义。

请注意，默认设置将启用 AWS CloudWatch 日志记录，这是您可以追溯访问容器实例控制台日志的一种方式。在这个例子中，将创建一个名为`/ecs/lemon-mart-task`的 CloudWatch 日志组。

在 Cloud Watch | 日志下查看您的新日志组。如果要添加需要持久数据的容器，任务定义允许您定义一个卷并挂载一个文件夹到您的 Docker 容器。我已经发布了一个指南，用于在 ECS 容器中配置 AWS 弹性文件系统（EFS）[bit.ly/mount-aws-efs-ecs-container](http://bit.ly/mount-aws-efs-ecs-container)。

# 创建弹性负载均衡器

在高可用部署中，我们希望根据刚刚创建的任务定义在两个不同的可用区（AZs）上运行两个容器实例。为了实现这种动态扩展和收缩，我们需要配置一个应用负载均衡器（ALB）来处理请求路由和排空：

1.  在一个单独的标签页上，导航到 EC2 | 负载均衡器 | 创建负载均衡器

1.  创建一个应用负载均衡器

1.  输入名称`lemon-mart-alb`：

为了支持监听器下的 SSL 流量，您可以在端口`443`上添加一个新的 HTTPS 监听器。通过 AWS 服务和向导，可以方便地实现 SSL 设置。在 ALB 配置过程中，AWS 提供了链接到这些向导以创建您的证书。然而，这是一个复杂的过程，可以根据您现有的域托管和 SSL 证书设置而有所不同。在本书中，我将跳过与 SSL 相关的配置。您可以在我发布的指南中找到与 SSL 相关的步骤[bit.ly/setupAWSECSCluster](http://bit.ly/setupAWSECSCluster)。

1.  在可用区中，选择为您的 fargate-cluster 创建的 VPC

1.  选择所有列出的可用区

1.  展开标签并添加一个键/值对，以便能够识别 ALB，比如`"App": "LemonMart"`

1.  点击“下一步”

1.  选择默认 ELB 安全策略

1.  点击“下一步”

1.  创建一个新的集群特定安全组，`lemon-mart-sg`，只允许端口`80`入站，如果使用 HTTPS，则允许端口`443`

在下一节创建集群服务时，请确保此处创建的安全组是在服务创建期间选择的安全组。否则，您的 ALB 将无法连接到您的实例。

1.  点击下一步

1.  将新的目标组命名为`lemon-mart-target-group`

1.  将协议类型从`instance`更改为`ip`

1.  在健康检查下，保持默认路由`/`，如果在 HTTP 上提供网站

健康检查对于扩展和部署操作至关重要。这是 AWS 用来检查实例是否已成功创建的机制。

如果部署 API 和/或将所有 HTTP 调用重定向到 HTTPS，请确保您的应用程序定义了一个不会被重定向到 HTTPS 的自定义路由。在 HTTP 服务器 GET `/healthCheck`返回简单的 200 消息，说`我很健康`，并验证这不会重定向到 HTTPS。否则，您将经历很多痛苦和苦难，试图弄清楚问题出在何处，因为所有健康检查都失败，部署也莫名其妙地失败。`duluca/minimal-node-web-server`提供了 HTTPS 重定向，以及一个开箱即用的仅 HTTP 的`/healthCheck`端点。使用`duluca/minimal-nginx-web-server`，您将需要提供自己的配置。

1.  点击下一步

1.  *不要*注册任何目标或 IP 范围。ECS Fargate 将神奇地为您管理这一切，如果您自己这样做，您将提供一个半破碎的基础设施。

1.  点击下一步：审查；您的 ALB 设置应该与所示的类似：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a2c2bb37-74c7-4c43-b071-da94aa7448c2.png)AWS 应用负载均衡器设置

1.  点击创建完成设置

在下一节创建集群服务时，您将使用 lemon-mart-alb。

# 创建集群服务

现在，我们将通过使用任务定义和我们创建的 ALB 在我们的集群中创建一个服务来将所有内容整合在一起：

1.  导航到弹性容器服务

1.  点击集群| fargate-cluster

1.  在服务选项卡下，点击创建

1.  选择启动类型`Fargate`

1.  选择您之前创建的任务定义

请注意，任务定义是有版本的，比如`lemon-mart-task:1`。如果您对任务定义进行更改，AWS 将创建`lemon-mart-task:2`。您需要使用这个新版本更新服务，以使更改生效。

1.  输入服务名称`lemon-mart-service`

1.  任务数量`2`

1.  最小健康百分比`50`

1.  最大百分比`200`

1.  点击下一步

将最小健康百分比设置为 100，以确保在部署期间保持高可用性。Fargate 的定价是基于每秒的使用量，因此在部署应用程序时，您将额外收费用于额外实例，而旧实例正在被取消配置。

1.  在配置网络下，选择与之前相同的 VPC 作为您的集群

1.  选择所有可用的子网；至少应该有两个以实现高可用性

1.  在上一节中创建的安全组中选择`lemon-mart-sg`

1.  选择负载均衡器类型为应用程序负载均衡器

1.  选择 lemon-mart-alb 选项

1.  通过单击“添加到负载均衡器”按钮，将容器端口添加到 ALB，例如`80`或`3000`

1.  选择您已经定义的侦听器端口

1.  选择您已经定义的目标组

1.  取消选中“启用服务发现集成”

1.  单击“下一步”

1.  如果您希望您的实例在达到一定限制时自动扩展和缩减，则设置自动扩展

我建议在服务的初始设置期间跳过自动扩展的设置，以便更容易排除任何潜在的配置问题。您可以随后返回并进行设置。自动任务扩展策略依赖于警报，例如 CPU 利用率。在第十二章 *Google Analytics and Advanced Cloud Ops,* 中的*可扩展环境中的每用户成本*部分，您可以了解如何计算您的最佳目标服务器利用率，并根据此数字设置您的警报。

1.  单击“下一步”并审查您的更改，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/6ebcff07-5980-4e80-9362-66a39efc8715.png)AWS Fargate 集群服务设置

1.  最后，单击“保存”完成设置

在 Elastic Container Service | Clusters | fargate-cluster | lemon-mart-service 下观察您的新服务。在将图像发布到容器存储库之前，您的 AWS 服务将无法配置实例，因为健康检查将不断失败。发布图像后，您需要确保服务的事件选项卡中没有错误。

AWS 是一个复杂的系统，使用 Fargate 可以避免很多复杂性。但是，如果您有兴趣使用自己的 Ec2 实例设置自己的 ECS 集群，您可以获得 1-3 年预留实例的重大折扣。我有一个 75+设置指南可在[bit.ly/setupAWSECSCluster](http://bit.ly/setupAWSECSCluster)上获得。

我们已经手动执行了很多步骤来创建我们的集群。AWS CloudFormation 通过提供配置模板来解决这个问题，您可以根据自己的需求进行自定义，或者从头开始编写自己的模板脚本。如果您想认真对待 AWS，这种代码即基础架构设置绝对是正确的方式。

对于生产部署，请确保您的配置由 CloudFormation 模板定义，这样它就可以很容易地重新配置，而不是在部署相关的失误发生时。

# 配置 DNS

如果您使用 AWS Route 53 来管理您的域名，很容易将域名或子域分配给 ALB：

1.  导航到 Route 53 | 托管区域

1.  选择您的域名，如`thejavascriptpromise.com`

1.  点击“创建记录集”

1.  将名称输入为`lemonmart`

1.  将别名设置为“是”

1.  从负载均衡器列表中选择 lemon-mart-alb

1.  点击“创建”完成设置

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/f1b4f3fc-7f27-4687-ab90-4e641b544aa1.png)Route 53 - 创建记录集

现在，您的站点将可以通过您刚刚定义的子域访问，例如`http://lemonmart.thejavascriptpromise.com`。

如果不使用 Route 53，请不要惊慌。在您的域名提供商的网站上，编辑“区域”文件以创建一个`A`记录到 ELB 的 DNS 地址，然后您就完成了。

# 获取 DNS 名称

为了获取负载均衡器的 DNS 地址，请执行以下步骤：

1.  导航到 EC2 | 负载均衡器

1.  选择 lemon-mart-alb

1.  在“描述”选项卡中注意 DNS 名称；请参考以下示例：

```ts
DNS name:
lemon-mart-alb-1871778644.us-east-1.elb.amazonaws.com (A Record)
```

# 准备 Angular 应用

本节假定您已经按照第三章中详细介绍的设置了 Docker 和“用于 Docker 的 npm 脚本”。您可以在[bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker)获取这些脚本的最新版本。

实现优化的`Dockerfile`：

```ts
Dockerfile 
FROM duluca/minimal-nginx-web-server:1.13.8-alpine
COPY dist /var/www
CMD 'nginx'
```

请注意，如果您正在使用“用于 Docker 的 npm 脚本”，请将内部镜像端口从`3000`更新为`80`，如下所示：

```ts
"docker:runHelper": "cross-conf-env docker run -e NODE_ENV=local --name $npm_package_config_imageName -d -p $npm_package_config_imagePort:80 $npm_package_config_imageRepo",
```

# 添加用于 AWS 的 npm 脚本

就像“用于 Docker 的 npm 脚本”一样，我开发了一组脚本，称为“用于 AWS 的 npm 脚本”，可以在 Windows 10 和 macOS 上运行。这些脚本将允许您以惊人的、无停机的蓝绿色方式上传和发布您的 Docker 镜像。您可以在[bit.ly/npmScriptsForAWS](http://bit.ly/npmScriptsForAWS)获取这些脚本的最新版本：

1.  确保在您的项目上设置了[bit.ly/npmScriptsForDocker](http://bit.ly/npmScriptsForDocker)

1.  创建一个`.env`文件并设置`AWS_ACCESS_KEY_ID`和`AWS_SECRET_ACCESS_KEY`：

```ts
.env
AWS_ACCESS_KEY_ID=your_own_key_id
AWS_SECRET_ACCESS_KEY=your_own_secret_key
```

1.  确保您的`.env`文件在您的`.gitignore`文件中，以保护您的秘密信息。

1.  安装或升级到最新的 AWS CLI：

+   在 macOS 上`brew install awscli`

+   在 Windows 上``choco install awscli``

1.  使用您的凭据登录到 AWS CLI：

1.  运行`aws configure`

1.  您需要从配置 IAM 帐户时获取您的访问密钥 ID 和秘密访问密钥

1.  设置默认区域名称为`us-east-1`

1.  更新`package.json`，添加一个新的`config`属性，具有以下配置属性：

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

确保您更新了`package.json`，从您配置`npm Scripts for Docker`时，`imageRepo`属性中有您新的 ECS 存储库的地址。

1.  在`package.json`中添加 AWS `scripts`，如下所示：

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

`npm run aws:login`调用特定于平台的命令，自动执行从 AWS CLI 工具获取 Docker 登录命令的多步操作，如下所示：

```ts
example
$ aws ecr get-login --no-include-email --region us-east-1
docker login -u AWS -p eyJwYXl...3ODk1fQ== https://073020584345.dkr.ecr.us-east-1.amazonaws.com
```

您首先要执行`aws ecr get-login`，然后复制粘贴生成的`docker login`命令并执行它，以便您的本地 Docker 实例指向 AWS ECR：

```ts
package.json
...
"scripts": {
  ...
  "aws:deploy": "cross-conf-env docker run --env-file ./.env duluca/ecs-deploy-fargate -c $npm_package_config_awsEcsCluster -n $npm_package_config_awsService -i $npm_package_config_imageRepo:latest -r $npm_package_config_awsRegion --timeout 1000"
  }
...
```

`npm run aws:deploy`拉取一个 Docker 容器，它本身执行蓝绿部署，使用您使用`aws ecr`命令提供的参数。这个工作原理的细节超出了本书的范围。要查看更多使用原生`aws ecr`命令的示例，请参考`aws-samples`存储库，网址为[github.com/aws-samples/ecs-blue-green-deployment](https://github.com/aws-samples/ecs-blue-green-deployment)。

请注意，`duluca/ecs-deploy-fargate`蓝绿部署脚本是原始`silintl/ecs-deploy`镜像的一个分支，经过修改以支持使用 PR `https://github.com/silinternational/ecs-deploy/pull/129`进行 AWS ECS Fargate。一旦`silintl/ecs-deploy`合并了这一更改，我建议您在蓝绿部署中使用`silintl/ecs-deploy`：

```ts
package.json
...
"scripts": {
  ...
  "aws:release": "run-s -cs aws:login docker:publish aws:deploy"
}
...
```

最后，`npm run aws:release`简单地按正确顺序运行`aws:login`，`docker:publish`从`npm Scripts for Docker`和`aws:deploy`命令。

# 发布

您的项目已配置为在 AWS 上部署。您主要需要使用我们创建的两个命令来构建和发布图像：

1.  执行`docker:debug`来测试、构建、标记、运行、跟踪并在浏览器中启动您的应用程序以测试图像：

```ts
$ npm run docker:debug
```

1.  执行`aws:release`以配置 Docker 登录到 AWS，发布您的最新图像构建，并在 ECS 上发布它：

```ts
 $ npm run aws:release
```

1.  验证您的任务是否在服务级别上运行：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/0a2d364f-6765-47de-ae97-71986360135a.png)AWS ECS 服务确保运行计数和期望计数相同。

1.  验证您的实例是否在任务级别上运行：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/e562d999-718c-45a3-9e2d-cbf41f192aab.png)AWS ECS 任务实例

请注意公共 IP 地址并导航到它；例如，`http://54.164.92.137`，您应该看到您的应用程序或 LemonMart 正在运行。

1.  验证负载均衡器设置在 DNS 级别上是否正确。

1.  导航到 ALB DNS 地址，例如`http://lemon-mart-alb-1871778644.us-east-1.elb.amazonaws.com`，并确认应用程序呈现如下：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/490c9bc1-8041-4500-a606-eab6e8ce98fe.png)在 AWS Fargate 上运行的 LemonMart

Et voilà！您的网站应该已经上线并运行。

在随后的发布中，您将能够观察蓝绿部署的实际操作，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/cf3d456c-09af-4193-94a8-a38efc501f23.png)蓝绿部署期间的 AWS 服务

有两个正在运行的任务，正在提供两个新任务。在验证新任务的同时，运行计数将上升到四个任务。在验证新任务并且从旧任务中排出连接之后，运行计数将返回到两个。

您可以通过配置 CircleCI 与您的 AWS 凭据，使用安装了`awscli`工具并运行`npm Scripts for AWS`的容器，来自动化您的部署。通过这种技术，您可以实现对暂存环境的持续部署或对生产环境的持续交付。

这一切都很好，但是一个基本的高可用配置会花费多少？让我们在下一节中进行检查。

# AWS 计费

我的在 AWS Fargate 上高可用的 LemonMart 部署大约每月花费大约 45 美元。以下是详细信息：

| **描述** | **     成本** |
| --- | --- |
| 亚马逊简单存储服务（S3） |          $0.01 |
| AWS 数据传输 |          $0.02 |
| 亚马逊云监控 |          $0.00 |
| 亚马逊 EC2 容器服务（ECS Fargate） |        $27.35 |
| 亚马逊弹性计算云（EC2 负载均衡器实例） |        $16.21 |
| 亚马逊 EC2 容器注册表（ECR） |          $0.01 |
| 亚马逊路由 53 |          $0.50 |
| **总计** | **       $44.10** |

请注意，账单非常详细，但确实准确列出了我们最终使用的所有 AWS 服务。主要成本是在**EC2 容器服务**（**ECS**）上运行我们的 Web 服务器的两个实例，以及在**弹性计算云**（**EC2**）上运行负载均衡器。客观地说，每月 45 美元似乎是托管一个 Web 应用程序的很多钱。如果愿意自己设置专用 EC2 服务器的集群，并且可以选择 1 年或 3 年的付款周期，最多可以节省 50%的费用。在 Heroku 上，类似的高可用部署以每月 50 美元起步，并提供其他丰富的功能。同样，在 Zeit Now 上，两个实例的成本为每月 30 美元。请注意，Heroku 和 Zeit Now 都不提供对物理上不同可用区的访问。另一方面，Digital Ocean 允许您在不同的数据中心中设置服务器；但是，您必须编写自己的基础设施。每月 15 美元，您可以在三台服务器上设置自己的高可用集群，并能够在上面托管多个站点。

# 总结

在本章中，您了解了在正确保护您的 AWS 账户时的微妙之处和各种安全考虑因素。我们讨论了调整基础设施的概念。您以隔离的方式进行了简单的负载测试，以找出两个 Web 服务器之间性能的相对差异。拥有优化的 Web 服务器后，您配置了 AWS ECS Fargate 集群，以实现高可用的云基础设施。使用 AWS 的 npm 脚本，您学会了如何编写可重复且可靠的无停机蓝绿部署。最后，您了解了在 AWS 和其他云提供商（如 Heroku、Zeit Now 和 Digital Ocean）上运行基础设施的基本成本。

在下一章，我们将完成对全栈 Web 开发人员在部署 Web 应用程序时应该了解的各种主题的广度的覆盖。我们将向 LemonMart 添加 Google Analytics 以测量用户行为，利用高级负载测试来了解部署良好配置的可扩展基础设施的财务影响，并使用自定义分析事件来测量重要应用程序功能的实际使用情况。


# 第十二章：谷歌分析和高级云运维

您已经设计、开发并部署了一个世界级的 Web 应用程序；然而，这只是您应用程序故事的开始。网络是一个不断发展的、生机勃勃的环境，需要关注才能继续成功地作为一个业务。在第十一章中，*AWS 上高可用云基础设施*，我们已经介绍了云基础设施的基本概念和所有权成本。在本章中，我们将更深入地了解用户如何实际使用谷歌分析来创建真实的负载测试，以模拟实际用户行为，了解单个服务器实际容量。了解单个服务器的容量，我们可以微调我们的基础设施扩展以减少浪费，并讨论各种扩展策略的影响。最后，我们将介绍高级分析概念，如自定义事件，以获得对用户行为更细粒度的理解和跟踪。

在本章中，您将了解以下主题：

+   谷歌分析

+   谷歌标签管理器

+   预算和扩展

+   高级负载测试以预测容量

+   自定义分析事件

在整个章节中，您将设置这些：

+   谷歌分析账户

+   谷歌标签管理器账户

+   OctoPerf 账户

# 收集分析

现在我们的网站已经上线运行，我们需要开始收集指标来了解它的使用情况。指标是操作 Web 应用程序的关键。

谷歌分析有许多方面；主要的三个如下：

1.  获取，衡量访问者如何到达您的网站

1.  行为，衡量访问者如何与您的网站互动

1.  转化，衡量访问者如何在您的网站上完成各种目标

让我们来看看我的网站[TheJavaScriptPromise.com](http://TheJavaScriptPromise.com)的行为|概述：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/50c99fe0-c01a-4f08-90a9-5ac2b43e72d6.png)谷歌分析行为概述

[TheJavaScriptPromise.com](http://TheJavaScriptPromise.com)是一个简单的单页面 HTML 网站，所以指标非常简单。让我们来看看屏幕上的各种指标：

1.  页面浏览显示访问者数量

1.  独立页面浏览显示独立访问者的数量

1.  平均页面停留时间显示每个用户在网站上花费的时间

1.  跳出率显示用户在不浏览子页面或以任何方式与站点进行交互的情况下离开站点，例如单击具有自定义事件的链接或按钮

1.  % 退出表示用户在查看特定页面或一组页面后离开站点的频率

在 2017 年，该网站大约有 1,090 名独立访客，平均每位访客在网站上花费约 2.5 分钟或 157 秒。鉴于这只是一个单页面站点，跳出率和%退出指标在任何有意义的方式上都不适用。稍后，我们将使用这些数字来计算每用户成本。

除了页面浏览之外，Google Analytics 还可以捕获特定事件，例如单击触发服务器请求的按钮。然后可以在事件|概述页面上查看这些事件，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/e1e8eabd-a481-4032-bff0-0eb5b2a9b28b.png)Google Analytics 事件概述

在服务器端也可以捕获指标，但这将提供请求随时间变化的统计数据。您将需要额外的代码和状态管理来跟踪特定用户的行为，以便计算用户随时间变化的统计数据。通过在客户端使用 Google Analytics 实施此类跟踪，您可以更详细地了解用户的来源、他们的行为、是否成功以及何时离开您的应用程序，而不会给后端添加不必要的代码复杂性和基础设施负载。

# 将 Google Tag Manager 添加到 Angular 应用程序

让我们开始在您的 Angular 应用程序中捕获分析数据。Google 正在逐步淘汰随 Google Analytics 一起提供的传统`ga.js`和`analytics.js`产品，而是使用其新的、更灵活的全局站点标签`gtag.js`，该标签与 Google 标签管理器一起提供。这绝不是对 Google Analytics 的结束；相反，它是朝着更易于配置和管理的分析工具的转变。全局站点标签可以通过 Google 标签管理器远程配置和管理。标签是交付给客户端的 JavaScript 跟踪代码片段，它们可以启用对新指标的跟踪，并与多个分析工具集成，而无需更改已部署的代码。您仍然可以继续使用 Google Analytics 来分析和查看您的分析数据。Google 标签管理器的另一个主要优势是它是版本控制的，因此您可以在不害怕对分析配置造成任何不可逆转的损害的情况下尝试不同类型的标签，这些标签在各种条件下被触发。

# 设置 Google 标签管理器

让我们从为您的应用程序设置 Google 标签管理器帐户开始：

1.  登录到[GoogleTagManager.com](https://googletagmanager.com)的 Google 标签管理器

1.  按照以下步骤添加一个带有 Web 容器的新帐户：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a2d3c667-536f-4c2f-863c-62072247bbd9.png)Google 标签管理器

1.  按照指示将生成的脚本粘贴到您的`index.html`的顶部`<head>`和`<body>`部分附近：

```ts
src/index.html
<head>
<!-- Google Tag Manager -->
<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-56D4F6K');</script>
<!-- End Google Tag Manager -->
...
</head>
<body>
<!-- Google Tag Manager (noscript) -->
<noscript><iframe src="https://www.googletagmanager.com/ns.html?id=GTM-56D4F6K"
height="0" width="0" style="display:none;visibility:hidden"></iframe></noscript>
<!-- End Google Tag Manager (noscript) -->
<app-root></app-root>
</body>
```

请注意，`<noscript>`标签仅在用户在其浏览器中禁用 JavaScript 执行时才会执行。这样，我们可以收集这些用户的指标，而不是对他们的存在一无所知。

1.  提交并发布您的标签管理器容器

1.  您应该看到您的标签管理器的初始设置已完成，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/a421aa04-332d-4966-8c6e-d8615847ec3d.png)已发布的标签

1.  验证您的 Angular 应用程序是否没有任何错误运行。

请注意，如果您不发布您的标签管理器容器，您将在`dev`控制台或网络选项卡中看到 404 错误加载`gtm.js`。

# 设置 Google Analytics

现在，让我们通过 Google Analytics 生成一个跟踪 ID：

1.  登录到[analytics.google.com](https://analytics.google.com)的 Google Analytics

1.  打开管理控制台，如下面截图中指出的*齿轮*图标：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/382cd801-dc47-4661-809a-d637a7e4c15c.png)Google Analytics 管理控制台

1.  创建一个新的分析帐户

1.  使用图像中的箭头作为指南：

1.  添加一个名为`LemonMart`的新属性

1.  根据您的偏好配置属性

1.  点击跟踪代码

1.  复制以`UA-xxxxxxxxxx-1`开头的跟踪 ID

1.  忽略提供的`gtag.js`代码

# 在标签管理器中配置 Google Analytics 标签

现在，让我们将我们的 Google Analytics ID 连接到 Google Tag Manager：

1.  在[tagmanager.google.com](https://tagmanager.google.com)上，打开工作区选项卡

1.  点击添加新标签

1.  将其命名为`Google Analytics`

1.  点击标签配置并选择通用分析

1.  在 Google Analytics 设置下，添加一个新变量

1.  在上一节中复制的跟踪 ID 粘贴

1.  点击触发器并添加所有页面触发器

1.  点击保存，如下截图所示：

！[](Images/d19ac69c-9873-438e-9464-efa05b4ec2b1.png)创建 Google Analytics 标签

1.  提交并发布您的更改，并观察版本摘要，其中显示了 1 个标签：

！[](Images/5f1211b6-18b0-445a-ae28-a6ef095c88f7.png)显示一个标签的版本摘要

1.  现在刷新您的 Angular 应用程序，在`/home`路由上

1.  在私人窗口中，打开您的 Angular 应用程序的新实例，并导航到`/manager/home`路由

1.  在[analytics.google.com](https://analytics.google.com)上，打开实时|概览窗格，如下所示：

！[](Images/2ec54d66-0dd0-4c50-ad8a-c4b415b25713.png)Google Analytics 实时概览

1.  请注意，正在跟踪两个活跃用户

1.  在活跃页面顶部，您应该看到用户所在的页面

通过同时利用 Google Tag Manager 和 Google Analytics，我们能够在不更改 Angular 应用程序内部任何代码的情况下完成页面跟踪。

**搜索引擎优化**（**SEO**）是分析的重要部分。为了更好地了解爬虫如何感知您的 Angular 站点，请使用 Google 搜索控制台，网址为[`www.google.com/webmasters/tools`](https://www.google.com/webmasters/tools)，来识别优化。此外，考虑使用 Angular Universal 来在服务器端呈现某些动态内容，以便爬虫可以索引您的动态数据源并将更多流量带到您的站点。

# 预算和扩展

在第十一章的 AWS 计费部分，《在 AWS 上构建高可用云基础设施》，我们涵盖了运行 Web 服务器的月度成本，从每月 5 美元到每月 45 美元，从单服务器实例方案到高可用基础设施。对于大多数需求，预算讨论将从这个月度数字开始并结束。您可以执行负载测试，如高级负载测试部分建议的那样，来预测每台服务器的用户容量，并大致了解您可能需要多少服务器。在一个动态扩展的云环境中，有数十台服务器全天候运行，这是计算预算的一种过于简单化的方式。

如果您经营规模相当大的网络资产，事情变得复杂。您将在不同技术堆栈上运行多个服务器，提供不同的用途。很难判断或证明为看似过剩的容量或不必要的高性能服务器留出多少预算。不知何故，您需要能够沟通您的基础设施的效率，考虑到您服务的用户数量，并确保您的基础设施经过调整，以便您不会因为应用程序无响应或因为使用的容量超出需要而失去用户或支付过多。因此，我们将采取以用户为中心的方法，并将我们的 IT 基础设施成本转化为业务和您组织的营销部门可以理解的每用户成本指标。

在下一节中，我们将调查计算基础设施每用户成本的含义，以及当云扩展应用时这些计算如何改变，以我的一个网站为例。

# 计算每用户成本

我们将利用来自 Google Analytics 的行为指标，目标是在一定时间内计算每个用户的成本：

**每用户成本**![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/d999dbd8-28df-41cf-a125-8aa31e280ec7.png)

使用之前的[TheJavaScriptPromise.com](http://TheJavaScriptPromise.com)数据，让我们将数据代入公式计算*perUserCost/month*。

这个网站部署在 DigitalOcean 的 Ubuntu 服务器上，所以包括每周备份在内的月度基础设施成本为每月 6 美元。从 Google Analytics 中，我们知道 2017 年有 1,090 名独立访客：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/4d389358-99b2-4e63-a610-c31d6bf4b788.png)

2017 年，我每个用户支付了 7 美分。花得值吗？每月 6 美元，我不介意。在 2017 年，[TheJavaScriptPromise.com](http://thejavascriptpromise.com/)部署在传统的服务器设置上，作为一个静态站点，不会动态扩展或缩减。这些条件使得使用独立访客指标并找到每个用户成本非常简单。这种简单性不仅使得容易计算，也导致了基础设施的不佳。如果我在相同的基础设施上为 100 万用户提供服务，我的成本将达到每年 7 万美元。如果我通过 Google 广告每 1000 个用户赚取 100 美元，我的网站每年将赚取 10 万美元。税收、开发费用和不合理的托管费用后，该运营很可能会亏损。

如果您利用云扩展，其中实例可以根据当前用户需求动态扩展或缩减，那么前面的公式很快就会变得无用，因为您必须考虑到预配时间和目标服务器利用率。预配时间是您的云提供商从头开始启动新服务器所需的时间。目标服务器利用率是给定服务器的最大使用度量标准，当达到扩展警报时，必须发送新服务器准备就绪，以防当前服务器达到最大容量。为了计算这些变量，我们必须对我们的服务器执行一系列负载测试。

页面浏览是一种过于简单化的方式来确定 Angular 等单页应用程序中的用户行为，其中页面浏览不一定与请求相关联。如果我们仅基于页面浏览执行负载测试，我们将无法真实模拟您的平台在负载下的性能。

用户行为，或者用户实际使用您的应用程序的方式，可以极大地影响您的性能预测，并且会导致预算数字大幅波动。您可以使用 Google Analytics 自定义事件来捕获一系列复杂的操作，这些操作导致平台提供各种类型的请求。在本章的后面，我们将探讨如何在*测量实际使用*部分中测量实际使用情况。

最初，您将不会拥有任何上述指标，您可能拥有的任何指标都将在您对软件或硬件堆栈进行重大更改时无效。因此，必须定期执行负载测试，以模拟真实的用户负载。

# 高级负载测试

为了能够预测容量，我们需要运行负载测试。在第十一章中，《AWS 上高可用云基础设施》，我讨论了一种简单的负载测试技术，即向服务器发送一堆网络请求。在相对比较的情况下，这对于测试原始功率效果很好。然而，实际用户以不同的间隔生成数十个请求，当他们浏览您的网站时，会导致对后端服务器的各种 API 调用。

我们必须能够模拟虚拟用户，并将大量用户释放到我们的服务器上，以找到服务器的瓶颈。 OctoPerf 是一个易于使用的服务，可执行此类负载测试，位于[`octoperf.com`](https://octoperf.com)。 OctoPerf 提供了一个免费的套餐，允许 50 个并发用户/测试在无限次测试运行中使用两个负载生成器：

1.  创建一个 OctoPerf 账户

1.  登录并为 LemonMart 添加一个新项目，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/c9f916a9-cbce-42e7-a592-d950c1b0cddf.png)OctoPerf 添加项目

OctoPerf 允许您创建具有不同使用特征的多个虚拟用户。由于它是基于 URL 的设置，任何基于点击的用户操作也可以通过直接调用应用程序服务器 URL 与测试参数来模拟。

1.  创建两个虚拟用户：一个作为“经理”，导航到基于经理的页面，第二个作为`POS`用户，只能使用 POS 功能

1.  单击“创建场景”：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/e7ba3d65-b1d4-4b86-a4a5-e0ac810e530f.png)POS 用户场景

1.  将场景命名为“晚高峰”

1.  您可以添加一些经理和 POS 用户，如图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/94f055b8-086d-4139-953e-c7dc1d6566a6.png)晚高峰场景

1.  单击“启动 50 个 VUs”按钮开始负载测试

您可以实时观察到达到的用户数量和每秒点击数，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/1a83b924-c8f2-4ff8-b161-644afa539427.png)晚高峰负载测试进行中

1.  ECS 服务指标还给我们提供了实时利用率的高层次概念，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/08c773f1-a8eb-497b-b4b3-779110666916.png)ECS 实时指标

1.  分析负载测试结果。

您可以通过单击 ECS 服务指标中的 CPU 利用率链接或导航到 CloudWatch |指标部分来从 ECS 中获得更准确的结果，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/57c634ba-85f7-49ea-a4be-adff93c320f6.png)AWS CloudWatch 指标

如前图所示，CPU 利用率在持续 50 个用户负载的 10 分钟内保持在 1.3%左右。在此期间，没有请求错误，如 OctoPerf 的统计摘要所示：

！[](Images/2030e153-a12e-45b1-acc6-0ae6b8ac7261.png)OctoPerf 统计摘要

理想情况下，我们会测量每秒最大用户数，直到出现错误。然而，考虑到只有 50 个虚拟用户和我们已经拥有的信息，我们可以预测在 100%利用率下可以处理多少用户：

！[](Images/187cb266-4556-4d6a-8342-024c2f6a8a5a.png)

我们的负载测试结果显示，我们的基础设施可以处理每秒 3,846 个用户。根据这些信息，我们可以在下一节中计算可扩展环境中的每个用户成本。然而，性能和可靠性是相辅相成的。您选择如何设计基础设施也将提供重要的预算信息，因为您需要的可靠性水平将决定您必须始终保留的实例的最低数量。

# 可靠的云扩展

可靠性可以用您组织的恢复点目标（RPO）和恢复时间目标（RTO）来表达。 RPO 代表您愿意丢失多少数据，而 RTO 代表在发生故障时您可以多快重建基础设施。

假设你经营一家电子商务网站。每个工作日中午左右，你的销售达到峰值。每当用户将商品添加到购物车时，你会将商品存储在服务器端缓存中，以便用户可以在家后继续他们的购物狂欢。此外，你每分钟处理数百笔交易。生意很好，你的基础设施扩展得很好，一切都运行顺利。与此同时，一只饥饿的老鼠或一个过度充电的闪电云决定袭击你的数据中心。最初，一个看似无害的电源单元停机了，但没关系，因为附近的电源单元可以接管工作。然而，这是午餐高峰期；数据中心上的其他网站也面临着高流量。结果，几个电源单元过热并失败。没有足够的电源单元来接管工作，因此，电源单元接连过热并逐个失败，引发了一系列故障，最终导致整个数据中心崩溃。与此同时，你的一些用户刚刚点击了“添加到购物车”，其他用户点击了“支付”按钮，还有一些用户正要到达你的网站。如果你的 RPO 是一小时，意味着你每小时持久化一次购物车缓存，那么你可能会失去那些夜间购物者的宝贵数据和潜在销售额。如果你的 RTO 是一小时，那么你需要最多一个小时才能让你的网站重新上线运行，你可以放心，那些刚刚点击购买按钮或到达无响应网站的客户大部分当天都不会在你的网站上购买商品。

深思熟虑的 RPO 和 RTO 是一个关键的业务需求，但它们也必须与合适的基础设施配合，以便以一种经济有效的方式实现你的目标。AWS 由全球两打以上的地区组成，每个地区至少包含它们的可用区（AZs）。每个 AZ 都是一个物理上分离的基础设施，不会受到另一个 AZ 故障的影响。

在 AWS 上的高可用配置意味着你的应用程序至少在两个 AZ 上运行，因此，如果一个服务器实例失败，甚至整个数据中心失败，你已经在一个物理上分离的数据中心上有另一个实例可以无缝接管传入的请求。

容错架构意味着您的应用部署在多个区域。即使整个区域因自然灾害、分布式拒绝服务（DDoS）攻击或糟糕的软件更新而崩溃，您的基础设施仍然可以保持稳定，并能够响应用户请求。通过层层安全和错位备份，您的数据得到了保护。

AWS 拥有出色的服务，如 Shield 用于保护针对您网站的 DDoS 攻击，Pilot Light 服务可在另一个区域保持最小基础设施处于休眠状态，如果需要，可以扩展到完整容量，同时保持运营成本低廉，以及 Glacier 服务以经济的方式存储大量数据长时间。

高可用配置将始终需要至少两个实例在多个可用区设置中。对于容错设置，您需要至少在两个区域中拥有两个高可用配置。大多数 AWS 云服务，如用于数据存储的 DynamoDB 或用于缓存的 Redis，默认情况下都是高可用的，包括无服务器技术，如 Lambda。Lambda 按使用量收费，并且可以以成本有效的方式扩展以满足任何需求。如果您可以将繁重的计算任务转移到 Lambda，您可以大大减少服务器利用率和扩展需求。在规划基础设施时，您应考虑所有这些变量，以建立适合您需求的可扩展环境。

# 可扩展环境中的每个用户成本

在可扩展的环境中，你不能计划 100%的利用率。要为新服务器提供服务需要时间。利用率达到 100%的服务器无法及时处理额外的请求，这会导致用户视角下的请求丢失或错误。因此，相关服务器必须在达到 100%利用率之前发送触发器，以避免请求丢失。在本章的前面，我建议在扩展之前将目标利用率设定为 60-80%。确切的数字将高度依赖于您特定的软件和硬件堆栈选择。根据您的自定义利用率目标，我们可以计算出您的基础设施预计平均每个实例需要为多少用户提供服务。利用这些信息，您可以计算出更准确的每用户成本，这应该可以根据您的特定需求来正确规划您的 IT 预算。低于预算和超出预算一样糟糕。您可能会放弃增长、安全性、数据、可靠性和弹性，这是不可接受的。

在下一节中，我们将详细介绍如何计算最佳目标服务器利用率指标，以便您可以计算更准确的每用户成本；然后，我们将探讨在预定时间框架和软件部署期间可能发生的扩展。

# 计算目标服务器利用率。

首先，计算您的自定义服务器利用率目标，这是您的服务器承受增加负载并触发新服务器提供服务的点，以便原始服务器不会达到 100%的利用率并丢失请求。考虑这个公式：

**目标利用率**![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/744f4ac5-b88d-4050-bc72-5ea63b0da856.png)

让我们通过一个具体的例子来演示这个公式是如何工作的：

1.  对您的实例进行负载测试，以找出每个实例的用户容量：*负载测试结果：* 3,846 用户/秒

每秒请求和每秒用户并不相等，因为用户需要多次请求才能完成一个动作，可能每秒执行多个请求。高级负载测试工具如 OctoPerf 是必要的，以执行真实和多样化的工作负载，并测量用户容量和请求容量。

1.  测量实例提供速度，从创建/冷启动到首次满足请求：*测量实例提供速度：* 60 秒

为了测量这个速度，你可以放下秒表。根据你的确切设置，AWS 在 ECS 服务事件选项卡、CloudWatch 和 CloudTrail 中提供事件和应用程序日志，以关联足够的信息来确定何时请求了一个新实例以及实例准备好满足请求需要多长时间。例如，在 ECS 服务事件选项卡中，将目标注册事件作为开始时间。一旦任务开始，点击任务 ID 查看创建时间。使用任务 ID，在 CloudWatch 中检查任务的日志，以查看任务为第一个网络请求提供服务的时间作为结束时间，然后计算持续时间。

1.  测量 95 百分位数用户增长率，排除已知容量增加：*95 百分位数用户增长率：*每秒 10 个用户

如果你没有先前的指标，最初定义用户增长率将是最好的一个合理猜测。然而，一旦开始收集数据，你可以更新你的假设。此外，要以一种成本效益的方式运营一个可以应对任何想象得到的异常值的基础设施是不可能的。根据你的指标，应该有意识地做出一个商业决策，忽略哪个异常值百分位数作为可接受的商业风险。

1.  让我们将数字代入公式中：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/b7f31ebc-1145-43a1-873b-0a6b6930de62.png)

自定义目标利用率，向下取整，将是 84%。将扩展触发器设置为 84%将避免实例过度配置，同时避免丢弃用户请求。

有了这个自定义的目标利用率，让我们考虑扩展后更新每用户成本公式：

**带有扩展的每用户成本**！[](Images/abb6593b-cac6-4b06-a8c9-f779bf5bd9a9.png)

因此，如果我们的基础设施成本是每月 100 美元，为 150 个用户提供服务，在 100%的利用率下，你可以计算每用户成本为每月$0.67/用户。如果考虑到扩展，成本将如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/79087df7-be63-43ad-994a-e695047def40.png)

在不丢弃请求的情况下进行扩展将使每用户每月的成本从原始的$0.67 增加 16%，达到$0.79。然而，重要的是要记住，你的基础设施不会总是如此高效，在较低的利用率目标下，或者在配置错误的情况下，扩展触发器的成本很容易翻倍、翻三倍或者翻四倍。这里的最终目标是找到甜蜜点，这样你就会支付合适的每用户金额。

没有一个固定的每用户成本是您应该瞄准的。然而，如果您运行的服务在考虑了所有其他运营成本和利润率之后向用户收取每月 5 美元，然后您仍然有额外的预算 *和* 您的用户抱怨性能不佳，那么您的支出不足。然而，如果您在侵蚀利润率，甚至是亏损，那么您可能是在过度支出，或者您可能需要重新考虑您的商业模式。

还有一些其他因素可能会影响您的每个用户成本，比如蓝绿部署。您还可以通过利用预先安排的供应来提高扩展的效率。

# 预先安排的供应

动态扩展然后再收缩是定义云计算的特点。然而，目前可用的算法仍然需要一些规划，如果您知道一年中的某些天、周或月需要非同寻常地更高的资源容量。在新流量突然涌入时，您的基础设施将尝试动态扩展，但如果流量增长的速度是对数的，即使是优化的服务器利用率目标也无济于事。服务器经常会达到并以 100%的利用率运行，导致请求被丢弃或出现错误。为了防止这种情况发生，您应该在这些可预测的高需求时期主动提供额外的容量。

# 蓝绿部署

在第十一章中，*AWS 上的高可用云基础设施*，您配置了无停机的蓝绿部署。蓝绿部署是可靠的代码部署，可以确保您的网站持续运行，同时最大限度地减少糟糕部署的风险。

假设您有一个高可用的部署，意味着任何时候都有两个实例处于活动状态。在蓝绿部署期间，将会提供两个额外的实例。一旦这些额外的实例准备好满足请求，它们的健康状况将使用您预定义的健康指标来确定。

如果您的新实例被发现是健康的，这意味着它们是正常工作的。在这段时间内，比如 5 分钟，原始实例中的连接被排空并重新路由到新实例。此时，原始实例被取消供应。

如果发现新实例不健康，那么这些新实例将被取消配置，导致部署失败。然而，服务将保持可用状态，因为原始实例将保持完整，并在整个过程中继续为用户提供服务。

# 使用指标修订估算

负载测试和预测用户增长率可以让您了解您的系统在生产中可能的行为。收集更精细的指标和数据对于修订您的估算并确定更准确的 IT 预算至关重要。

# 测量实际使用

正如我们之前讨论的那样，仅跟踪页面浏览量并不能反映用户发送给服务器的请求量。使用 Google Tag Manager 和 Google Analytics，您可以轻松跟踪不仅仅是页面浏览量。

截至发布时间，以下是您可以在各个类别中配置的一些默认事件。此列表将随时间增长：

+   页面查看：用于跟踪用户在页面资源加载和页面完全呈现时是否停留在页面上：

+   页面查看，在第一次机会时触发

+   DOM 准备就绪，当 DOM 结构加载完成时

+   窗口加载完成，当所有元素都加载完成时

+   点击：用于跟踪用户与页面的点击交互：

+   所有元素

+   只有链接

+   用户参与度：跟踪用户行为：

+   元素可见性，元素是否已显示

+   表单提交，是否提交了表单

+   滚动深度，他们在页面上滚动了多远

+   YouTube 视频，如果播放了嵌入的 YouTube 视频

+   其他事件跟踪：

+   自定义事件：由程序员定义，用于跟踪单个或多步事件，例如用户完成结账流程的步骤

+   历史更改：用户是否在浏览器历史记录中导航

+   JavaScript 错误：是否生成了 JavaScript 错误

+   计时器：触发或延迟基于时间的分析事件

大多数这些事件不需要额外的编码来实现，因此我们将实现一个自定义事件，以演示如何使用自定义编码捕获任何单个或一系列事件。通过一系列事件捕获工作流程可以揭示您应该将开发工作重点放在哪里。

有关 Google Tag Manager 事件、触发器或技巧的更多信息，我建议您查看 Simo Ahava 在[www.simoahava.com](http://www.simoahava.com)的博客。

# 创建自定义事件

在此示例中，我们将捕获当客户成功结账并完成销售时的事件。我们将实现两个事件，一个用于结账启动，另一个用于交易成功完成时：

1.  登录到您的 Google 标签管理器工作区，网址为[tagmanager.google.com](https://tagmanager.google.com)

1.  在触发器菜单下，单击新建，如图所示：

创建`checkout`函数，在进行服务调用之前调用`checkoutInitiated`

1.  命名您的触发器

1.  单击空的触发器卡以选择事件类型

1.  选择自定义事件

1.  创建名为`checkoutCompleted`的自定义事件，如图所示：

现在，让我们编辑 Angular 代码来触发事件：

通过选择“一些自定义事件”选项，您可以限制或控制特定事件的收集，即仅当在特定页面或域上时，例如在`lemonmart.com`上。在下面的屏幕截图中，您可以看到一个自定义规则，该规则将过滤掉在`lemonmart.com`上未发生的任何结账事件，以清除开发或测试数据：

一些自定义事件

1.  保存您的新事件

1.  为名为`checkoutInitiated`的事件重复此过程

1.  添加两个新的 Google Analytics 事件标签，如图所示：

新的自定义事件标签

1.  配置事件并将您创建的相关触发器附加到其中，如图所示：

标签管理器工作区

1.  提交并发布您的工作区

我们现在准备在我们的分析环境中接收自定义事件。

# 在 Angular 中添加自定义事件

可选地，您可以直接在模板中添加`onclick`事件处理程序，例如在结账按钮上添加`onclick="dataLayer.push({'event': 'checkoutInitiated'})"`。这将`checkoutInitiated`事件推送到由`gtm.js`提供的`dataLayer`对象中。

1.  观察带有结账按钮的 POS 模板：

```ts
src/app/pos/pos/pos.component.html
...
  <button mat-icon-button (click)="checkout({amount: 12.25})">
    <mat-icon>check_circle</mat-icon>
  </button>
...
```

圆形结账按钮位于以下图表的左下角：

POS 页面与结账按钮

1.  在 POS 组件中，声明您打算推送的`dataLayer`事件的接口：

```ts
src/app/pos/pos/pos.component.ts ...
interface IEvent {
  event: 'checkoutCompleted' | 'checkoutInitiated'
}
declare let dataLayer: IEvent[]
...
export class PosComponent implements OnInit {
  ...
```

1.  自定义结账事件

1.  使用`setTimeout`模拟一个虚假交易，并在超时结束时调用`checkoutCompleted`事件：

```ts
src/app/pos/pos/pos.component.ts export class PosComponent implements OnInit {
...
checkout(transaction) {
    dataLayer.push({
      event: 'checkoutInitiated',
    })

    setTimeout(() => {
      dataLayer.push({
        event: 'checkoutCompleted',
      })
    }, 500)
  }
}
```

在实际实现中，只有在服务调用成功时才会调用`checkoutCompleted`。为了不错过分析收集过程中的任何数据，还要考虑覆盖失败情况，例如添加多个覆盖各种失败情况的`checkoutFailed`事件。

现在，我们准备看分析结果。

1.  在 POS 页面上，点击结账按钮

1.  在 Google Analytics 中，观察实时|事件选项卡，以查看事件发生时的事件。

1.  5-10 分钟后，这些事件也会显示在行为|事件选项卡下，如下所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/30f98116-4cc6-4087-8990-a5416a5a8975.png)Google Analytics 顶级事件

使用自定义事件，您可以跟踪站点上发生的各种微妙的用户行为。通过收集`checkoutInitiated`和`checkoutCompleted`事件，您可以计算有多少启动的结账最终完成的转化率。在销售点系统的情况下，该比率应该非常高；否则，这意味着您可能存在系统性问题。

# 高级分析事件

在每个事件中收集额外的元数据是可能的，例如在启动结账时收集付款金额或类型，或在完成结账时收集`transactionId`。

要使用这些更高级的功能，我建议您查看`angulartics2`，该工具可以在[`www.npmjs.com/package/angulartics2`](https://angulartics.github.io/angulartics2/)找到。`angulartics2`是一个供应商无关的 Angular 分析库，可以使用流行的供应商（如 Google Tag Manager、Google Analytics、Adobe、Facebook、百度等）实现独特和细粒度的事件跟踪需求，如该工具主页上所示：

![](https://github.com/OpenDocCN/freelearn-angular-zh/raw/master/docs/ng6-entrd-webapp/img/c80fff80-b31f-4536-90e6-f6388e6cab25.png)Angulartics2

`angulartics2`与 Angular 路由器和 UI-Router 集成，可以根据每个路由实现自定义规则和异常。该库使实现自定义事件和启用数据绑定的元数据跟踪变得容易。查看以下示例：

```ts
example
<div angulartics2On="click" angularticsEvent="DownloadClick" angularticsCategory="{{ song.name }}" [angularticsProperties]="{label: 'Fall Campaign'}"></div>
```

我们可以跟踪名为`DownloadClick`的点击事件，该事件将附加一个`category`和一个`label`，以便在 Google Analytics 中进行丰富的事件跟踪。

通过高级分析，您可以使用实际使用数据来指导您改进或托管您的应用程序。这个主题总结了从本书开始时创建铅笔草图模型的旅程，涵盖了今天的全栈 Web 开发人员必须熟悉的各种工具、技术和技术。我们深入研究了 Angular、Angular Material、Docker 和自动化，以使您成为最高效的开发人员，交付最高质量的 Web 应用程序，同时在这一过程中处理了许多复杂性。祝你好运！

# 总结

在本章中，您已经丰富了开发 Web 应用程序的知识。您学会了如何使用 Google Tag Manager 和 Google Analytics 来捕获您的 Angular 应用程序的页面浏览量。使用高级指标，我们讨论了如何计算每个用户基础设施的成本。然后，我们调查了高可用性和扩展性对预算的影响的细微差别。我们涵盖了负载测试复杂用户工作流程，以估算任何给定服务器可以同时托管多少用户。利用这些信息，我们计算了目标服务器利用率，以微调您的扩展设置。

我们所有的预发布计算大多是估计和经过深思熟虑的猜测。我们讨论了您可以使用哪些指标和自定义事件来衡量应用程序的实际使用情况。当您的应用程序上线并开始收集这些指标时，您可以更新您的计算，以更好地了解您基础设施的可行性和负担能力。

在本书的过程中，我已经表明，Web 开发远不止是编写网站。在本书的前半部分，我们涵盖了从流程、设计、方法、架构到开发环境、您使用的库和工具的各种主题，包括基本的 Angular 平台和 Angular Material，最后使用 Zeit Now 在 Web 上部署您的应用程序。

在书的下半部分，我们采用了“路由器优先”方法来设计、架构和实现一个大型的业务应用程序，涵盖了你在现实生活中可能遇到的大多数主要设计模式。在这个过程中，我们涵盖了单元测试、Docker、使用 CircleCI 进行持续集成、使用 Swagger 设计 API、使用 Google Tag Manager 收集分析数据，以及在 AWS 上部署高可用性应用程序。当你掌握了这些各种技能和技术，你将成为一个真正的全栈 web 开发人员，能够利用 Angular 交付小型和大型 web 应用程序。
