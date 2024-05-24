# Cypress 端到端 Web 测试（二）

> 原文：[`zh.annas-archive.org/md5/CF3AC9E3793BF8801DD5A5B999C00FD9`](https://zh.annas-archive.org/md5/CF3AC9E3793BF8801DD5A5B999C00FD9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 TDD 方法编写 Cypress 测试

现在我们已经完成了本书的*第一部分* - 也就是*作为前端应用的端到端测试解决方案的 Cypress* - 是时候转向本书的*第二部分*了，它将专注于*使用 TDD 方法进行自动化测试*。

在我们开始使用**TDD**（测试驱动开发）方法编写 Cypress 测试之前，我们需要了解如何正确地编写 Cypress 测试。这在本书的前几章中已经涵盖过。要在这个主题上取得成功，您需要了解 Cypress 测试的工作原理，测试的结构以及 Cypress 测试可以用来进行断言的不同方式。这些背景信息将帮助您了解如何在 Cypress 中使用 TDD 以及在软件开发生命周期中使用它所带来的优势。在本章中，我们将利用测试驱动的方法编写测试，这将极大地增加我们对应用程序和软件解决方案的信任和信心。

本章我们的重点将放在如何利用 Cypress 来帮助我们在开始开发之前全面思考一个应用的使用上。我们将应用测试我们的应用在开始开发之前。在这样做的过程中，我们将利用 Cypress 框架作为我们测试的核心。

本章将涵盖以下关键主题：

+   理解 TDD

+   在 Cypress 中编写 TDD 测试

+   修改 TDD 测试

一旦你完成了这些主题，你就准备好学习 Cypress 中的元素交互了。

## 技术要求

要开始，我们建议您克隆本书的 GitHub 存储库，其中包含我们将在本章中构建的应用程序和所有我们将编写的测试。

本章的 GitHub 存储库可以在以下链接找到

[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)

本章的源代码可以在`chapter-06`目录中找到。

我们将使用 ReactJS 库来开发我们的应用。

你可以通过运行以下命令来运行 ReactJS 应用程序：

+   `cd chapter-6/tdd-todo-app`

+   `npm install`（安装所有必需的依赖项）

+   `npm run start`（启动 React 应用程序进行测试）

以下链接：

# 理解 TDD

TDD 是一个依赖于将需求转化为非常具体测试用例的软件开发过程。编写这些测试用例后，代码被编写并根据其他测试用例进行检查。TDD 过程的最后一步是迭代和改进代码，以确保它符合所需的最佳实践，并且测试用例通过。TDD 方法的循环包括以下步骤：

1.  定义需要实现的功能

1.  编写新的测试

1.  运行测试以检查测试是否失败

1.  编写测试用例的代码

1.  运行测试以确保测试通过

1.  重构代码

1.  重复这个过程

TDD 的目的是在开发开始之前可视化最终结果。这样，就可以预见在开发过程中可能出现的问题或障碍。能够使用 TDD 方法开发功能有助于对解决方案进行批判性思考，并且有助于在应用程序开发过程中需要测试的场景。

假设我们正在创建一个登录功能；从测试的角度来看，我们需要为登录功能想出所有不同的场景。思考这些测试场景将使我们清楚地了解在开发阶段需要发生什么，使得在开发这个应用功能时需求更加清晰。

TDD 有助于减少范围蔓延的可能性，因为从一开始，我们就可以理解项目的目标。有了测试用例，我们可以确定功能并将范围限制在已编写的测试用例之内。了解此功能涉及的内容使开发人员能够制定代码的实现方式。从长远来看，这可能会导致减少开发时间。

重要提示

范围蔓延是指软件开发项目在项目开始后不受控制地增长或范围扩大。

接下来，让我们来看看 TDD 方法的优势。

## TDD 的优势

在本节中，我们将更详细地了解在软件开发生命周期中实施 TDD 方法所带来的好处。

### 更好的项目设计

在使用 TDD 方法进行开发时，开发人员需要考虑代码片段的目标。因此，开发人员将始终以最终目标为出发点。以特定目标开发功能的能力确保开发人员只编写所需和必要的代码，从而导致应用程序具有清晰的结构。

使用 TDD 还可以确保更高的代码质量，因为 TDD 强调使用“不要重复自己”（DRY）原则，这种原则在编写代码时会阻止重复。因此，通过使用 TDD，可以保持函数简单而简洁，代码库易于理解。清洁和简单的代码库易于维护和测试，这对开发人员和代码库维护者是一个额外的优势。

重要提示

DRY 原则是应用开发原则，强调软件模式的不重复和使用抽象来避免或减少冗余。

### 详细文档

TDD 强制执行引用正在开发的功能的严格文档；开发人员需要提出这样的规范，其中可能包括用户的操作。理解这些操作并将步骤分解为用户故事有助于开发人员实施功能，因此开发的功能非常接近定义的目标。

在编写测试的阶段开发适当的文档也减轻了其他参与方理解特性以重现文档的角色，因为这已经是软件开发过程的一部分。

### 减少开发时间

可以假设 TDD 在开发应用程序时需要更多时间，在大多数情况下，这是事实。根据这一说法，我们可以假设 TDD 很可能会延迟项目交付日期，但事实并非如此。

采用 TDD 方法，可以覆盖在开发中如果不使用 TDD 方法可能会出现错误的情况。虽然 TDD 可能最初比非 TDD 方法消耗更多时间，但它显著减少了开发人员维护项目和测试产品及其特性所需的工作量。

由于 TDD 强调清晰的代码，可以毫不夸张地说，即使发现了错误，也比在不使用 TDD 的项目中更容易修复。TDD 项目对高质量代码标准和持续反馈的关注使 TDD 项目的代码库易于维护，而非 TDD 项目则不然。

### 节约成本

在任何项目中，发现并修复错误在开发阶段比错误已经进入生产阶段时更便宜。TDD 专注于在开发过程中消除错误，大大减少了缺陷通过特性的开发和测试阶段的机会。这强化了代码重构原则和错误预防。TDD 方法大大节省了公司在与在生产中发现的错误和缺陷直接相关的行动上的支出。

作为缺陷直接结果而产生的成本可能包括直接收入损失、额外的时间和成本来修复发现的缺陷，甚至可能会失去公司利益相关者（如客户）的信任。了解 TDD 降低这些成本的能力使得公司的节约是值得的，因为开发软件需要花钱，而修复相同的软件则需要花费更多的钱。

### 可靠的解决方案

TDD 解决方案是可靠的，因为它们在开发开始之前经过了审查。TDD 确保了开发的概念就是实现的内容。这是通过在功能仍然是一个想法的时候编写的测试场景来实现的，并且以需求的形式存在。

没有使用 TDD，开发人员无法在不考虑程序的不同部分如何与新功能交互的情况下构建强大的解决方案。然而，使用 TDD，这些测试用例帮助开发人员了解新功能和现有功能如何集成，因此了解应用程序在新功能构建后的行为。这种方法使开发人员在开始开发之前就对解决方案有信心。

## TDD 的缺点

尽管 TDD 的大部分结果都是积极的，可以提高生产力和良好的开发流程，但对于结构不适合使用 TDD 的团队来说，TDD 也可能会带来负面影响。在本节中，我们将重点介绍使用 TDD 的缺点以及为什么它可能不适合某些团队。

### 组织准备工作

TDD 要求组织在实施过程中参与其中。TDD 要求在实施之前为组织定义需求，以确保成功，组织需要以适当的方式定位 TDD 适用于他们。在某些情况下，组织可能没有耐心等待所有需求在实施开始之前，也可能不愿意牺牲额外的时间来仔细审查需求。

TDD 是结构化的，需要管理层和开发团队一致同意承担与事先规划相关的成本，以便后期在维护上花费更少。并非所有团队都愿意采取等待 TDD 好处的方法，这意味着组织可能不愿意为目前看不到的成本付费。

### 理解问题

TDD 侧重于在实施开始之前构建测试。这种方法有助于团队更好地理解问题并提出坚实的实施解决方案。编写测试的最大挑战在于它们无法解决已经在实施代码中引入的逻辑错误。测试只能识别它们所测试的内容，可能无法测试代码中未明确定义的内容。

使用 TDD 可能会因为对问题的理解而导致错误；测试可能无法捕捉到设计解决方案的人员对需求理解不正确的情况。

## 总结 - 理解 TDD

在本节中，我们了解了 TDD，为什么我们需要它以及它如何在软件开发生命周期中使用。我们还了解了使用 TDD 的优势，以及它如何可以防止在后期开发和测试阶段发现的错误和缺陷带来的成本。我们还了解了利用 TDD 的缺点，其中一些可能源于测试的好坏取决于编写测试时的推理。因此，了解正在开发的问题对于为手头的问题制定测试是至关重要的。在接下来的部分中，我们将专注于在 Cypress 中编写 TDD 测试，以及这个过程如何帮助提出功能代码的坚实解决方案和实施。

# 在 Cypress 中编写 TDD 测试

在本节中，我们将专注于使用 Cypress 编写 TDD 测试。在本节中，我们将构建一个待办事项应用程序，并应用 TDD 原则。首先，我们需要有一个设计，这样我们才能编写适当的测试，并且还要对我们应用程序的功能进行批判性思考。本章的目标将是创建一个应用程序，可以添加待办事项，删除待办事项，显示已添加的待办事项，并显示已添加的待办事项的数量。下面的截图显示了最终应用程序的模拟。我们遵循的每一步都将帮助我们实现我们想要的模拟：

![图 6.1 - 待办事项应用程序模拟](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.1_B15616.jpg)

图 6.1 - 待办事项应用程序模拟

上面的截图显示了我们将要构建的待办事项应用程序的模拟。我们将使用 Cypress 中编写的 TDD 方法。该应用程序将具有以下功能：

+   添加新的待办事项

+   删除待办事项

+   查看已添加的待办事项

+   查看已添加的待办事项数量

这些功能构成了我们待办事项应用程序的要求。在本章中，我们将在开发测试和实现应用程序时将这些功能称为要求。

# 设置应用程序

为了避免在本节中增加任何进一步的复杂性，我们不会关注如何构建应用程序，而是关注在构建应用程序时如何实现测试。在背景上下文中，我们将构建的应用程序将使用 ReactJS 库，该库是用 JavaScript 编写的。

了解了我们的应用程序的外观之后，我们将采取逐步的方法来编写我们的测试，然后再开始开发我们的应用程序的过程。正如我们之前提到的，我们已经编写了我们将要构建的应用程序功能。我们将首先编写 TDD 测试，以便我们可以添加新的待办事项。

## 添加新的待办事项

我们将专注于的第一个 TDD 测试是负责检查新的待办事项是否已添加到我们的待办事项列表中的测试。要按照这些步骤进行，请使用以下命令导航到您从 GitHub 克隆的`tests`目录：

```js
 cd chapter-6/tdd-todo-app/integration/todo-v1.spec.js
```

上面的命令将引导您进入我们将在本章中使用的 TDD`tests`目录。该文件中的测试是我们在 TDD 过程中编写的测试的第一个版本。稍后，我们将修改它们，使其适应我们将添加的最终应用程序功能。

重要提示

在为我们的待办事项应用程序编写 TDD 测试时，请注意 Cypress 目录位于测试应用程序内部。这确保我们跟踪和识别属于正在开发的应用程序的 Cypress 测试。

以下代码片段是一个测试，检查我们是否可以向我们的应用程序添加新的待办事项，这是我们应用程序的要求之一：

```js
it('can create and display new todo', () => {
      cy.get('[data-testid="todo-item-input"]')
        .type('New todo');
      cy.get('[data-testid="add-todo-button"]')
        .click();
      cy.contains('New Todo');
});
```

在上面的代码片段中，我们编写了一个 TDD 测试，以检查在功能完成后，我们可以添加我们的待办事项并检查已添加的项目是否存在。请注意，在这个阶段，添加待办事项的功能尚未构建。如果我们在 Cypress 中运行这段代码片段，它应该会自动失败。为了验证这一点，我们可以运行以下命令来运行 Cypress 测试：

```js
npm run cypress:open 
```

以下截图显示了一个失败的 TDD 测试，用于创建和显示一个新的待办事项：

![图 6.2 - 在 Cypress 上运行 TDD 测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.2_B15616.jpg)

图 6.2 - 在 Cypress 上运行 TDD 测试

在前面的屏幕截图中，我们正在执行测试，以检查它是否失败以及 Cypress 是否能够执行它。在这个测试中，Cypress 尝试执行针对运行在端口`3000`上的本地运行的待办应用程序的测试。测试失败，因为 Cypress 找不到负责将待办事项添加到待办事项列表中的输入元素。从前面的屏幕截图中，我们可以验证应用程序成功导航到运行在本地主机上的应用程序。为了继续构建这个功能并确保测试通过，稍后，我们将添加添加待办事项的功能，并重新运行我们的测试。

## 删除待办事项

我们的待办应用程序要求说明，我们应该有能力删除已添加的待办事项。已删除的待办事项的要求之一是，一旦删除，它就不应再出现在待办事项列表上。为了编写我们的 TDD 测试，我们需要确保我们实际上已删除了待办事项，方法是验证一旦从待办事项列表中删除后，待办事项不再存在。我们将使用以下代码片段来实现删除功能测试要求：

```js
it(can delete added todo item', () => {
      cy.get('[data-testid="todo-item-input"]')
        .type('New todo');
      cy.get('[data-testid="add-todo-button"]')
        .click();
      cy.get('[data-testid="delete-todo-1-button"]')
        .click();
      expect('[data-testid="todolist"]'
      ).not.to.contain('New Todo')
   });
```

在上述代码块中，我们添加了一个待办事项，然后将其删除。后来，我们验证了已删除的待办事项不再存在，并通过使用 Cypress 断言方法来断言。这个测试片段不仅检查了待办事项的正确删除，还检查了删除后，待办事项将不再存在于 DOM 中。如前面的屏幕截图所示，使用 Cypress 运行此测试失败，因为我们的应用程序尚未构建。

查看已添加的待办事项

根据我们的应用程序要求，当添加待办事项时，它们应该在待办事项列表中可见。添加的待办事项应该与待办事项列表中的待办事项相同。为了进行适当的测试，我们需要确保我们的测试覆盖了确保添加的待办事项在待办事项列表上可见的情况。我们还需要验证已添加到待办应用程序的项目是否与待办事项列表上可见的项目相同。我们将再次策划一个 TDD 测试，旨在覆盖能够显示我们的待办事项的情况。以下代码块是用于显示已添加的待办事项的 TDD 测试：

```js
it(can view added todo item', () => {
      cy.get('[data-testid="todo-item-input"]')
        .type('New todo');
      cy.get('[data-testid="add-todo-button"]')
        .click();
      expect('[data-testid="todolist"]').to.contain(
      'New Todo')
 });
```

在这个代码块中，TDD 测试将使用应用程序的输入元素添加一个新的待办事项，然后验证添加的元素是否存在于待办事项列表中。有了这个测试，就可以排除待办事项被添加但在待办事项列表上不可见的可能性。

## 查看已添加的待办事项的数量

根据我们应用的要求，我们需要确保能够查看添加的待办事项的数量。根据我们的模拟，也可以在`chapter-06/mockups/todo-mockup.png`目录中找到，待办事项的数量应该对应于待办事项列表中的项目。根据我们的待办事项应用程序的要求，我们的 TDD 测试应该测试诸如添加多个待办事项并检查待办事项的数量增加或减少的情况，具体取决于它们是添加还是从待办事项列表中删除。

重要提示

在编写测试之前，了解 Cypress 如何理解要与之交互的元素，要单击哪个按钮，或者在输入字段上输入。Cypress 使用元素标识符，这些标识符唯一标识 Cypress 要与之交互的元素。网页上元素的唯一元素标识符可能包括唯一元素 ID CSS 选择器、XPath 定位器，甚至是我们选择的自定义元素标识符，格式为`[data-testid="our-unique-identifier"]`。

与添加、删除或查看待办事项的测试场景不同，这个测试将包含多个步骤和多个断言。以下代码块显示了一个查看已添加到待办事项列表中的待办事项数量的 TDD 测试：

```js
it('can view number of added todo items', () => {
      cy.get('[data-testid="todo-item-input"]')
        .type('New todo');
      cy.get('[data-testid="add-todo-button"]')
        .click();
      cy.get('[data-testid="todo-item-input"]')
        .type('Another todo');
      cy.get('[data-testid="add-todo-button"]')
        .click();
      expect('[data-testid="todo-item-number"]').to.eq('2')
      cy.get('[data-testid="delete-todo-1-button"]')
      .click();
      expect('[data-testid="todo-item-number"]').to.eq('1')
    });
```

这段代码片段将作为最终测试的模板，用于检查待办事项的数量随着待办事项的添加和删除而增加和减少。在这里，我们可以看到我们添加了两个待办事项，然后验证两个待办事项都存在。在验证待办事项列表中存在两个项目后，我们删除了一个待办事项，并检查待办事项的计数随着项目数量的减少而减少。

重要提示

在编写 TDD 测试时，我们并不太关心测试中可能存在的语法错误，而是关注场景和测试覆盖率。当我们在构建功能后开始修改测试时，我们将在再次运行测试时修复错误，这次针对添加的功能。

现在，是时候进行快速回顾了。

# 回顾-设置应用程序

在本节中，我们学习了如何编写 TDD 测试以及它们如何帮助塑造我们的思维，因为我们开发解决方案。我们涵盖了编写 TDD 测试的过程，用于添加待办事项、查看待办事项、删除待办事项以及查看待办事项列表中的总数。我们还了解到 TDD 测试帮助我们理解开发过程，并且这些测试不是在功能完成时我们将拥有的最终测试。在下一节中，我们将看看在应用程序的功能完成后如何修改 TDD 测试。

# 修改 TDD 测试

在前一节中，我们看了 TDD 测试的结构以及它们是如何根据正在开发的应用程序进行开发的原理。正如我们之前提到的，我们不会详细介绍如何开发应用程序，而是专注于如何将测试集成到正在开发的应用程序中。这里提到的应用程序可以在本书的 GitHub 存储库中找到（[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress/tree/master/chapter-06/`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress/tree/master/chapter-6/)）。

在本节中，我们将使用在上一节中创建的 TDD 测试。我们将要构建的 TDD 测试负责测试应用程序的定义要求，这些要求如下：

+   添加新的待办事项

+   删除待办事项

+   查看已添加的待办事项

+   查看已添加的待办事项数量

现在我们已经编写了测试，我们将在修改它们时向应用程序添加功能。首先，我们将运行第一个测试，因为我们已经构建了添加待办事项的功能。为了将 TDD 测试和应用程序中的最终测试分开，我们将创建一个名为`todo-v2.spec.js`的新测试文件，我们将在其中添加我们的最终测试。测试文件位于`chapter-06/tdd-todo-app/integration/todo-v2.spec.js`目录中。

## 添加新的待办事项

在这里，我们想要验证我们之前编写的用于验证添加新待办事项的测试是否有效。为了运行这个测试，我们将确保我们的应用程序（使用 ReactJS 构建）在本地运行。我们将针对本地托管的应用程序运行我们的测试。一旦添加新的待办事项功能完成，我们的应用程序将如下所示：

![图 6.3-添加新的待办事项功能](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.3_B15616.jpg)

图 6.3-添加新的待办事项功能

在前面的截图中，我们可以验证我们的**添加待办事项**功能是否正常工作，因为我们已经添加了待办事项。现在我们的代码似乎工作正常，是时候检查我们的测试在运行时是否实际通过了。为此，我们将使用`todo-v2.spec.js`测试文件，这是`todo-v1.spec.js`的修改版本。

我们修改了位于`todo-v1.spec.js`的版本 1 测试文件的测试，并且还修改了测试，使其适应我们在应用程序中创建的待办事项添加功能。新测试应如下所示：

```js
it('can create and displays new todo', () => {
      cy.visit('http://localhost:3000/')
      cy.get('[data-testid="todo-input-element"]')
        .type('New todo');
      cy.get('[data-testid="add-todo-button"]')
        .click();
      cy.get('[data-testid="todolist"]'
        .contains('New todo');
    });
```

就像在我们的初始测试中一样，要测试的初始场景并没有改变。我们首先导航到本地运行的应用程序的默认 URL。然后，我们使用 Cypress 添加一个待办事项，然后验证添加的待办事项是否与我们最初添加到输入元素中的内容相同。我们可以清楚地查看以下截图中发生的操作，该截图显示了成功的测试：

![图 6.4 – 通过测试添加待办事项](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.4_B15616.jpg)

图 6.4 – 通过测试添加待办事项

在上述截图中，我们可以看到 Cypress 导航到本地托管的应用程序并添加了一个待办事项，然后检查添加的待办事项是否出现在待办事项列表中。

重要提示

我们为我们的应用程序添加了以`data-testid=*`为前缀的元素标识符，以唯一标识元素。元素标识符在选择 Web 应用程序中的元素时非常方便。通过添加唯一标识符并且不使用应用程序的默认 CSS 选择器，即使应用程序的选择器发生变化，我们的测试也不会受到影响，仍将正常运行。

通过这样，我们成功完成了 TDD 中的第一个任务。在本节中，我们实现了以下目标：

+   确定了我们想要开发并创建原型的应用程序

+   在开发开始之前编写了 TDD 测试

+   开发了向我们的应用程序添加待办事项的功能

+   修改了 TDD 测试以使其符合我们开发的功能

以下截图显示了添加新待办事项的 TDD 版本和最终功能版本的测试的并排比较：

![图 6.5 – TDD 测试与最终功能测试的比较](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.5_B15616.jpg)

图 6.5 – TDD 测试与最终功能测试的比较

正如您所看到的，测试的第二个版本显示，尽管测试结构或目标没有改变，但我们不得不修改测试，以使其适应已开发的待办事项添加功能。识别需求、开发功能，然后修改测试以针对该功能运行是 TDD 的主要目标，我们成功实现了这一点。

## 删除待办事项

现在，我们将学习如何删除已添加的待办事项。根据我们的需求，删除的待办事项将从待办事项列表中移除，并且一旦单击待办事项的删除按钮，它将不再可见。再次强调，我们不会关注开发该功能的过程，而是关注该功能的测试。在以下截图中，我们可以看到为每个新添加的待办事项显示的删除按钮：

![图 6.6 – 删除待办事项功能](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.6_B15616.jpg)

图 6.6 – 删除待办事项功能

突出显示为红色的图标是出现在每个待办事项上的删除图标。如果单击删除按钮，添加的待办事项将从我们的待办事项列表中消失，就像我们的需求描述的那样。为了验证该功能是否按照我们设想的那样工作，我们现在将修改我们的 TDD 测试以针对删除功能运行测试。以下代码块是一个测试，用于删除已添加到待办事项列表中的待办事项：

```js
it('can delete an added todo item', () => {
      cy.visit('http://localhost:3000/')      
      cy.get('[data-testid="todo-input-element"]')
        .type('New todo');
      cy.get('[data-testid="add-todo-button"]')
        .click();
      cy.get('[data-testid="delete-todo-0-button"]')
        .click();
      expect('[data-testid="todolist"]'
        .not.to.contain('New todo')
});
```

这段代码显示了修改后的 TDD 测试，以确认一旦删除了待办事项，它将不再出现在待办事项列表中。我们还必须对我们最初编写的 TDD 测试进行一些微小修改，以使所有选择器和操作与已开发的功能匹配。从以下 Cypress 截图中可以看到，我们的测试通过了，添加的待办事项已被删除，正如我们预期的那样：

![图 6.7 – 删除已添加的待办事项](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.7_B15616.jpg)

图 6.7 – 删除已添加的待办事项

在这里，Cypress 快照功能帮助我们可视化了 Cypress 点击新添加的待办事项的删除按钮的过程。我们还编写了一个断言来验证一旦删除后，已删除的待办事项在待办事项列表中不存在。我们的测试通过了，这意味着我们已经使用 TDD 向待办事项列表中添加了一个待办事项，并且还删除了这个待办事项并测试了它在待办事项列表中不存在。在我们的下一个测试中，我们将专注于查看已添加的待办事项。

## 查看已添加的待办事项

我们应用程序的要求之一是查看待办事项列表中已添加的待办事项。在添加待办事项时，我们已经能够看到这个功能在运行，但还没有进行测试。为了验证这个功能，我们将添加一个新的待办事项，并检查创建的待办事项是否出现在待办事项列表中。以下代码块是一个检查已添加的待办事项是否在我们创建的应用程序中可见的测试：

```js
it('can view added todo items', () => {
      cy.visit('http://localhost:3000/')      
      cy.get('[data-testid="todo-input-element"]')
      .type('New todo, {enter}')
      cy.get('[data-testid="todo-input-element"]')
      .type('Another todo, {enter}')
      cy.get('[data-testid="todolist"]').contains(
      'New todo');
      cy.get('[data-testid="todolist"]'
      .contains('Another todo');
    });
```

在这里，我们修改了我们的 TDD 测试。不仅仅是检查我们是否可以查看单个待办事项，我们添加了两个项目，并添加了一个断言来检查这两个项目是否存在于待办事项列表中。我们将在 Cypress 中运行我们的测试，并使用应用程序预览来验证这两个待办事项是否存在，如下截图所示：

![图 6.8 – 查看已添加的待办事项](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.8_B15616.jpg)

图 6.8 – 查看已添加的待办事项

万岁！我们的测试通过了！

这个截图显示了我们正确构建了一个添加待办事项的功能的需求，并且我们对查看待办事项在待办事项列表中的测试需求也得到了满足。在这里，我们已经实现了查看我们的待办事项功能的目标。我们还使用了 TDD 来检查在查看我们的待办事项时需要测试的场景。

## 查看已添加的待办事项数

现在我们已经修改了用于添加待办事项、删除待办事项和查看待办事项的 TDD 测试，我们还想添加一个功能，用于检查已添加的待办事项的数量。查看我们已添加的待办事项数的功能如下截图所示：

![图 6.9 – 查看已添加的待办事项数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.9_B15616.jpg)

图 6.9 – 查看已添加的待办事项数

这个功能显示了当前在我们的待办事项列表中可用的待办事项数量。随着添加更多的待办事项，待办事项的数量将增加，并且当从列表中删除待办事项时，数量将减少。在这里，我们将使用我们为此功能编写的 TDD 测试，并修改它以便我们的应用程序可以使用。在我们的测试中，我们将专注于添加和删除待办事项，并验证在添加和删除时，待办事项的数量会相应地改变。以下代码块显示了不同的断言，检查该功能是否按照我们的要求正常工作：

```js
it('can view number of added todo items', () => {
      cy.visit('http://localhost:3000/')      
      cy.get('[data-testid="todo-input-element"]')
      .type('New todo, {enter}')
      cy.get('[data-testid="todo-input-element"]')
      .type('Another todo, {enter}')
      cy.get('[data-testid="todo-item-number"]')
      .should(($header) => {
        expect($header.get(0).innerText).to.contain('2')
      })
      cy.get('[data-testid="delete-todo-1-button"]')
      .click();
      cy.get('[data-testid="todo-item-number"]')
 	.should(($header) => {
        expect($header.get(0).innerText).to.contain('1')
      })
    });
```

上面的代码片段向我们展示了添加新的待办事项，验证列表中的项目是否被删除，以及计数在应用程序不同状态变化中保持一致。在这里，我们修改了我们最初的 TDD 测试，并且能够使用它们来测试我们是否实际上可以增加或减少可用的待办事项的数量。通过在 Cypress 上运行相同的测试，我们可以验证 Cypress 是正常的，并且我们有一个未被删除的待办事项，如下截图所示：

![图 6.10 – 测试待办事项数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_6.10_B15616.jpg)

图 6.10 – 测试待办事项数

从前面的截图中，我们可以验证，随着应用程序状态的改变，比如添加和删除待办事项，数量会相应地增加或减少。

## 总结 – 修改 TDD 测试

在本节中，我们学会了如何修改 TDD 测试，一旦功能已经开发完成，使其符合我们应用程序的构建方式。我们还学会了 Cypress 在测试运行时如何独特地识别要与之交互的元素。最后，我们学会了如何将已经编写的 TDD 测试转换为已为我们的应用程序开发的测试功能。

# 总结

在本章中，我们了解了 TDD 工作的过程以及在任何团队中拥抱 TDD 的重要性，并探讨了 TDD 的优缺点。我们还探讨了如何将 TDD 应用于实际应用程序。通过这样做，我们为一个尚未构建的 Todo 应用程序创建了需求。在开发应用程序之前，我们为我们认为重要的功能编写了 TDD 测试，然后使用这些需求和 TDD 测试来开发我们的功能。在开发完功能后，我们修改了我们的第一个 TDD 版本的测试，使其适用于我们开发的功能，从而完成了展示如何在实际应用程序中利用 TDD 的过程。

现在，您应该了解什么是 TDD，如何编写 TDD 测试，以及如何修改和使用 TDD 测试在实际应用程序中，使其符合已开发的应用程序。

既然我们已经了解了 TDD 以及如何在项目中实施它，接下来我们将专注于如何与 Cypress DOM 的不同元素进行交互。


# 第七章：理解 Cypress 中的元素交互

在开始运行测试时，了解 Cypress 与元素交互的方式之前，最好先对构成 Cypress 的原则，它的工作原理，不同的 Cypress 命令，甚至 Cypress 的使用实际示例有一个坚实的理解。要完全理解本章，您需要已经学习了前几章，这将使您在学习过程中取得成功。

在本章中，我们将介绍 Cypress 如何与元素交互以及它如何响应交互过程中元素的不同状态。我们还将介绍 Cypress 如何通过 Cypress 命令中的内置机制确定元素是否准备好进行交互。

我们将在本章中涵盖以下关键主题：

+   理解可操作性

+   强制可操作性

一旦您完成了这些主题中的每一个，您将具有理解 Cypress 如何解释测试的知识，以及它在执行测试时如何解释发生的错误所需的知识。

## 技术要求

要开始，请克隆包含源代码和我们将在本章中编写的所有测试的存储库从 GitHub。

本章的 GitHub 存储库可以在以下网站找到：

[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)

本章的源代码可以在`chapter-07`目录中找到。

# 理解可操作性

现在我们知道了 Cypress 命令是什么，以及何时何地使用它们，我们需要了解 Cypress 在执行测试时的思考和操作过程。在本节中，我们将介绍 Cypress 如何与命令交互，如何确保元素可见和可操作，甚至如何处理元素中的动画。我们还将介绍 Cypress 在完成任何命令之前如何确定**可操作性**。

可操作性是 Cypress 在**文档对象模型**（**DOM**）中执行操作的能力。Cypress 具有命令，其唯一目的是与 DOM 元素交互。这些命令像“用户”一样行事，并模拟与应用程序用户界面的交互。Cypress 事件负责命令的行为，因为它将事件发送到浏览器，使其看起来像是在应用程序的用户界面上与用户进行交互。

以下是 Cypress 中直接与 DOM 交互的一些命令；要完成操作，DOM 元素必须是可操作的。这些命令带有内置的 Cypress 机制，用于检查它们交互的元素的可操作性。这些命令包括以下内容：

+   `cy.type()`: 在 DOM 元素中输入

+   `cy.clear()`: 清除文本区域或输入框的值

+   `cy.click()`: 在 DOM 元素上执行单击操作

+   `cy.dbclick()`: 在 DOM 元素上执行双击操作

+   `cy.rightclick()`: 在 DOM 元素上执行右键单击操作

+   `cy.select()`: 从`<select>`下拉菜单中选择一个`<option>`选项

+   `cy.trigger()`: 在 DOM 元素上执行触发事件

+   `cy.check()`: 检查 DOM 上的单选按钮和复选框

+   `cy.uncheck()`: 取消 DOM 上的单选按钮和复选框

重要说明

`cy.rightclick()`命令不会打开浏览器菜单，而是会检查您的元素与浏览器的**上下文菜单**的行为。

在运行任何上述命令之前，Cypress 会采取行动来确保 DOM 准备好接收操作。为了执行任何命令，Cypress 会执行自己的检查，以验证条件是否适合在 DOM 元素上执行命令。

所有这些检查都在指定的时间内进行，可以通过**defaultCommandTimeout**配置选项进行配置，该选项可以在`cypress.json`文件中进行修改。以下是 Cypress 执行的检查 DOM 元素准备就绪的操作：

+   **可见性**：滚动元素以查看

+   **残疾**：确保元素未隐藏

+   **分离**：检查元素是否已从 DOM 中移除

+   **只读**：检查元素是否处于只读状态

+   **动画**：检查动画是否已完成

+   **覆盖**：检查元素是否未被父元素覆盖

+   **滚动**：检查被固定位置元素覆盖的元素的滚动

+   **坐标**：检查事件是否在所需坐标处触发

为了更好地理解 Cypress 如何解释 DOM 的响应以及如何确定可操作性，我们将逐个讨论这些列出的操作，并描述 Cypress 在执行可操作命令时如何通过每个动作检查状态。

## 可见性

Cypress 使用不同的因素来确定元素是否可见。Cypress 确定元素的可见性的默认方式是通过检查该元素的**层叠样式表**（**CSS**）属性。任何元素的 CSS 属性定义了元素的行为，如果默认情况下 CSS 属性以一种意味着元素被隐藏的方式定义，Cypress 将自动知道该元素由于其属性而不可见。

如果满足以下任一条件，Cypress 认为元素是隐藏的：

+   元素的 CSS`width`和`height`为`0`。

+   元素或其祖先具有`visibility: hidden`的 CSS 属性。

+   元素或其祖先具有`display: none`的 CSS 属性。

+   元素具有`position: fixed`的 CSS 属性，并且被遮盖或在屏幕上不存在。

此外，Cypress 使用`hidden overflow` CSS 属性来确定在测试执行期间元素是否隐藏。以下是 Cypress 用于确定元素是否隐藏的一些其他实例：

+   祖先元素具有隐藏的溢出和`width`或`height`值为`0`，并且在祖先元素和具有`position: absolute`的元素之间有一个元素。

+   祖先元素具有隐藏的溢出，并且该元素具有`position: relative`的 CSS 属性，并且位于祖先元素的边界之外。

重要提示

隐藏的溢出意味着 CSS 属性可以是以下任何一种溢出：`hidden`，`overflow: auto`，`overflow: scroll`，`overflow-x: hidden`或`overflow-y: hidden`。

所有这些转换和平移的计算都由 Cypress 处理，如果 Cypress 偶然发现元素不可见，则测试将失败，并显示错误，指出 Cypress 试图与之交互的元素的可见性被隐藏。

## 残疾

在检查可操作性时，Cypress 还会检查元素是否已禁用。当元素具有`disabled: true`的 CSS 属性时，Cypress 无法与其交互，因为在 DOM 上禁用元素时无法对元素执行任何操作。当 Cypress 遇到禁用的元素并需要对其执行操作时，它将返回一个错误，描述禁用元素的状态以及为什么无法通过 Cypress 可操作命令与元素交互。

## 分离

分离的元素是已从 DOM 中移除但由于 JavaScript 的原因仍然存在于内存中的元素。大多数应用程序通过从 DOM 中移除元素并在 DOM 中插入其他元素来工作，因此不断地分离和附加元素在 DOM 中。在评估元素是否可操作时，Cypress 会在对元素运行任何可操作的命令之前检查元素是否未分离。如果 Cypress 遇到分离的元素，它会在测试中执行可操作的命令之前抛出错误。

重要的是要注意，Cypress 只会在 DOM 中搜索元素，不会检查分离的元素是否存在于内存中。

## 只读

只读元素是仅用于查看的，不能接受新内容或编辑的。Cypress 在`.type()`命令中检查`readonly` CSS 属性；如果遇到`readonly` CSS 属性，测试将以错误失败。

## 动画

Cypress 具有内置机制，用于确定元素中是否存在动画。在评估元素是否可操作时，Cypress 会等待动画完成，然后才开始与元素交互。

为了确定测试中的元素是否正在进行动画，Cypress 必须使用元素的最后坐标的样本，然后应用其算法来计算斜率。

重要提示

斜率是通过选择两个不同的点并记录它们的坐标来计算的。然后记录 y 坐标和 x 坐标之间的差异。然后进行 y 坐标和 x 坐标之间的差异的除法，以确定元素的斜率。

通过检查元素的当前和上一个位置来确定元素的动画和斜率。Cypress 带有内置的动画阈值，用于检查元素必须超过的像素距离以被认为是正在进行动画。您可以在`cypress.json`文件中配置此项，并按以下代码块中所示更改默认值：

```js
{
"animationDistanceThreshold": 10
}
```

当这个值被改变时，无论是增加还是减少，Cypress 都会改变其灵敏度和确定元素是否正在进行动画的行为。较高的动画阈值意味着 Cypress 在检测像素变化的距离时会降低其灵敏度，而较低的动画阈值意味着 Cypress 在检测正在进行动画的元素时会更加敏感。

在运行测试时也可以关闭动画。为了做到这一点，我们需要配置`cypress.json`配置文件来忽略动画并继续执行我们的命令。以下配置可以通过以下代码块实现：

```js
{
"waitForAnimations": false
}
```

当我们指定我们的测试不应等待动画时，如此处所示，我们的测试将忽略动画，并且将执行，就好像动画不存在一样。但是，可以将此配置更改回`true`值，以继续执行我们的测试，同时等待元素中的动画执行。

## 覆盖

Cypress 在发出命令之前，会检查元素是否被父元素覆盖，作为验证可操作性的一部分。有许多情况下，元素可能在 DOM 中可见，但只是被父元素覆盖，比如模态框、弹出窗口或对话框。如果有一个父元素覆盖了元素，Cypress 将不允许执行命令。

在父元素覆盖 Cypress 应该执行操作的元素的情况下，Cypress 会抛出错误，因为即使在现实生活中，用户也无法与被覆盖的元素进行交互。

重要提示

如果子元素覆盖了元素，Cypress 将继续向子元素发出事件，并且执行会在没有任何问题的情况下继续进行。

在下面的代码块中，我们有一个`button`元素，它部分或完全被`span`元素覆盖，而不是直接点击`button`元素本身：

```js
<button>
  <span> Submit </span>
</button>
```

在这个代码块中，尽管`span`元素覆盖了`button`元素，Cypress 将向子`span`元素发出命令，这将触发对我们的`button`元素的点击事件，而不会遇到错误。

## 滚动

Cypress 在元素上执行滚动，并且在本节开头指定的可操作命令中默认启用了此行为。默认情况下，在与元素交互之前，Cypress 会滚动到该元素的位置，并确保它在视图中。

提示

诸如`cy.get()`或`cy.find()`之类的命令在其中没有内置 Cypress 滚动到视图的机制，就像 Cypress 中的可操作命令一样。

Cypress 中的滚动是通过算法启用的，该算法首先尝试确定元素是否在 DOM 上可见。然后，它使用坐标从当前元素到 Cypress 操作的元素的期望位置计算坐标，以导航到实际元素。

Cypress 滚动算法会不断滚动，直到元素变得可见，或者直到元素不再被其他元素遮挡。该算法非常好地确保了 DOM 上的大多数元素在视图中可以滚动并进行交互。

## 坐标

在 Cypress 完成了检查元素是否可操作的验证过程之后，默认情况下，它会向元素的中心触发事件。Cypress 提供了一种机制来覆盖触发事件的默认位置，并且大多数命令的行为都可以自定义。

以下代码块显示了更改按钮上点击事件的触发行为：

```js
it('can mark a todo as completed - with changed hitbox position', () => {
cy.visit('http://todomvc.com/examples/react/#/')
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get(".new-todo").type("Another New Todo {Enter}");
      cy.get('.todo-list>li:nth-child(1)').find(
      '.toggle').click({ position: 'topLeft' });
    });
```

在这个代码块中，我们导航到我们的 Todo 应用程序并添加了两个待办事项，然后标记其中一个待办事项为已完成。当标记我们的第一个待办事项为完成时，我们改变了点击的位置，并指示 Cypress 点击`topLeft`位置，而不是默认的`center`位置。以下截图显示了`click`命令在被点击的待办事项动作的**事件点击框**的顶部左侧部分：

![图 7.1 – 更改 Cypress 点击位置的坐标](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_7.1_B15616.jpg)

图 7.1 – 更改 Cypress 点击位置的坐标

重要提示

事件点击框是在固定的 Cypress 快照上弹出的高亮显示，以显示测试与元素的交互。事件点击框可以由 Cypress 事件触发，例如`.click()`方法。

正如*图 7.1*所示，Cypress 有能力计算元素的坐标，并确定在哪里点击元素。此外，当触发行为的坐标发生变化时，Cypress 会将它们记录在 Cypress 测试运行器的命令日志中。我们可以进一步检查控制台，查看 Cypress 在执行元素的顶部左侧点击后打印的坐标。以下图显示了第一个已完成待办事项的`click`事件的打印坐标：

![图 7.2 – 新的点击位置坐标](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_7.2_B15616.jpg)

图 7.2 – 新的点击位置坐标

截图中显示的坐标是我们指示 Cypress 使用的新的`.click()`命令坐标，而不是带有可操作命令的默认命令。

## 总结-理解可操作性

在本节中，我们了解了 Cypress 如何确定元素的可操作性以及如何评估不同元素的条件，例如可见性、禁用、分离模式、动画、滚动属性、坐标，甚至`readonly`属性。我们还学习了 Cypress 如何计算元素中的动画以及如何增加动画阈值以减少 Cypress 检测动画的敏感度。

在下一节中，我们将学习如何强制 Cypress 在元素的可操作性检查失败时继续执行操作，并在可以安全执行强制操作的元素上执行强制操作。

# 强制可操作性

理解了可操作性是什么，以及 Cypress 需要进行的检查来确定元素是否可操作，也很重要了解我们如何覆盖 Cypress 设置的机制来检查可操作性。在本节中，我们将专注于执行操作和命令，即使元素未通过 Cypress 为可操作命令执行的可操作性检查。我们还将学习如何安全地实现一些元素和测试的覆盖机制。

## 覆盖 Cypress 可操作性检查

在 Cypress 测试中，可操作性非常有用，因为它帮助我们找到用户可能无法与应用程序元素交互的情况。但有时，可操作性检查可能会妨碍正确的测试，这就引出了我们的下一个任务：覆盖安全检查。

在某些测试中，“像用户一样操作”可能并不值得，因为归根结底，目标是编写可以以自动化方式防止错误和缺陷的有意义的测试。诸如嵌套导航结构和界面之类的情况可能导致复杂的测试，可以通过消除嵌套导航结构，而是直接与我们想要的元素进行交互来实现。

为了覆盖 Cypress 的可操作性检查，我们可以向 Cypress 可操作命令传递`{force: true}`参数选项。该选项将指示 Cypress 覆盖所有检查，以检查可操作性，并继续执行默认操作。以下代码块是一个测试，使用我们的 Todo 应用程序中的`toggle-all`按钮将所有待办事项标记为已完成：

```js
it('can mark all todo as completed - with no forced toggle option (Failure)', () => {
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get(".new-todo").type("Another New Todo {Enter}");
      cy.get('.todo-list>li:nth-child(1)').find(
      '.toggle').click();
      cy.get('#toggle-all').click();
    });
```

当此测试运行时，它将失败，因为尝试切换第一个元素并标记为完成将导致测试失败和错误，因为它已经标记为完成。以下截图显示了 Cypress 可操作性的运行情况，测试失败，因为待办事项由于被另一个元素覆盖而无法标记为完成：

![图 7.3 - 未通过 Cypress 可操作性检查的测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_7.3_B15616.jpg)

图 7.3 - 未通过 Cypress 可操作性检查的测试

进一步调查*图 7.3*，我们可以验证第一个项目无法标记为已完成，因为它已经完成，这导致了失败。我们可以通过告诉 Cypress 在切换所有待办事项完成之前忽略可操作性检查来覆盖此测试行为，如下面的代码块所示：

```js
it('can mark all todo as completed - with forced toggle option (Success)', () => {
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get(".new-todo").type("Another New Todo {Enter}");
      cy.get('.todo-list>li:nth-child(1)').find(
      '.toggle').click();
      cy.get('#toggle-all').click({force: true});
    });
```

在运行代码块中显示的测试时，它会通过，因为我们已经阻止了 Cypress 检查我们需要点击的元素是否被另一个元素覆盖。以下截图显示了代码运行情况，并成功测试了通过点击 toggle-all 下拉按钮标记两个待办事项为已完成：

![图 7.4 - 覆盖 Cypress 可操作性检查的通过测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_7.4_B15616.jpg)

图 7.4 - 覆盖 Cypress 可操作性检查的通过测试

在*图 7.4*中，Cypress 忽略了与项目可操作性相关的检查，而是继续执行默认操作，我们的情况下是切换两个待办事项并标记为已完成。我们通过向 toggle 按钮的`click`命令传递`{force: true}`选项来实现覆盖。

当使用强制选项强制发生 Cypress 事件时，Cypress 会执行以下操作：

+   继续执行所有默认操作

+   强制在元素上触发事件

然而，Cypress 不会执行以下操作：

+   确保元素可见

+   滚动元素以查看

+   确保元素未被禁用

+   确保元素未被分离

+   确保元素未处于动画状态

+   确保元素没有被覆盖

+   确保元素不是只读的

+   在后代元素上触发事件

重要提示

强制可操作性在某些情况下非常有用，特别是当你不需要花费时间自动化不值得自动化的步骤时；然而，有时强制可操作性并不是解决问题的最佳方案。当我们强制可操作性时，大多数问题都可以通过编写更好的应用程序代码和确保项目的正确对齐来解决，以确保没有元素阻挡其他元素。我们还可以利用 Cypress 来克服诸如动画之类的情况，等待动画停止运行，然后在确保页面动画已完成后执行我们的测试。

当在命令上强制可操作性时，Cypress 放弃了确保在对元素执行任何操作之前满足正确条件的角色，而是直接在测试中执行发出的条件。

## 总结 - 强制可操作性

在本节中，我们学习了可以在元素上强制可操作性，并且可以通过在发出的可操作命令上传递`{force: true}`参数来实现。我们还看到了当我们强制执行 Cypress 命令时的显著差异，例如在测试中切换我们的待办事项为完成状态。在本节中，我们还了解了何时重写 Cypress 的可操作性是重要的，以及它如何潜在地减少测试的复杂性。

# 摘要

在本章中，我们学习了 Cypress 如何通过确保元素处于正确状态来强制元素的可操作性，然后才对元素执行命令。我们了解到 Cypress 在执行任何元素操作之前会检查可见性、禁用状态、DOM 分离、`readonly`模式、动画、覆盖、滚动和元素坐标。我们还了解了 Cypress 如何计算元素的动画，甚至在对元素执行操作时如何改变坐标。我们还学习到可以通过在测试中强制可操作性来覆盖 Cypress 设置的默认检查。

完成了本章后，我相信你已经掌握了理解 Cypress 如何确定元素的可操作性以及如何在测试中覆盖可操作性的技能，以减少复杂性。在下一章中，我们将学习使用变量和别名，并深入研究如何多次重用我们在测试中定义的变量和别名。


# 第八章：理解 Cypress 中的变量和别名

在我们开始讨论 Cypress 中变量和别名的工作原理之前，重要的是要了解我们在前几章中涵盖了什么，如何在 Cypress 中编写测试，如何配置测试，甚至如何使用 Cypress 按照测试驱动开发的方式编写应用程序。本书前几章提供的背景信息将为我们提供一个良好的基础，让我们深入了解变量和别名的工作原理。通过探索变量和别名，我们将了解如何在 Cypress 中创建引用，这将简化我们的测试编写过程和测试的复杂性。了解如何使用变量和别名不仅可以让您编写更好的测试，还可以编写易于阅读和维护的测试。

在本章中，我们将专注于编写异步命令，以利用 Cypress 捆绑的变量和别名。我们还将了解如何通过使用别名简化我们的测试，以及如何在测试的不同区域利用我们创建的别名和变量，例如元素的引用、路由和请求。

本章将涵盖以下关键主题：

+   理解 Cypress 变量

+   理解 Cypress 别名

一旦您了解了这些主题，您将完全了解如何在 Cypress 测试中使用别名和变量。

## 技术要求

要开始，请克隆包含本章中将编写的所有源代码和测试的存储库从 GitHub 中获取。

本章的 GitHub 存储库可以在[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)找到。

本章的源代码可以在`chapter-08`目录中找到。

# 理解 Cypress 变量

本节将重点介绍 Cypress 中的变量是什么，它们在测试中如何使用以及它们在测试中的作用，特别是在减少测试复杂性方面。我们还将探讨可以在哪些不同区域使用 Cypress 变量来增加测试的可读性。通过本节的学习，您将能够使用变量编写测试，并了解在编写测试时应该在哪里使用变量。

为了更好地理解 Cypress 中变量的工作原理，重要的是要了解 Cypress 如何执行其命令。以下代码块是一个测试，首先选择一个按钮，然后选择一个输入元素，然后点击按钮：

```js
it('carries out asynchronous events', () => {
   const button = cy.get('#submit-button');
   const username = cy.get('#username-input');
   button.click()
});
```

上述代码块说明了一个测试，应该首先识别一个按钮，然后识别一个用户名输入，最后点击按钮。然而，测试和执行不会按照我们通常的假设方式进行。在我们的假设中，我们可能会认为第一个命令将在第二个命令运行之前执行并返回结果，然后第三个命令将是最后执行的。Cypress 利用 JavaScript 的**异步 API**来控制 Cypress 测试中命令的执行方式。

重要提示

异步 API 被实现为它们在收到命令或请求时提供响应，并不一定等待某个特定请求获得响应后再处理其他请求。相反，API 会返回收到的第一个响应，并继续执行尚未收到响应的响应。请求和接收响应的非阻塞机制确保可以同时进行不同的请求，因此使我们的应用程序看起来是多线程的，而实际上，它的本质是单线程的。

在前面的代码块中，Cypress 以异步顺序执行命令，响应不一定按照测试中发出请求的顺序返回。然而，我们可以强制 Cypress 按照我们的期望执行测试，我们将在下一节中介绍闭包时进行讨论。

## 闭包

当 Cypress 捆绑测试函数和对函数周围状态的引用时，就会创建闭包。闭包是 Cypress 大量借鉴的 JavaScript 概念。因此，Cypress 中的测试闭包将能够访问测试的外部范围，并且还将能够访问由测试函数创建的内部范围。我们将测试的局部功能范围称为**词法环境**，就像 JavaScript 函数中的情况一样。在下面的代码块中，我们可以看到 Cypress 中的闭包是什么，以及变量在闭包中如何被利用：

```js
describe('Closures', () => {
    it('creates a closure', () => {
       // { This is the external environment for the test }
      cy.get('#submit-button').then(($submitBtn) => {
       // $submitBtn is the Object of the yielded cy.get()
       // response
       // { This is the lexical environment for the test }
      })
	 // Code written here will not execute until .then()  
      //finishes execution
    })
  });
```

`$submitBtn`变量用于访问从`cy.get('#submit-button')`命令获取的响应。使用我们在测试中刚刚创建的变量，我们可以访问返回的值并与之交互，就像在普通函数中一样。在这个测试中，我们使用了`$submitBtn`变量创建了一个测试闭包函数。`.then()`函数创建了一个**回调函数**，使我们能够在代码块中嵌套其他命令。闭包的优势在于我们可以控制测试执行命令的方式。在我们的测试中，我们可以等待`.then()`方法内部的所有嵌套命令执行完毕，然后再运行测试中的其他命令。测试代码中的注释进一步描述了执行行为。

重要提示

回调函数是作为参数传递到其他函数中的函数，并在外部函数中被调用以完成一个动作。当我们的`.then()`函数内部的命令完成运行时，函数外部的其他命令将继续执行它们的执行例程。

在下面的代码块中，我们将探讨如何使用变量编写测试，并确保在闭包内部的代码执行之前，任何其他代码在闭包之外和闭包开始执行之后都不会执行。该测试将添加两个待办事项，但在添加第二个待办事项之前，我们将使用闭包来验证闭包内部的代码是否首先执行：

```js
it('can Add todo item - (Closures)', () => {
      cy.visit('http://todomvc.com/examples/react/#/')
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get('.todo-list>li:nth-child(1)').then(($todoItem) => {
        // Storing our todo item Name 
        const txt = $todoItem.text()
        expect(txt).to.eq('New Todo')
      });
      // This command will run after all the above commands  
      // have finished their execution.  
      cy.get(".new-todo").type("Another New Todo {Enter}");
    });
```

在前面的代码块中，我们已经向待办事项列表中添加了一个待办事项，但在添加第二个项目之前，我们验证添加的待办事项确实是我们创建的。为了实现这一点，我们使用了闭包和一个需要在执行下一个命令之前返回`true`的回调函数。以下截图显示了我们运行测试的执行步骤：

![图 8.1 - Cypress 中的闭包](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_8.1_B15616.jpg)

图 8.1 - Cypress 中的闭包

在*图 8.1*中，我们可以看到 Cypress 执行了获取添加的待办事项的命令，并断言添加的待办事项是我们在列表中拥有的，然后执行最后一个命令将新的待办事项添加到我们的待办事项列表中。

Cypress 中的闭包不能存在于变量之外。要使用闭包，我们需要利用变量将从我们的命令中接收的值传递给闭包函数，而利用变量是唯一的方法。在这个代码块中，我们使用了`$todoItem`变量将`cy.get()`命令的值传递给了断言找到的待办事项是我们创建的确切项目的闭包。

Cypress 像 JavaScript 一样利用变量作用域。在 Cypress 中，用户可以使用`const`、`var`和`let`标识符来指定变量声明的范围。在接下来的部分中，我们将看到可以在测试中使用的不同范围。

### Var

`var`关键字用于声明函数或全局作用域变量。为了初始化目的，为变量提供值是可选的。使用`var`关键字声明的变量在遇到测试函数时会在任何其他代码执行之前执行。可以使用`var`关键字在全局范围内声明变量，并在测试函数内的功能范围内覆盖它。以下代码块显示了使用`var`关键字声明的全局作用域变量的简单覆盖：

```js
describe('Cypress Variables', () => {
  var a = 20;
  it('var scope context', () => {
    a = 30; // overriding global scope
    expect(a).to.eq(30) // a = 30
  });
 it('var scope context - changed context', () => {
    // Variable scope remains the same as the change affects 
    // the global scope     expect(a).to.eq(30) //a = 30
  });
});
```

在这段代码中，我们在测试的全局上下文中声明了一个`a`变量，然后在测试中改变了全局变量。新更改的变量将成为我们的全局`a`变量的新值，除非它被明确更改，就像我们在测试中所做的那样。因此，`var`关键字改变了变量的全局上下文，因为它在全局重新分配了全局变量的值。

### Let

`let`变量声明的工作方式与使用`var`声明的变量相同，唯一的区别是定义的变量只能在声明它们的范围内使用。是的，我知道这听起来很混乱！在下面的代码块中，两个测试展示了在使用`let`关键字时的范围声明的差异：

```js
describe('Cypress Variables', () => {
  // Variable declaration
  let a = 20;
  it('let scope context', () => {
    let a = 30;
    // Local scoped variable
    expect(a).to.eq(30) // a = 30
  });
  it('let scope context - global', () => {
    // Global scoped variable
    expect(a).to.eq(30) // a = 20
  });

```

在这第二个测试中，由于`let`关键字只会使更改后的`a`变量对更改它的特定测试可用，而不会对整个测试套件的全局范围可用，因此我们有一个测试失败，就像使用`var`变量声明一样。在下面的截图中，我们可以看到测试失败，因为它只选择了在`describe`块中声明的变量，而没有选择前面测试中的变量：

![图 8.2 – let 关键字](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_8.2_B15616.jpg)

图 8.2 – let 关键字

如*图 8.2*所示，在编写测试时，可以在不影响声明变量的范围的情况下在不同的测试中对同一变量进行声明，因为每个变量都将属于并拥有自己的上下文，不会影响全局上下文。

### Const

`const`关键字用于声明只读的对象和变量，一旦声明后就不能被改变或重新赋值。使用`const`关键字分配的变量是“最终的”，只能在其当前状态下使用，其值不能被改变或改变。在下面的代码块中，我们试图重新分配使用`const`关键字声明的变量，这将导致失败：

```js
describe('const Keyword', () => {
    const a = 20;
    it('let scope context', () => {
      a = 30;
      // Fails as We cannot reassign
      // a variable declared with a const keyword
      expect(a).to.eq(30) // a = 20
    });
});
```

从这段代码中，考虑到`a`变量是用`const`声明的，它是不可变的，因此 Cypress 会因为错误而失败，如下面的截图所示：

![图 8.3 – const 关键字](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_8.3_B15616.jpg)

图 8.3 – const 关键字

就像在 JavaScript 中一样，Cypress 不能重新分配使用`const`关键字声明的变量。使用`const`声明的变量是在程序执行期间不需要在全局或局部范围内改变的变量。

## 总结 – 理解 Cypress 变量

在本节中，我们了解了 Cypress 中变量的利用。我们看了一下变量在闭包中的使用方式，以及它们如何在不同的范围和上下文中声明。在这里，我们还了解了变量范围的含义以及它们在测试中的使用方式。现在我们知道了变量是什么以及它们代表什么，我们将在下一节中深入了解 Cypress 测试中别名的使用。

# 理解 Cypress 别名

别名是一种避免在我们的测试中使用`.then()`回调函数的方法。我们使用别名来创建引用或某种“内存”，Cypress 可以引用，从而减少我们需要重新声明项目的需求。别名的常见用途是避免在我们的`before`和`beforeEach`测试钩子中使用回调函数。别名提供了一种“清晰”的方式来访问变量的全局状态，而无需在每个单独的测试中调用或初始化变量。在本节中，我们将学习如何正确地在我们的测试执行中利用别名，并介绍使用别名的不同场景。

在某些情况下，别名非常方便，其中一个变量被测试套件中的多个测试所使用。以下代码块显示了一个测试，我们希望验证在将待办事项添加到待办事项列表后，我们的待办事项确实存在：

```js
context('TODO MVC - Aliases Tests', () => {
  let text;
  beforeEach(() => {
    cy.visit('http://todomvc.com/examples/react/#/')
    cy.get(".new-todo").type("New Todo {Enter}");
    cy.get('.todo-list>li:nth-child(1)').then(($todoItem) => {
      text = $todoItem.text()
    });
  });
  it('gets added todo item', () => {
    // todo item text is available for use
    expect(text).to.eq('New Todo')
  });
});
```

要在`beforeEach`或`before`钩子中外部使用声明的变量，我们在代码块中使用回调函数来访问变量，然后断言由我们的`beforeEach`方法创建的变量的文本与我们期望的待办事项相同。

重要提示

代码结构仅用于演示目的，不建议在编写测试时使用。

虽然前面的测试肯定会通过，但这是 Cypress 别名存在的反模式。Cypress 别名存在的目的是为了在 Cypress 测试中提供以下目的：

+   在钩子和测试之间共享对象上下文

+   访问 DOM 中的元素引用

+   访问路由引用

+   访问请求引用

我们将研究别名的每个用途，并看看它们在覆盖的用途中如何使用的示例。

## 在测试钩子和测试之间共享上下文

别名可以提供一种“清晰”的方式来定义变量，并使它们在测试中可访问，而无需在测试钩子中使用回调函数，就像在前一个代码块中所示的那样。要创建别名，我们只需将`.as()`命令添加到我们要共享的内容，然后可以使用`this.*`命令从 Mocha 的上下文对象中访问共享的元素。每个测试的上下文在测试运行后都会被清除，因此我们的测试在不同的测试钩子中创建的属性也会被清除。以下代码块显示了与前一个相同的测试，以检查待办事项是否存在，但这次利用了别名：

```js
describe('Sharing Context between hooks and tests', () => {
    beforeEach(() => {
      cy.visit('http://todomvc.com/examples/react/#/');
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get('.todo-list>li:nth-
        child(1)').invoke('text').as('todoItem');
    });
    it('gets added todo item', function () {
      // todo item text is available for use
      expect(this.todoItem).to.eq('New Todo');
    });
  });
```

在上述代码块中，我们可以验证 Mocha 在其上下文中具有`this.todoItem`并成功运行，从而验证确实创建了待办事项。测试的进一步验证可以如下截图所示，突出显示了在使用别名引用我们待办事项列表中创建的待办事项后，Cypress 测试的通过状态：

![图 8.4 – 上下文共享](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_8.4_B15616.jpg)

图 8.4 – 上下文共享

在*图 8.4*中，我们看到 Cypress 突出显示了别名文本，并显示了它在我们的测试中是如何被调用的。Cypress 打印出了已使用的别名元素和命令，这样在失败时很容易识别和调试，并跟踪导致别名元素失败的原因。

重要提示

在您的 Cypress 测试中，无法使用箭头函数与`this.*`，因为`this.*`将指向箭头函数的**词法上下文**，而不是 Mocha 的上下文。对于任何使用`this`关键字的地方，您需要将 Cypress 测试切换为使用常规的`function () {}`语法，而不是`() => {}`。

别名在共享上下文方面的另一个很好的用途是与 Cypress fixtures 一起使用。Fixtures 是 Cypress 用于提供用于测试的模拟数据的功能。Fixtures 在文件中创建，并可以在测试中访问。

重要提示

固定提供测试数据，我们利用固定提供与应用程序期望的输入或在执行操作时生成的输出一致的数据。固定是我们为测试提供数据输入的简单方法，而无需在测试中硬编码数据或在测试运行时自动生成数据。使用固定，我们还可以为不同的测试利用相同的测试数据集。

假设我们有一个包含所有已创建待办事项列表的 `todos fixture`，我们可以编写类似以下代码块的测试：

```js
describe('Todo fixtures', () => {
    beforeEach(() => {
      // alias the todos fixtures
      cy.get(".new-todo").type("New Todo {Enter}");
      cy.get('.todo-list>li:nth-
        child(1)').invoke('text').as('todoItem')
      cy.fixture('todos.json').as('todos')
    })

    it('todo fixtures have name', function () {
      // access the todos property
      const todos = this.todos[0]

      // make sure the first todo item contains the first
      // todo item name
      expect(this.todoItem).to.contain(todos.name)
    })
  })
```

在前面的代码块中，我们为创建的待办事项和包含已创建待办事项的 `todos.json` 固定文件都创建了别名。我们可以在所有测试中利用待办事项的固定，因为我们在测试的 `beforeEach` 钩子中加载了固定。在这个测试中，我们使用 `this.todo[0]` 来访问我们的第一个固定值，它是我们待办事项数组中的第一个对象。要进一步了解如何使用固定和我们正在使用的确切文件，请查看我们在本章开头克隆的 GitHub 存储库，位于 `cypress/fixtures` 目录下。

重要提示

Cypress 仍然使用异步命令工作，尝试在 `beforeEach` 钩子之外访问 `this.todos` 将导致测试失败，因为测试首先需要加载固定才能使用它们。

在共享上下文时，Cypress 命令还可以使用特殊的 `'@'` 命令，这消除了在引用已声明别名的上下文时使用 `this.*` 的需要。以下代码块显示了在引用 Cypress 别名时使用 `'@'` 语法的用法：

```js
it('todo fixtures have name', () => {
      // access the todos property
      cy.get('@todos').then((todos) => {
        const todo = todos[0]
      // make sure the first todo item contains the first
      // todo item name
      expect(this.todoItem).to.contain(todo.name)
      });
    });
```

在前面的代码块中，我们使用了 `cy.get()` 命令来消除在访问我们的固定文件时使用 `this.*` 语法，以及使用旧式函数声明方法的需要。当我们使用 `this.todos` 时，我们是同步访问 `todos` 对象，而当我们引入 `cy.get('@todos')` 时，我们是异步访问 `todos` 对象。

如前所述，当 Cypress 以同步方式运行代码时，命令按照调用顺序执行。另一方面，当我们以异步方式运行 Cypress 测试时，由于命令的执行不是按照调用顺序进行的，所以执行的命令的响应也不会按照调用顺序返回。在我们的情况下，`this.todo`将作为同步命令执行，它将按照执行顺序返回 `todo` 对象结果，而 `cy.get('@todos')` 将像异步命令一样行为，并在可用时返回 `todo` 对象响应。

## 访问元素引用

别名还可以用于访问 DOM 元素以便重用。引用元素可以确保我们在引用别名后不需要重新声明 DOM 元素。在下面的代码块中，我们将为添加新待办事项的输入元素创建一个别名，并在创建待办事项时稍后引用它：

```js
it('can add a todo - DOM element access reference', () => {
      cy.get(".new-todo").as('todoInput');
      // Aliased todo input element
      cy.get('@todoInput').type("New Todo {Enter}");
      cy.get('@todoInput').type("Another New Todo {Enter}");
      cy.get(".todo-list").find('li').should('have.length', 2)
  });
```

这个测试展示了使用别名来访问已存储为引用的 DOM 元素。在测试中，Cypress 查找我们保存的 `'todoInput'` 引用并使用它，而不是运行另一个查询来查找我们的输入项。

## 访问路由引用

我们可以使用别名来引用测试应用程序的路由。路由管理网络请求的行为，通过使用别名，我们可以确保在进行请求时进行正确的请求，发送服务器请求，并在进行请求时创建正确的 XHR 对象断言。以下代码块显示了在处理路由时使用别名的用法：

```js
it('can wait for a todo response', () => {
      cy.server()
      cy.intercept('POST', '/todos', { id: 123 }).as('todoItem')
      cy.get('form').submit()
      cy.wait('@todoItem').its('requestBody')
        .should('have.property', 'name', 'New Todo')
      cy.contains('Successfully created item: New Todo')
    });
```

在这个代码块中，我们将我们的`todoItem`请求引用为别名。路由请求将检查我们提交的表单是否已成功提交并返回响应。在路由中使用别名时，我们不必保持引用或调用路由，因为 Cypress 已经从我们之前创建的别名中存储了路由的响应。

## 访问请求引用

就像访问路由引用时使用别名一样，我们可以使用 Cypress 访问 Cypress 请求并在以后使用请求的属性。在下面的代码块中，我们标识了一个特定评论的请求，并使用别名检查评论的属性：

```js
it('can wait for a comment response', () => {
      cy.request('https://jsonplaceholder.cypress.io/comments/6')
    .as('sixthComment');
      cy.get('@sixthComment').should((response) => {
        expect(response.body.id).to.eq(6)
    });
 });
```

测试对特定评论进行断言，并检查断言是否与评论的 ID 匹配。我们使用别名引用请求 URL，这样当运行我们的测试时，我们只需要引用我们已经别名的 URL，而不必完整输入它。运行测试的下面的屏幕截图显示了 Cypress 如何创建别名，并在运行测试时引用它：

![图 8.5 - 请求引用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_8.5_B15616.jpg)

图 8.5 - 请求引用

在上面的屏幕截图中，第一个`sixthComment`命令是 Cypress 创建别名的命令，第二个是运行测试识别别名并对从别名 URL 获取的响应进行断言的命令。

## 总结 - 了解 Cypress 别名

在本节中，我们学习了别名及其如何用于编写测试的“干净”代码，通过提供一种方式让我们可以访问和引用我们在测试中可能需要的请求、元素、路由和命令。我们还学习了 Cypress 别名的访问方式：通过异步方法，该方法在别名之前使用`@`符号，或者直接使用`this`关键字访问别名对象的同步方法。最后，我们学习了如何在测试中利用别名引用元素，使我们能够在测试中使用别名路由和请求。

# 总结

在本章中，我们学习了别名和变量以及如何在 Cypress 中利用它们。我们介绍了 Cypress 测试中的变量是什么，不同类型的变量及其作用域，以及如何利用它们。我们还介绍了 Cypress 中变量如何帮助创建闭包，以及如何创建只能被变量访问的环境，除了测试可访问的全局上下文。最后，我们看了如何使用别名以及别名的不同上下文。我们学习了如何在测试中引用别名，如何与元素、路由和请求一起使用它们，甚至用于测试钩子和测试本身之间的上下文共享。

通过本章，您已经掌握了了解别名和变量如何工作，别名如何在异步和同步场景中使用，以及何时以及如何创建和实现测试中变量的作用域的技能。

现在您完全了解了别名和变量的工作原理，我们已经准备好进行下一章，我们将了解测试运行器的工作原理。我们将深入研究测试运行器的不同方面以及如何解释测试运行器上发生的事件。


# 第九章：Cypress 测试运行器的高级用法

在我们开始讨论测试运行器的高级用法之前，您必须了解 Cypress 的工作原理、测试运行器的作用以及测试在测试运行器中的执行方式是至关重要的。本章是在您在前八章中所学到的 Cypress 知识的基础上构建的，并将重点放在帮助您理解测试运行器的高级功能上，这些功能在本书中尚未探讨过。

在本章中，我们将利用测试运行器，并通过利用测试运行器的内置功能来学习如何编写更好的测试。通过学习如何使用测试运行器，我们将更深入地了解测试的运行方式，当测试失败时会发生什么，以及如何改进它们。本章将涵盖以下关键主题：

+   理解仪表板

+   理解选择器游乐场

+   测试运行器键盘快捷键

一旦您学习了这些主题，您将完全了解测试运行器，以及如何充分利用它来编写您的测试。

## 技术要求

要开始，我们建议您从 GitHub 克隆包含本章中将编写的所有源代码和测试的存储库。

重要说明

我们已经在*第五章* *调试 Cypress 测试*中介绍了如何阅读和解释测试运行器中的 Cypress 错误。在该章节中，我们还介绍了如何与测试运行器中的 DOM 快照进行交互，其中我们涵盖了元素和命令日志之间的交互。在本章中，我们可能会参考*第五章* *调试 Cypress 测试*，或者进一步阐述该章节提供的信息。

本章的 GitHub 存储库可以在[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)找到。

本章的源代码可以在`chapter-09`目录中找到。

# 理解仪表板

仪表板是 Cypress 测试运行器中的一个特殊面板，只有当 Cypress 为您提供有关测试的其他信息时才可见。仪表板的出现是由特定命令触发的，这些命令提供了有关测试的更多信息。触发仪表板的命令包括`cy.stub()`、`cy.intercept()`和`cy.spy()`。在本节中，我们将探讨如何使用仪表板来显示有关测试的其他信息。

为了实现我们理解仪表板工作原理的目标，我们将不得不了解**拦截**、**存根**和**间谍**的工作原理，以及在 Cypress 测试中调用存根、路由和间谍时仪表板显示的具体信息。

## 拦截

Cypress 使用`cy.intercept()`命令来管理测试的网络层中的 HTTP 请求的行为。要理解拦截，我们首先需要了解 Cypress 中网络请求是如何进行的。Cypress 会在测试运行器上自动指示当运行测试时发出**XHR**（**XMLHttpRequest**）请求。Cypress 还会在请求被调用和响应被接收时创建 DOM 快照，这让我们了解了请求之前和之后 DOM 的情况。以下代码块是一个示例，用于从我们的 Todo 应用程序获取对 XHR 请求的响应：

```js
describe(Routing a request', () => {
    it('can wait for a app initialization, () => {
 	cy.intercept('POST','**/j/** 
     ').as('initializeTodoApp');
      cy.visit('http://todomvc.com/examples/react/#/');
      cy.wait('@initializeTodoApp'); // wait for intercept
      response
    })
  });
```

上述代码块显示了 Cypress 的`cy.intercept()`命令监听对初始化应用程序时 Cypress 预期进行的 XHR 响应。在测试中，我们正在验证确实已经向应用程序发出了请求，因为我们正在等待路由响应在我们的测试执行完成之前被调用。

Cypress 有能力解释请求，这使得框架可以轻松地通过监听测试发出的 HTTP 请求并知道请求调用返回的响应来管理 HTTP 请求。

在 Cypress 中，使用`cy.intercept()`命令进行拦截提供了覆盖 Cypress 测试执行期间由请求发出的 XHR 响应的能力。覆盖我们应用程序发出的 XHR 响应就是我们所谓的**存根**，我们将在本章后面讨论这个概念。

Cypress 在仪表板上记录了所有拦截的信息，通过查看面板，我们可以知道在我们的测试中匹配的路由数量，是否有任何与我们的路由匹配的响应，以及它们是否被存根。以下截图说明了使用仪表板来详细说明 Cypress 记录的有关路由的信息：

![图 9.1 – Cypress 仪表板](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_9.1_B15616.jpg)

图 9.1 – Cypress 仪表板

*图 9.1*显示了仪表板上标有**路由**的区域，其中包含了不同类型的信息列，当测试完成运行时，路由响应的信息就会显示在这里。路由仪表板中的不同列具有不同的目的，并且对于运行测试和仪表板都是重要的。以下是不同的列，每个列都有其在 Cypress 路由中的用途和重要性的描述：

+   **方法**（**1**）：**方法**列代表`cy.intercept()`命令期望的请求，根据预期的请求，它可以是**GET**、**POST**、**PUT**、**PATCH**甚至**DELETE**。

+   **URL**（**2**）：**URL**列将显示运行 Cypress 测试时`cy.intercept()`命令期望的 URL。在这种情况下，我们告诉 Cypress 查找任何以`learn.json`结尾的路由，如果遇到它，那么我们的测试应该通过。

+   **存根**（**3**）：**存根**列将显示我们的路由是否已被存根。当路由被存根时，Cypress 不会返回接收到的响应，而是返回我们传递给路由的响应。

+   **别名**（**4**）：**别名**列显示了我们在 Cypress 中给予路由的别名。在*第八章*中，*了解 Cypress 中的变量和别名*，我们学习了别名以及当我们需要访问元素、路由或请求的信息时它们可以是有用的。**别名**列中提供的别名是我们用来调用我们的路由的，我们将在别名前加上`@`前缀来做到这一点。

+   **#**（**5**）：这个匹配列将显示与我们的路由匹配的响应的计数。在我们的情况下，对我们的 URL 的请求只被发出了一次，因此我们的路由在我们的测试中只被调用了一次。

路由的仪表板信息足以让您了解在我们的测试中是否有任何 XHR 请求发送到已在我们的测试中声明的路由，并且方法和请求次数是否与应用程序中预期的一致。

## 存根

Cypress 中的存根用于替换函数，控制其行为或记录其使用情况。存根可用于用我们自己编写的合成响应替换实际方法。在下面的代码块中，我们将验证我们在测试运行时可以存根名为`foo`的方法：

```js
it('can stub a method', () => {
      let obj = {
        foo () {},
      }
      const stub = cy.stub(obj, 'foo').as('foo')
      obj.foo('foo', 'bar')
      expect(stub).to.be.called
    })
```

在前面的代码块中显示的`foo()`方法说明了存根的实际操作，从代码中我们可以看到我们期望 Cypress 知道我们的存根在测试中被调用了。以下截图显示了测试执行和通过测试的详细信息，包括存根类型、存根名称以及存根被调用的次数：

![图 9.2 – Cypress 存根](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_9.2_B15616.jpg)

图 9.2 – Cypress 存根

在*图 9.2*中，Cypress 显示了我们在仪表板中创建的存根，并显示了在执行测试过程中调用存根的次数。存根非常方便，因为我们可以存根化我们不想在范围内进行测试的依赖项或函数。

## 间谍

间谍的行为与存根完全相同，不同之处在于它们包装了间谍方法中的方法，以记录对函数的调用和参数。间谍仅用于验证 Cypress 中工作元素或方法。在测试中最常见的用法是验证测试中是否进行了某些调用，而不一定是为了改变对调用的期望，就像存根的情况一样。以下屏幕截图显示了我们验证`foo`方法是否在我们的`cy.spy()`方法中被调用的间谍：

![图 9.3-Cypress 间谍](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_9.3_B15616.jpg)

图 9.3-Cypress 间谍

在*图 9.3*中，仪表板在显示调用我们的`spy`函数时发挥了关键作用，函数的名称，分配给我们的间谍方法的别名以及我们的测试方法的类型。

## 总结-理解仪表板

在本节中，我们学习了如何利用仪表板来理解 Cypress 中的拦截、间谍和存根。我们还学习了拦截、间谍和存根实际上是如何工作的，以及仪表板上的信息对于理解我们的实现是否正确是有用的。在下一节中，我们将深入了解 Cypress 中的选择器游乐场以及它的工作原理。

# 理解选择器游乐场

选择器游乐场是 Cypress 测试运行器的一个交互式功能。选择器游乐场使您能够确定唯一选择器，检查与特定选择器匹配的元素，并检查与 Cypress 应用程序中特定文本匹配的元素。在本节中，我们将看看 Cypress 用于选择元素的不同策略，以及从测试运行器中如何识别我们可以在测试中使用的选择器。在本节结束时，您将学会如何使用 Cypress 使用选择器游乐场来唯一选择元素，以及如何使用 Cypress 使用的选择器策略来运行测试。

## 选择唯一元素

选择器游乐场可能是 Cypress 测试运行器中最未充分利用的功能之一，但对于想要编写具有有意义选择器的测试的人来说，它也是最有用的。选择器游乐场使我们能够识别测试应用程序中元素的有效选择器和唯一选择器。

在选择器游乐场中，Cypress 计算了目标元素的唯一选择器，并通过评估测试框架中默认启用的内置选择器策略来确定选择器。以下显示了两个添加的待办事项和一个打开的 Cypress 选择器游乐场，显示了我们如何唯一选择任何待办事项：

![图 9.4-Cypress 选择器游乐场](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_9.4_B15616.jpg)

图 9.4-Cypress 选择器游乐场

第一步是点击选择器游乐场按钮，一旦点击它，选择器游乐场菜单就会出现，如*图 9.4*所示。在选择器游乐场菜单中，您可以选择将选择器的类型更改为使用`cy.get()`选择其选择器的元素，或者使用元素文本，这可以通过将选择器切换为`cy.contains()`来找到。在`cy.get()`命令或`cy.contains()`命令中，是我们想要从应用程序预览中获取的特定元素或文本。为了确保任何元素或文本有资格成为唯一的元素选择器，匹配元素的数量，由选择器游乐场上的灰色表示，应为**1**，以确保我们没有元素或文本的重复。匹配元素标签旁边的按钮代表将选择器复制到剪贴板的复制命令，而下一个按钮是一个打印按钮，将我们选择或选择的命令打印到浏览器的控制台日志中。

当点击选择器游乐场下方的鼠标按钮时，Cypress 会自动显示一个弹出窗口，当用户悬停在元素上时，会自动选择一个可以用于在我们的测试中识别元素的唯一选择器。在*图 9.4*中，我们可以看到一旦悬停在**New Todo**项目上，Cypress 会将唯一选择器显示为工具提示，并且在单击元素时还会填充`cy.get()`命令。当在选择器游乐场菜单上选择元素时，Cypress 将在选择器游乐场上返回唯一的选择器。

### 选择器的确定

为了确定选择器游乐场中的唯一选择器，Cypress 使用了一种偏好策略，选择的选择器基于 Cypress 已知的一系列策略。Cypress 在选择和分配唯一选择器给元素时，偏好以下策略：

+   `data-cy`

+   `data-test`

+   `data-testid`

+   `id`

+   `class`

+   `tag`

+   `attributes`

+   `nth-child`

重要提示

选择器游乐场更喜欢以`data-*`开头的选择器策略作为它们的识别格式。在大多数情况下，选择器策略是自定义的，因此消除了由于应用程序中使用动态 ID、类名或 CSS 更改而导致测试不稳定的可能性。使用自定义的`data-*`标签，选择器标识符不会改变，并且可以在应用程序的整个生命周期中持续存在。

当元素可以通过任何这些选择器策略进行识别时，Cypress 将显示元素的唯一选择器。虽然这些策略是 Cypress 偏好的策略，但可以通过更改配置来使 Cypress 识别您的选择器策略，并将其添加到可识别的选择器策略列表中。

## 编辑选择器元素

选择器游乐场使用户能够编辑所选元素的选择器。编辑选择器元素的能力很重要，因为可以生成更有针对性的选择和更精细的选择器标记，这是 Cypress 本身可能无法做到的。Cypress 会自动识别对选择器游乐场所做的更改，并且当编辑的选择器元素有匹配时，将选择器游乐场突出显示为蓝色，如果在应用程序预览的选择器游乐场中对编辑的选择器标识符没有匹配时，则突出显示为红色。*图 9.5*和*图 9.6*显示了使用正确的元素选择器编辑选择器游乐场以及使用不正确的元素选择器：

![图 9.5 - 游乐场中的有效元素选择器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_9.5_B15616.jpg)

图 9.5 - 游乐场中的有效元素选择器

在*图 9.5*中，使用无效的元素选择器编辑选择器游乐场会显示错误，并用红色突出显示选择器游乐场，以向我们显示使用我们提供的选择器元素未找到任何元素。另一方面，*图 9.6*显示编辑选择器游乐场元素选择器是成功的：

![图 9.6-游乐场中的无效元素选择器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_9.6_B15616.jpg)

图 9.6-游乐场中的无效元素选择器

如*图 9.6*所示，我们能够使用在选择器游乐场中编辑的选择器选择我们的两个待办事项。蓝色显示了 Cypress 找到了我们正在搜索的元素，并通过在选择器游乐场中的元素选择器输入右侧显示元素数量来实现这一点。

## 总结-理解选择器游乐场

在这一部分，我们学习了选择器游乐场是什么，以及在使用测试运行器运行测试时它有多重要。我们学习了如何使用选择器游乐场来选择元素，修改元素，甚至从 Cypress 测试运行器的应用程序预览中选择和复制唯一元素。我们还学习了 Cypress 如何识别元素以及在选择元素时首选的选择器策略。最后，我们学习了如何在选择器游乐场中编辑定位器，以及如何确定我们的选择器是否有效。在下一节中，我们将看看测试运行器上的键盘快捷键是如何工作的。

# 测试运行器键盘快捷键

键盘快捷键在我们不想在浏览器上执行一系列步骤的情况下特别方便。在本节中，我们将学习如何使用三个键盘快捷键来控制 Cypress 测试运行器并有效地运行我们的测试。通过测试运行器，我们将比使用浏览器操作显式触发操作更快地执行常见操作。

以下是不同键盘键的映射及其关联的操作：

+   *R* - 重新运行规范文件的测试

+   *S* - 停止运行测试

+   *F* - 查看规范窗口中的所有测试

这些键盘键将根据用户的按键触发测试运行器上的不同操作。

## 总结-测试运行器键盘快捷键

在本节中，我们学习了如何使用 Cypress 键盘快捷键来控制测试运行器的常见操作，只需键盘上的三个键。我们还了解到，使用键盘执行操作比使用浏览器操作触发相同操作时更快。

# 总结

在本章中，我们学习了仪表板、选择器游乐场和 Cypress 测试运行器中的键盘快捷键。我们探讨了仪表板如何与存根、间谍和路由一起工作，并探讨了路由、存根和间谍的工作原理，以及仪表板中显示的信息。我们还看了选择器游乐场在 Cypress 中的应用以及我们如何利用它来识别应用程序测试中的元素，以及优化 Cypress 用于唯一选择元素的选择器。最后，我们学习了 Cypress 键盘快捷键的作用以及哪些键与使用浏览器功能可用的操作相对应。

现在我们知道并理解了 Cypress 中不同元素是如何联系在一起的，我们可以进一步通过练习来测试我们所学到的知识。在下一章中，我们将测试我们对导航、网络请求和测试的导航配置选项的了解。


# 第三部分：您的 Web 应用程序的自动化测试

本书的这一部分将让您接触到一些练习，这些练习将帮助您将在第一和第二部分中获得的知识融会贯通。本节包括在测试时的最佳实践，以及涵盖使用 Cypress 来测试大型应用程序。

在本节中，我们将涵盖以下章节：

+   *第十章*，*练习 - 导航和网络请求*

+   *第十一章*，*练习 - 桩和监听 XHR 请求*

+   *第十二章*，*Cypress 中的视觉测试*


# 第十章：练习-导航和网络请求

在开始本章之前，重要的是要理解，我们在本书的第三部分的重点将放在练习和示例上，这将帮助您磨练测试技能并建立我们在本书之前可能无法涵盖的知识。在本节中，我们将采取实践方法，目标是尽可能多地进行示例和练习。在深入研究本章之前，重要的是您已经阅读了每一章，并且现在希望在我们学习 Cypress 如何用于测试时，建立在您获得的理论知识基础上。

在本章中，我们将专注于涵盖以下主题的练习和示例：

+   实现导航请求

+   实现网络请求

+   高级导航请求配置

一旦您完成了这些练习，您将有信心成为更好的测试人员，并在导航和网络请求领域进行更复杂的测试。

## 技术要求

为了开始，建议您从 GitHub 克隆包含源代码和本章中将编写的所有测试的存储库。

本章的 GitHub 存储库可以在[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)找到。

本章的源代码可以在`chapter-10`目录中找到。

在我们的 GitHub 存储库中，我们有一个财务测试应用程序，我们将在本章中的不同示例和练习中使用 Cypress 导航和 Cypress 请求。

重要说明：在 Windows 中运行命令

注意：默认的 Windows 命令提示符和 PowerShell 无法正确解析目录位置。

请遵循以下列出的 Windows 命令，这些命令仅适用于以`*windows`结尾的 Windows 操作系统。

为了确保测试应用程序在您的机器上运行，请从应用程序的根文件夹目录中在您的终端上运行以下命令。

`npm run cypress-init`命令将安装应用程序运行所需的依赖项，另一方面，`npm run cypress-app`命令将启动应用程序。可选地，您可以使用`npm run cypress-app-reset`命令重置应用程序状态。重置应用程序会删除任何不属于应用程序的已添加数据，将应用程序状态恢复到克隆存储库时的状态。我们可以在终端中运行这些命令，就像它们在这里显示的那样：

```js
$ cd cypress/chapter-10;
$ npm install -g yarn or sudo npm install -g yarn
$ npm run cypress-init; (for Linux or Mac OS)
$ npm run cypress-init-windows; (for Windows OS)
// run this command if it's the first time running the application
or
$ npm run cypress-app (for Linux or Mac OS)
$ npm run cypress-app-windows; (for Windows OS)
// run this command if you had already run the application previously
Optionally
$ npm run cypress-app-reset; (for Linux or Mac OS)
$ npm run cypress-app-reset-windows; (for Windows OS)
// run this command to reset the application state after running your tests
```

重要说明

在我们的`chapter-10`目录中有两个主要文件夹，一个文件夹包含我们将用于示例和测试练习的应用程序，而第二个文件夹包含我们的 Cypress 测试。为了正确运行我们的测试，我们必须同时运行我们的应用程序和 Cypress 测试，因为测试是在我们本地机器上运行的实时应用程序上运行的。还要注意，应用程序将要求我们使用端口*3000*用于前端应用程序和端口*3001*用于后端应用程序。

掌握上述命令将确保您能够运行应用程序，重置应用程序状态，甚至安装应用程序的依赖项。现在让我们开始导航请求。

# 实现导航请求

Cypress 导航涉及导航到应用程序的网页的行为。在本书中我们已经涵盖了很多测试，在测试之前，您可能还记得`cy.visit()`命令，其中包含我们要导航到或正在测试的页面的 URL。`cy.visit()`命令是导航命令的一个例子，它帮助我们在 Cypress 前端测试中进行导航请求。在本节中，我们将通过示例和练习介绍不同的 Cypress 导航命令。通过本节结束时，我们将更深入地了解 Cypress 导航命令，这将帮助我们在本书前几章已经具备的导航知识基础上构建更多的知识。

## cy.visit()

在 Cypress 中，我们使用`cy.visit()`导航到被测试应用程序的远程页面。通过使用这个命令，我们还可以传递配置信息给命令，并配置选项，如方法、URL、超时选项，甚至查询参数；我们将在本章后面深入探讨该命令的配置选项。

在我们的 GitHub 存储库中，在`chapter-10/cypress-realworld-app`目录中，我们有一个应用程序，我们将在示例和练习中使用。

重要提示

我们的金融应用程序位于`chapter-10/cypress-realworld-app`目录中，记录交易。通过该应用程序，我们可以通过请求或支付用户来创建交易，这些交易已经存在于应用程序中。我们可以看到已发生交易的通知，还可以查看联系人和已发生交易的日志。

该应用程序使用 JSON 数据库，因此在将所有数据加载到我们的应用程序时会有点慢。在我们的测试中，我们已经实现了一个“安全开关”，通过确保在`beforeEach`方法中，我们等待所有初始的 XHR（XMLHttpRequest）请求加载数据，以防止测试失败。在下面的代码块中查看有关`beforeEach`方法的更多信息。

在我们的第一个示例中，在`navigation.spec.js`中，如下所示的代码块，我们将使用`cy.visit()`命令导航到应用程序的通知页面：

```js
describe('Navigation Tests', () => {
    beforeEach(() => {
 	cy.loginUser();
	cy.server();
	cy.intercept('bankAccounts').as('bankAccounts');
     	cy.intercept('transactions/public').as('transactions')
     ;
     	cy.intercept('notifications').as('notifications');
     	cy.wait('@bankAccounts');
     	cy.wait('@transactions');
     	cy.wait('@notifications');
});
    afterEach(() => { cy.logoutUser()});
    it('Navigates to notifications page', () => {
        cy.visit('notifications', { timeout: 30000 });
        cy.url().should('contain', 'notifications');
    });
});
```

这个代码块说明了`cy.visit()`命令的用法，我们访问远程 URL 到通知路由（`http://localhost:3000/notifications`），然后验证我们访问的远程 URL 是否符合预期。在我们的导航命令中，我们还添加了超时选项，确保在失败导航测试之前，Cypress 将等待 30 秒的“页面加载”事件。

以下截图显示了我们的测试正在执行，Cypress 正在等待从后端接收的 XHR 请求加载所有必须从我们的 JSON 数据库中加载的数据：

![图 10.1 - XHR API 请求和响应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_10.1_B15616.jpg)

图 10.1 - XHR API 请求和响应

在这个截图中，我们正在导航到`/signin`页面，然后等待所有资源加载完成后，我们使用 Cypress 的`cy.visit()`命令导航到`/notifications`页面，在测试应用程序预览的右侧可见。这进一步通过我们的测试断言进行验证，该断言验证访问的 URL 是否包含名称`notifications`。以下练习将帮助您更好地了解如何使用`cy.visit()`命令实现测试。

## 练习 1

使用 GitHub 存储库中提供的金融应用程序，位于`cypress-real-world-app`文件夹的根目录中，进行以下练习，测试您对`cy.visit()`命令的了解：

1.  登录到我们的测试应用程序，并使用`cy.visit()`命令导航到`http://localhost:3000/bankaccounts` URL。

1.  创建一个新的银行账户，然后检查在创建新的银行账户后应用程序是否重定向回`/bankaccounts` URL。

1.  登录应用程序，并使用`cy.visit()`命令尝试导航到`http://localhost:3000/signin`。

1.  成功登录测试用户后，验证 URL 重定向到仪表板而不是`/signin`页面。

练习的解决方案可以在`chapter-10/integration/navigation/navigation-exercise-solutions`目录中找到。

此练习将测试您理解`cy.visit()`命令的能力，确保作为 Cypress 用户，您可以有效地使用该命令导航到不同的 URL，并将参数和配置选项传递给命令。

## cy.go()

Cypress 的`cy.go()`导航命令使用户能够在测试应用程序中向前或向后导航。在使用`cy.go()`命令时，将'back'选项传递给命令将导致浏览器导航到浏览器历史记录的上一页，而'forward'选项将导致浏览器导航到页面的前进历史记录。我们还可以使用此命令通过传递数字选项作为参数来单击前进和后退按钮，其中'-1'选项将导航应用程序*后退*，而传递'1'将导致*前进*从浏览器历史记录中导航。

通过使用`cy.go()`，我们能够通过能够向后跳转到浏览器历史记录的上一页，以及向前跳转到浏览器历史记录的下一页，来操纵浏览器的导航行为。

重要提示

我们在`cy.visit()`命令中只使用`/bankaccounts`，因为我们已经在`cypress.json`文件中声明了`baseUrl`。`baseUrl`是 URL 的完整版本，我们在使用`cy.visit()`和`cy.intercept()`命令时不需要每次重复。您可以在开始本章时克隆的 GitHub 存储库中查看更多信息。

在以下代码块中，我们将使用我们的金融应用程序来验证我们可以在导航到`/bankaccounts`页面后返回到仪表板：

```js
describe('Navigation Tests', () => {
    it('cy.go(): Navigates front and backward', () => {
        cy.visit('bankaccounts');
        cy.url().should('contain', '/bankaccounts');
        cy.go('back');
        cy.url().should('eq', 'http://localhost:3000/');
    });
});
```

在此测试中，导航到`/bankaccounts` URL 后，我们然后使用 Cypress 内置的`cy.go('back')`命令导航回仪表板 URL，然后验证我们已成功导航回去。以下练习将更详细地介绍如何使用`cy.go()`命令。

## 练习 2

使用 GitHub 存储库中提供的金融应用程序，位于`chapter-10/cypress-real-world-app`目录中，执行以下练习以测试您对`cy.go()`命令的了解：

1.  登录后，在交易仪表板上，单击**Friends**选项卡，然后单击**Mine**选项卡。

1.  使用 Cypress 使用`cy.go()`命令返回到**Friends**选项卡。

1.  登录后，单击应用程序导航栏右上角的**New**按钮，并创建一个新交易。

1.  然后使用`cy.go()`Cypress 命令返回到仪表板页面，然后返回到新交易。

练习的解决方案可以在`chapter-10/integration/navigation/navigation-exercise-solutions`目录中找到。

此练习将帮助您建立使用`cy.go()`命令测试前进和后退导航的技能。它还将帮助您在测试应用程序时建立对导航的信心。

## cy.reload()

Cypress 的`cy.reload()`命令负责重新加载页面。该命令只有一组选项可以传递给它，即重新加载页面时清除缓存或重新加载页面时保留应用程序内存中的缓存。当将`true`的布尔值传递给`cy.reload()`方法时，Cypress 不会重新加载带有缓存的页面；相反，它会清除缓存并加载有关页面的新信息。省略布尔值会导致 Cypress 重新加载启用缓存的页面。在以下代码块中，我们在登录到我们的应用程序后重新加载仪表板；这将刷新我们仪表板页面的状态：

```js
it('cy.reload(): Navigates to notifications page', () => {
    cy.reload(true);
    });
```

在这个测试中，如果我们的浏览器中有任何缓存项目，Cypress 将重新加载页面并使缓存无效，以确保在执行我们的测试时创建页面的新状态和缓存。让我们看看下面的练习，了解更多关于使用`cy.reload()`命令的情景。

## 练习 3

使用 GitHub 存储库中提供的金融应用程序，位于`chapter-10/cypress-real-world-app`目录中，进行以下练习，以测试您对`cy.reload()`命令的了解：

1.  转到**账户**菜单项，那里有用户设置。

1.  在点击**保存**按钮之前，编辑您测试用户的名字和姓氏。

1.  重新加载页面并验证`cy.reload()`命令是否重置了尚未保存的所有设置。

练习的解决方案可以在`chapter-10/integration/navigation/navigation-exercise-solutions`目录中找到。

在这个练习中，我们已经学会了 reload 命令只会重置浏览器中暂时存储的项目。通过使用`cy.reload()`命令，我们了解了如何重置我们应用程序的缓存存储以及如何对其进行测试。

## 总结 - 实现导航请求

在本节中，我们通过评估示例和进行练习来学习了 Cypress 上的导航请求是如何工作的。我们还探讨了各种导航命令，如`cy.visit()`、`cy.go()`和`cy.reload()`，它们在执行 Cypress 中的导航请求时都扮演着重要角色。在下一节中，我们将深入研究如何使用练习和示例来实现网络请求。

# 实现网络请求

网络请求涉及处理向后端服务的 AJAX 和 XHR 请求。Cypress 使用其内置的`cy.request()`和`cy.intercept()`命令来处理这一点。在本节中，我们将采用实践方法，深入探讨如何使用示例和练习在 Cypress 中实现网络请求。在本书的*第九章*中，我们已经与网络请求进行了交互，本章将帮助您建立在您已经熟悉的理论知识和概念基础上。

## cy.request()

Cypress 的`cy.request()`命令负责向 API 端点发出 HTTP 请求。该命令可用于执行 API 请求并接收响应，而无需创建或导入外部库来处理我们的 API 请求和响应。我们的 Cypress 金融应用程序使用基于 JSON 数据库的后端 API。为了了解`cy.request()`命令的工作原理，我们将请求数据库并检查响应。以下代码块是一个请求，用于从我们的 API 中获取所有交易：

```js
it('cy.request(): fetch all transactions from our JSON database', () => {
        cy.request({
            url: 'http://localhost:3001/transactions',
            method: 'GET',
        }).then((response) => {
            expect(response.status).to.eq(200);
            expect(response.body.results).to.be.an
            ('array');
        })
    });
```

在上面的测试中，我们正在验证我们的后端是否以`200`状态代码和交易数据（数组）做出响应。我们将在下一个练习中了解更多关于`cy.request()`命令的内容。

## 练习 4

使用 GitHub 存储库中提供的金融应用程序，位于`chapter-10/cypress-real-world-app`目录中，进行以下练习，以测试您对`cy.server()`命令的了解。练习的解决方案可以在`chapter-10/integration/navigation/network-requests-excercise-solutions`目录中找到：

1.  登录后，使用您的浏览器，调查我们的`cypress-realworld`应用程序在我们首次登录时加载的 XHR 请求。

1.  根据观察，编写一个返回以下数据的测试：

应用程序中的联系人

应用程序中的通知

通过进行这个练习，您将更好地理解`cy.request()`命令，并增加对 Cypress 请求工作原理的了解。接下来，我们将看一下 Cypress 路由。

## cy.intercept()

`cy.intercept()`命令管理测试的网络层的 HTTP 请求的行为。通过该命令，我们可以了解是否进行了 XHR 请求，以及我们的请求的响应是否与我们的预期相匹配。我们甚至可以使用该命令来存根路由的响应。使用`cy.intercept()`，我们可以解析响应并确保我们实际上对于我们测试的应用程序有正确的响应。`cy.intercept()`命令使我们可以在所有阶段完全访问我们 Cypress 测试的所有 HTTP 请求。

重要提示

我们必须在测试中引用路由之前调用`cy.intercept()`，以便在测试中调用它们之前记录路由，并且从下面的测试中，我们可以观察到`beforeEach()`命令块中的行为。在接下来的测试中，我们在开始运行 Cypress 测试之前调用了`cy.intercept`命令。

在`network-request.spec.js`文件中找到的以下代码块中，我们正在验证在测试应用程序进行正确登录请求时，我们是否有用户信息的响应：

```js
describe('Netowork request routes', () => {
        beforeEach(() => {        
        cy.intercept('POST','login').as('userInformation');
        });

        it('cy.intercept(): verify login XHR is called when
        user logs in', () => {
            cy.login();
            cy.wait('@userInformation').its('
            response.statusCode').should('eq', 200)
        });
    });
```

在这个代码块中，我们正在验证应用程序是否向登录端点发出了`POST`请求，并且我们收到了成功的`200`状态，这是一个成功的登录。`cy.login()`命令导航到应用程序的登录页面。我们将在下一个练习中进一步使用`cy.intercept()`命令。

## 练习 5

使用 GitHub 存储库中提供的金融应用程序，位于`chapter-10/cypress-real-world-app`目录中，进行以下练习，以测试您对`cy.intercept()`命令的了解。练习的解决方案可以在`chapter-10/integration/navigation/network-requests-exercise-solutions`目录中找到：

1.  登录到测试应用程序并转到账户页面。

1.  使用 Cypress 的`cy.route()`命令来检查 Cypress 是否在更改用户信息时验证用户是否已登录。

是时候进行快速总结了。

## 总结-实施网络请求

在本节中，我们探讨了 Cypress 网络请求的工作原理，通过示例和练习来理解`cy.request()`和`cy.intercept()`在 Cypress 测试中的应用。通过示例和练习，我们还扩展了对如何使用诸如`cy.intercept()`之类的命令来操作和存根的知识。现在我们了解了网络请求，并且可以轻松地编写涉及 Cypress 网络请求的测试，在下一节中，我们将深入研究导航请求的高级配置。

# 高级导航请求配置

导航是正确运行测试的最重要的方面之一。通过使用`cy.visit()`、`cy.go()`甚至`cy.reload()`命令，我们能够知道在编写测试时应该采取什么样的快捷方式。导航命令还显著简化了测试工作流程。大多数前端测试都需要导航，因此掌握高级配置不仅会让您的生活更轻松，而且在编写测试时也会带来更顺畅的体验。在本节中，我们将主要关注 Cypress 的`cy.visit()`命令的高级命令配置，因为它是 Cypress 的主要导航命令。

## cy.visit() 配置选项

下表显示了`cy.visit()`命令的配置选项以及当没有传递选项给选项对象时加载的默认值：

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/B15616_10_Table_1a.jpg)![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/B15616_10_Table_1b.jpg)

`cy.visit()`命令接受不同类型的参数，这决定了传递给它的配置和选项。以下是该命令接受的参数：

+   只使用 URL 进行配置：

```js
cy.visit(url)
e.g. cy.visit('https://test.com');
```

+   使用 URL 和选项作为对象的配置：

```js
cy.visit(url, options)
e.g. cy.visit('https://test.com', {timeout: 20000});
```

+   只使用选项作为对象进行配置：

```js
cy.visit(options);
e.g. cy.visit('{timeout: 30000}');
```

现在是总结时间！

## 总结-高级导航请求配置

在本节中，我们学习了如何使用不同的选项配置`cy.visit()`命令，以及该命令接受的不同类型的参数。我们还学习了 Cypress 在没有传递选项对象时为我们提供的不同默认选项，这使得使用`cy.visit()`命令的过程变得简单，因为我们只需要向命令提供我们需要在测试中覆盖的选项。

# 总结

在本章中，我们学习了 Cypress 如何执行导航，如何创建请求以及 Cypress 如何解释和返回它们以进行我们的测试执行过程。我们采用了实践方法来学习三个基本的 Cypress 导航命令，以及 Cypress 用于创建和解释请求的三个命令。这些练习为您提供了一个渠道，让您走出舒适区，并对 Cypress 的高级用法进行一些研究，以及如何将我们在本书中获得的逻辑和知识整合到编写有意义的测试中，从而为被测试的应用程序增加价值。最后，我们看了一下`cy.visit()`命令的高级配置选项。我相信在本章中，您学会了处理和实现测试中的导航和网络请求的技能，以及配置导航请求。

现在我们已经实际探索了使用 Cypress 进行导航和请求，接下来我们将在下一章中使用相同的方法来处理使用 Cypress 进行测试的存根和间谍。


# 第十一章：练习-存根和监视 XHR 请求

在开始本章之前，您需要了解为什么需要存根或监视请求和方法，为此，您需要了解 Cypress 请求以及如何测试单个方法。之前的章节已经介绍了如何轻松开始使用 Cypress，并且我们已经涵盖了与网络请求和功能测试相关的概念。在本章中，我们将在之前章节中获得的概念基础上进行构建，重点是通过示例和练习的实践方法。

在本章中，我们将涵盖以下关键主题：

+   理解 XHR 请求

+   理解如何存根请求

+   理解如何在测试中监视方法

完成每个主题后，您将准备好开始使用 Cypress 进行视觉测试。

## 技术要求

为了开始，我们建议您从 GitHub 克隆包含源代码、所有测试、练习和解决方案的存储库，这些内容将在本章中编写。

本章的 GitHub 存储库可以在[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)找到。本章的源代码可以在`chapter-11`目录中找到。

在我们的 GitHub 存储库中，我们有一个财务测试应用程序，我们将在本章的不同示例和练习中使用。

重要提示：在 Windows 中运行命令

注意：默认的 Windows 命令提示符和 PowerShell 无法正确解析目录位置。

请遵循进一步列出的适用于 Windows 操作系统的 Windows 命令，并在末尾加上`*windows`。

为了确保测试应用程序在您的计算机上运行，请在终端中从应用程序的根文件夹目录运行以下命令：

```js
$ cd cypress/chapter-11;
$ npm install -g yarn or sudo npm install -g yarn
$ npm run cypress-init; (for Linux or Mac OS)
$ npm run cypress-init-windows; (for Windows OS)
// run this command if it's the first time running the application
or
$ npm run cypress-app (for Linux or Mac OS)
$ npm run cypress-app-windows; (for Windows OS)
// run this command if you had already run the application previously
Optionally
$ npm run cypress-app-reset; (for Linux or Mac OS)
$ npm run cypress-app-reset-windows; (for Windows OS)
// run this command to reset the application state after running your tests
```

重要提示

我们的测试位于`chapter-11`目录中，测试应用程序位于存储库的根目录中。为了正确运行我们的测试，我们必须同时运行我们的应用程序和 Cypress 测试，因为测试是在我们本地计算机上运行的实时应用程序上运行的。还要注意，应用程序将需要使用端口`3000`用于前端应用程序和端口`3001`用于服务器应用程序。

第一个命令将导航到我们的应用程序所在的`cypress-realworld-app`目录。然后，`npm run cypress-init`命令将安装应用程序运行所需的依赖项，`npm run cypress-app`命令将启动应用程序。可选地，您可以使用`npm run cypress-app-reset`命令重置应用程序状态。重置应用程序会删除任何不属于应用程序的已添加数据，将应用程序状态恢复到克隆存储库时的状态。

# 理解 XHR 请求

**XMLHttpRequest**（**XHR**）是现代浏览器中存在的 API，它以对象的形式存在，其方法用于在 Web 浏览器发送请求和 Web 服务器提供响应之间传输数据。XHR API 是独特的，因为我们可以使用它在不重新加载页面的情况下更新浏览器页面，请求和接收页面加载后的服务器数据，甚至将数据作为后台任务发送到服务器。在本节中，我们将介绍 XHR 请求的基础知识以及在编写 Cypress 测试过程中的重要性。

## 在测试中利用 XHR 请求

XHR 请求是开发人员的梦想，因为它们允许您*悄悄地*发送和接收来自服务器的数据，而不必担心诸如错误或等待时间等问题，当客户端应用程序需要重新加载以执行操作时。虽然 XHR 对开发人员来说是一个梦想，但对测试人员来说却是一场噩梦，因为它引入了诸如无法知道请求何时完成处理，甚至无法知道数据何时从服务器返回等不确定性。

为了解决 XHR 不确定性的问题，Cypress 引入了`cy.intercept()`命令，我们在*第九章*和*第十章*中深入研究了这个命令，分别是*高级 Cypress 测试运行*和*练习-导航和网络请求*中的网络请求部分。`cy.intercept()`命令监听 XHR 响应，并知道 Cypress 何时返回特定 XHR 请求的响应。使用`cy.intercept()`命令，我们可以指示 Cypress 等待直到接收到特定请求的响应，这使得我们在编写等待来自服务器的响应的测试时更加确定。

`xhr-requests/xhr.spec.js`文件中的以下代码块显示了将用户登录到我们的财务测试应用程序的代码。当用户登录时，应用程序会向服务器发送请求，以加载应用程序所需的通知、银行账户和交易明细。这些详细信息作为 XHR 响应从 API 服务器返回：

```js
describe('XHR Requests', () => {
    it('logs in a user', () => {
        cy.intercept('bankAccounts').as('bankAccounts');
        cy.intercept('transactions/public').
        as('transactions');
        cy.intercept('notifications').as('notifications');
        cy.visit('signin'); 
        cy.get('#username').type('Katharina_Bernier');
        cy.get('#password').type('s3cret');
        cy.get('[data-test="signin-submit"]').click()
        cy.wait('@bankAccounts').its('response.statusCode'
        ).should('eq', 200);
        cy.wait('@transactions').its('response.statusCode
        ').should('eq', 304);
        cy.wait('@notifications').its('response.statusCode
        ').should('eq', 304);
    });
});
```

在上述代码块中，我们正在登录用户，并等待 Cypress 返回我们从服务器发送的交易、通知和银行账户请求的 XHR 响应。只有在成功的用户登录尝试时才会发送响应。我们可以通过以下截图来可视化 Cypress 如何在测试中处理 XHR 请求：

![图 11.1-XHR 请求和来自服务器的响应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_11.1_B15616.jpg)

图 11.1-XHR 请求和来自服务器的响应

这个截图显示了应用程序向我们的服务器发送`/bankAccounts`、`/transactions`和`/notifications`的 XHR 请求。为了使我们的测试具有确定性，并且为了等待指定的时间以确保成功登录，我们使用`cy.intercept()`命令来检查 XHR 请求的响应何时被服务器发送回来，以及它们是否以正确的状态码发送回来。

在测试中等待 XHR 响应给我们带来了明显的优势，这些优势超过了没有处理等待的*失败机制*或者具有显式时间等待的测试。等待 XHR 响应的替代方法是显式等待特定的时间量，这只是一个估计值，并不是 Cypress 等待特定响应的确切时间。在运行我们的测试时等待路由响应的一些优势如下：

+   能够断言从路由返回的 XHR 响应对象

+   创建健壮的测试，从而减少不稳定性

+   具有精确性的失败消息

+   能够存根响应和“伪造”服务器响应

通过突出这些优势，使用 XHR 请求帮助我们确定地知道何时收到响应，以及 Cypress 何时可以继续执行我们的命令，已经收到了应用程序所需的所有响应。

## 总结-在测试中利用 XHR 请求

在本节中，我们了解了 XHR 请求，它们是什么，以及 Cypress 如何利用它们向应用程序服务器发送和获取请求。我们还学习了如何等待 XHR 响应以减少不稳定的测试，通过确定性地等待来自我们服务器响应的响应。我们还学习了 XHR 如何帮助我们，我们如何拥有精确的失败消息，甚至如何断言来自我们服务器响应的响应。最后，我们将通过使用`cy.intercept()`命令与 XHR 响应以及能够通过减少测试不确定性来控制测试执行的潜在好处。在下一节中，我们将看看如何使用存根来控制来自服务器的 XHR 响应。

# 了解如何存根请求

现在我们知道了什么是 XHR 请求，重要的是要知道我们如何帮助 Cypress 测试 XHR 请求，更重要的是，我们如何避免来自服务器的实际响应，而是创建我们自己的“假”响应，我们的应用程序将解释为来自服务器发送的实际响应。在本节中，我们将看看如何存根 XHR 请求到服务器，何时存根请求以及存根服务器请求对我们的测试的影响。

## 存根 XHR 请求

Cypress 灵活地允许用户要么使他们的请求到达服务器，要么在应用程序发出对服务器端点的请求时，使用存根响应。有了 Cypress 的灵活性，我们甚至可以允许一些请求通过到服务器，同时拒绝其他请求并代替它们进行存根。存根 XHR 响应为我们的测试增加了一层控制。通过存根，我们可以控制返回给客户端的数据，并且可以访问更改**body**、**status**和**headers**的响应，甚至在需要模拟服务器响应中的网络延迟时引入延迟。

### 存根请求的优势

存根请求使我们对返回给测试的响应以及由应用程序向服务器发出请求时将收到的数据具有更多控制。以下是存根请求的优势：

+   对响应的 body、headers 和 status 具有控制权。

+   响应的快速响应时间。

+   服务器不需要进行任何代码更改。

+   可以向请求添加网络延迟模拟。

接下来，让我们也看看一些缺点。

### 存根请求的缺点

虽然存根是处理 Cypress 客户端应用程序测试中的 XHR 响应的一种好方法，但它也有一些缺点，如下所示：

+   无法对某些服务器端点进行测试覆盖。

+   无法保证响应数据和存根数据匹配

建议在大多数测试中存根 XHR 响应，以减少执行测试所需的时间，并且还要在存根和实际 API 响应之间有一个健康的混合。在 Cypress 中，XHR 存根也最适合与 JSON API 一起使用。

在`xhr-requests/xhr-stubbing.spec.js`文件的以下代码块中，我们将对`bankAccounts`端点进行存根，并在运行应用程序时避免实际请求到服务器：

```js
describe('XHR Stubbed Requests', () => {    
    it('Stubs bank Account XHR server response', () => {
        cy.intercept('GET', 'bankAccounts',
        {results: [{id :"RskoB7r4Bic", userId :"t45AiwidW",
        bankName: "Test Bank Account", accountNumber 
        :"6123387981", routingNumber :"851823229", 
        isDeleted: false}]})
        .as('bankAccounts');
        cy.intercept('GET', 'transactions/public').
        as('transactions');
        cy.intercept('notifications').as('notifications');
        cy.wait('@transactions').its('
        response.statusCode').should('eq', 304);
        cy.wait('@notifications').its('
        response.statusCode').should('eq', 304);
        cy.wait('@bankAccounts').then((xhr) => {
            expect(xhr.response.body.results[0].
            bankName).to.eq('Test Bank Account')
            expect(xhr.response.body.results[0].
            accountNumber).to.eq('6123387981')  
        });
    });
});
```

在上述代码块中，我们对`/bankaccounts`服务器响应进行了存根，并且我们提供了一个几乎与服务器将要发送的响应几乎相同的响应，而不是等待响应。以下截图显示了成功的存根响应以及我们使用存根响应向客户端提供的“假”存根银行账户信息：

![图 11.2 - 客户端应用程序中的存根 XHR 响应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_11.2_B15616.jpg)

图 11.2 - 客户端应用程序中的存根 XHR 响应

在*图 11.2*中，我们可以看到几乎不可能判断我们的响应是存根化的还是从服务器接收的。使用 Cypress，客户端应用程序无法识别响应是真正从服务器发送的还是存根化的，这使得 Cypress 成为拦截请求并发送响应的有效工具，否则这些响应将需要很长时间才能从服务器发送。我们将在以下练习中了解更多关于存根化 XHR 响应的知识。

## 练习 1

使用 GitHub 存储库中提供的金融应用程序，位于`cypress-realworld-app`目录中，进行以下练习，以测试您对存根化 XHR 响应的了解。练习的解决方案可以在`chapter-11/integration/xhr-requests-exercises`目录中找到：

1.  存根化应用程序的登录 POST 请求，而不是在仪表板中返回测试用户的名称，而是更改为反映您的名称和用户名。

断言返回的响应确实包含您的用户名和名称信息，这些信息已经被存根化。以下屏幕截图显示了应更改的页面信息：

![图 11.3 - 通过存根化登录响应来更改名称和用户名](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_11.3_B15616.jpg)

图 11.3 - 通过存根化登录响应来更改名称和用户名

重要提示

要正确地存根化响应，您需要了解服务器在路由未存根化时发送的响应。为此，请在浏览器上打开浏览器控制台，单击**网络**选项卡，然后选择**XHR 过滤器**选项。现在您可以看到所有发送到服务器并由客户端接收的响应和请求。要获取特定请求以进行存根化，您应单击确切的请求并从浏览器控制台的**网络**窗口的**响应**选项卡中复制响应。确切的响应（或结构类似的响应）是我们应该用来存根化我们的服务器响应，以确保对客户端的响应一致性。从**网络**窗口，我们还可以获取有关与请求一起发送和接收的标头以及用于将请求发送到服务器的实际 URL 的信息。

以下屏幕截图显示了服务器返回的**通知**XHR 响应的示例：

![图 11.4 - Chrome 浏览器控制台上通知端点的服务器 XHR 响应](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_11.4_B15616.jpg)

图 11.4 - Chrome 浏览器控制台上通知端点的服务器 XHR 响应

1.  成功登录后，从`Everyone Dashboard`选项卡中选择一个随机交易，并将交易金额修改为$100。

通过这个练习，您不仅学会了如何存根化 XHR 响应，还学会了客户端如何处理从服务器接收到的数据。通过了解 XHR 响应存根化的好处，您现在已经准备好处理涉及存根化响应的复杂 Cypress 测试了。

## 总结 - 了解如何存根请求

在本节中，我们学习了如何使用 XHR 服务器请求来接收请求，还学习了如何通过存根来拦截发送的请求。我们还学习了如何使用存根来控制我们发送回客户端应用程序的响应的性质，以及如何断言我们的存根化响应看起来与我们从服务器接收到的客户端响应类似。最后，我们学习了如何使用浏览器来识别哪些响应需要存根，并使用我们正在存根的响应的内容。在下一节中，我们将看看间谍工作的原理以及如何在我们的 Cypress 方法中利用它。

# 了解如何在测试中对方法进行间谍

间谍和存根密切相关，不同之处在于，与可以用于修改方法或请求的数据的存根不同，间谍仅获取方法或请求的状态，并且无法修改方法或请求。它们就像现实生活中的间谍一样，只跟踪和报告。间谍帮助我们了解测试的执行情况，哪些元素已被调用，以及已执行了什么。在本节中，我们将学习 Cypress 中间谍的概念，监视方法的优点以及如何利用监视编写更好的 Cypress 测试。

## 为什么要监视？

我们在 Cypress 中使用间谍来记录方法的调用以及方法的参数。通过使用间谍，我们可以断言特定方法被调用了特定次数，并且使用了正确的参数进行了调用。我们甚至可以知道方法的返回值，或者在调用时方法的执行上下文。间谍主要用于单元测试环境，但也适用于集成环境，例如测试两个函数是否正确集成，并且在一起执行时能够和谐工作。执行`cy.spy()`命令时返回一个值，而不是像几乎所有其他 Cypress 命令一样返回一个 promise。`cy.spy()`命令没有超时，并且不能进一步与其他 Cypress 命令链接。

### 间谍的优点

以下是在测试中使用间谍的一些优点：

+   间谍不会修改调用的请求或方法。

+   间谍使您能够快速验证方法是否已被调用。

+   它们提供了一种测试功能集成的简单方法。

监视是一个有趣的概念，因为它引入了一种在不必对结果采取行动的情况下监视方法的方式。在下面的代码块中，我们有一个测试，其中包含一个简单的函数来求两个数字的和：

```js
  it('cy.spy(): calls sum method with arguments', () => {
        const obj = {
            sum(a, b) {
                return a + b
            }
        }
        const spyRequest = cy.spy(obj, 'sum').as('sumSpy');
        const spyRequestWithArgs = spyRequest.withArgs(1, 
        2).as('sumSpyWithArgs')
        obj.sum(1, 2); //spy trigger 
        expect(spyRequest).to.be.called;
        expect(spyRequestWithArgs).to.be.called;
        expect(spyRequest.returnValues[0]).to.eq(3);
    });
```

在上述方法中，我们设置了`cy.spy()`来监视我们的`sum`方法，并在调用方法或使用参数调用方法时触发间谍。每当方法被调用时，我们的间谍将记录它被调用的次数，我们还可以继续检查我们的方法是否被调用了任何参数。`sum`函数位于 JavaScript 对象中，触发间谍方法的是`obj.sum(1, 2)` sum 函数调用，在我们的测试中的断言执行之前被调用。以下屏幕截图显示了间谍、调用次数和测试的别名：

![图 11.5 - 监视 sum 方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_11.5_B15616.jpg)

图 11.5 - 监视 sum 方法

查看使用`cy.spy()`方法在`sum()`函数上的方法，我们可以看到`sum`方法的间谍和使用参数调用的`sum`方法在`sum`方法开始执行时都被触发了一次。

在下一个示例中，我们将探索一个更复杂的场景，我们将尝试监视一个从服务器返回我们 JSON 数据库中所有交易的方法。以下代码块显示了将获取所有交易的方法的间谍：

```js
it('cy.spy(): fetches all transactions from our JSON database', () => {
        const obj = {
          fetch(url, method) {
                return cy.request({
                    url,
                    method
                }).then((response) => response);
            }
        }
        const spyRequest = cy.spy(obj, 
        'fetch').as('reqSpy');
        obj.fetch('http://localhost:3001/transactions', 
        'GET');
        expect(spyRequest).to.be.called;
        expect(spyRequest.args[0][0]).to.eq
        ('http://localhost:3001/transactions')
        expect(spyRequest.args[0][1]).to.eq('GET');
    });
```

在这个测试中，我们正在验证从数据库获取交易的请求是否发生。通过这个测试，我们可以监视我们的方法，并检查在调用方法时是否传递了正确的参数。

很明显，使用间谍，我们能够确定调用了哪些方法，它们被调用了多少次，以及在调用方法时使用了什么参数。我们将在下一个练习中了解更多关于间谍的知识。

## 练习 2

使用 GitHub 存储库中提供的金融应用程序，位于`cypress-realworld-app`目录中，进行以下练习，以测试您对存根 XHR 响应的了解。练习的解决方案可以在`chapter-11/integration/spies-exercise`目录中找到：

1.  创建一个名为`Area`的方法来计算三角形的面积，对`area`方法进行间谍活动，并调用该方法来断言确实使用了`cy.spy()`对`area`方法进行了间谍活动。断言该方法也是使用`base`和`height`参数进行调用的。

1.  使用我们的应用程序，以用户身份登录并对 API 请求方法进行间谍活动，以获取该已登录用户的所有银行账户。断言已调用该方法向服务器发出 API 请求，并且参数作为方法的参数传递。

这个练习将帮助你了解间谍在 Cypress 中是如何工作的，以及可以使用`cy.spy()`的不同方法来查找被监视的方法的内容。通过监视方法，我们还能够判断方法参数是否被调用以及它们是如何被调用的，还有返回值。

## 总结-了解如何在测试中对方法进行间谍活动

在这一部分，我们学习了关于间谍活动的重要性以及它与存根活动的不同之处，因为我们不被允许改变被监视方法或请求的值。我们还学会了如何使用存根活动来识别方法的参数、方法被调用的次数、执行上下文，以及被监视方法的返回值。通过例子和练习，我们还学会了如何与`cy.spy()`命令进行交互，这帮助我们了解了该命令以及它在方法上下文中的工作方式。

# 总结

这一章的重点主要是 XHR 请求和响应以及它们如何与客户端和服务器进行交互。我们首先了解了 XHR 请求和响应是什么，以及当我们想要从客户端发送请求并从服务器接收请求时它们是多么重要。在这一章中，我们还看到了如何通过使用内置在`cy.intercept()`命令中的 Cypress 存根功能来存根 XHR 响应来“伪造”服务器响应。最后，我们探讨了 Cypress `cy.spy()`命令，这进一步让我们了解了如何在 Cypress 中监视方法，并获得找出方法被执行的次数、它们是如何被执行的、它们的参数，甚至它们的返回值的能力。在最后一节中，我们学会了知道通过间谍，我们只能“观察”执行的过程，而不一定有能力改变被测试的请求或方法的执行过程。

我相信通过这一章，你已经掌握了 XHR 请求是什么，它们是如何工作的，如何对它们进行存根，以及如何在 Cypress 中进行间谍活动的技能。在下一章中，我们将看看 Cypress 中的视觉测试。


# 第十二章：Cypress 中的视觉测试

在开始进行视觉测试之前，您应该了解其他形式的测试以及我们如何使用 Cypress 来完成这些测试。本书的前几章介绍了如何轻松入门 Cypress，如何配置 Cypress，以及如何优化您使用 Cypress 来为测试编写过程开发更有创意的工作流程。前几章的背景信息将为您提供解决本章所需的上下文。本书的最后一章将重点介绍使用 Cypress 进行视觉测试。

在本章中，我们将介绍视觉测试的基础知识，并了解为什么我们需要它。我们还将学习一些工具，可以用来进行视觉测试。本章的主题将帮助你作为工程师或测试人员理解为什么视觉测试对于 Web 应用程序很重要，以及我们如何利用它来编写更好的测试。

我们将在本章中涵盖以下关键主题：

+   视觉测试

+   理解视口

+   Cypress 测试中的视觉测试工具

一旦您完成了每个主题，您将准备好开始使用 Cypress 作为您的选择工具进入自动化测试世界的旅程。

## 技术要求

要开始，请克隆本书的 GitHub 存储库，其中包含本章中将编写的所有源代码、测试、练习和解决方案。

本章的 GitHub 存储库可以在[`github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress`](https://github.com/PacktPublishing/End-to-End-Web-Testing-with-Cypress)找到。

本章的源代码可以在`chapter-12`目录中找到。

在我们的 GitHub 存储库中，我们有一个金融测试应用程序，我们将在本章的不同示例和练习中使用它。

重要提示：在 Windows 中运行命令

注：默认的 Windows 命令提示符和 PowerShell 无法正确解析目录位置。

请遵循以下列出的 Windows 命令，这些命令仅适用于 Windows 操作系统，并以`*windows`结尾。

为了确保测试应用程序在您的计算机上运行，请从存储库的根文件夹目录中在您计算机的终端上运行以下命令：

```js
$ cd cypress/chapter-12;
$ npm install -g yarn or sudo npm install -g yarn
$ npm run cypress-init; (for Linux or Mac OS)
$ npm run cypress-init-windows; (for Windows OS)
// run this command if it's the first time running the
application
or
$ npm run cypress-app (for Linux or Mac OS)
$ npm run cypress-app-windows; (for Windows OS)
// run this command if you had already run the application
previously
Optionally
$ npm run cypress-app-reset; (for Linux or Mac OS)
$ npm run cypress-app-reset-windows; (for Windows OS)
// run this command to reset the application state after
running your tests
```

重要提示

我们的测试位于`chapter-12`目录中，测试应用程序位于存储库的根目录中。为了正确运行我们的测试，我们必须同时运行我们的应用程序和 Cypress 测试，因为测试是在实时应用程序上运行的，而这个应用程序必须在我们的计算机上本地运行。重要的是要注意，测试应用程序将需要使用端口`3000`用于前端应用程序和端口`3001`用于服务器应用程序。

第一个命令将导航到`cypress-realworld-app`目录，这是我们的应用程序所在的位置。`npm run cypress-init`命令将安装应用程序运行所需的依赖项，而`npm run cypress-app`命令将启动应用程序。可选地，您可以使用`npm run cypress-app-reset`命令重置应用程序状态。重置应用程序会删除任何不属于应用程序的已添加数据，从而将应用程序状态恢复到克隆存储库时的状态。

# 视觉测试

无论您是 Web 开发人员还是测试人员，都需要确保正在开发的应用程序保留了项目概念时预期的外观和感觉。作为开发人员，您可能希望验证应用程序在发布之间没有发生视觉方面的变化。作为测试人员，您可能希望验证应用程序的用户界面在发布之间保持一致，并且与设计一致。

**功能测试**可以用来检查视觉方面，比如验证按钮或输入框是否存在。然而，这可能需要编写大量代码，并且大多数情况下，它不会允许您测试应用程序的每个方面，比如在验证用户界面元素时使用 CSS 更改。视觉测试是验证应用程序用户界面的视觉方面，并确保它们与预期一致的能力。

在本节中，我们将学习什么是视觉测试，视觉测试的不同类型是什么，手动和自动视觉测试之间的区别，以及何时使用不同类型的视觉测试方法。

## 为什么要进行视觉测试？

视觉测试采取了实际的方法，因为您必须直接映射页面的视觉方面，并将这些方面与预期的设计进行比较。我们可能会忽略视觉测试的想法，因为我们认为我们的眼睛对于验证目的足够准确，这是一个错误的假设。虽然肉眼可以注意到可见的页面变化，但对于眼睛来说，检测微小的细节，比如改变 CSS 属性导致输入元素移动了几个像素或者像素变化很小，可能会更加困难。

视觉测试的存在是为了让开发人员和测试人员确信网页的用户界面没有被任何开发人员的更改破坏。例如，通过视觉测试，如果部署到生产环境的应用程序版本缺少注册按钮，而以前的应用程序版本有该按钮，就不需要担心。

有两种类型的视觉测试，如下所示：

+   手动视觉测试

+   自动化视觉测试

这两种类型的视觉测试将向我们展示视觉测试的重要性，以及我们如何利用这两种测试方法来编写更好的测试。

### 手动视觉测试

手动视觉测试涉及使用肉眼验证开发团队所做的更改是否破坏了任何可见的用户界面功能。手动视觉测试要么由测试人员，要么由开发团队进行，他们会对开发的用户界面进行视觉测试，并将其与最初创建的设计进行比较。通过视觉测试应用程序的过程确认了行为、外观和用户界面的变化是否符合预期。手动视觉测试适用于用户界面的小改变，但这可能不是一种非常准确的验证应用程序的方式，特别是对于具有许多页面和视觉元素或不同视口的应用程序。为了识别手动视觉测试的局限性，以下图片由*Atlantide Phototravel*显示了埃菲尔铁塔的并排比较。它们非常相似，但第二帧中省略了微小的细节。花几秒钟比较这些图像，试图找出视觉上的差异，而不看第二张图像中的圆形区域：

![图 12.1 - 发现埃菲尔铁塔图像中的差异](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_12.1_B15616.jpg)

图 12.1 - 发现埃菲尔铁塔图像中的差异

即使对于训练有素的眼睛来说，也有一些细节，比如鸟的图案、缺少的人和甚至缺少的云，这几乎让人无法通过视觉来判断两张照片之间是否真的有差异。通过应用手动视觉测试的相同想法，很可能会忽略细节，无法找到它们之间的任何差异，即使一些元素在测试应用程序中丢失或添加了。

### 自动化视觉测试

自动化视觉测试涉及测试页面的视觉元素。与手动方法不同，使用自动化流程来检查应用程序页面的一致性。要正确运行自动化视觉测试，我们必须将所需的用户界面保存和定义为基线。然后我们可以在测试中使用这个基线来检查是否需要更新基线或修改应用程序所做的更改。

自动化视觉测试源于功能测试。自动化视觉测试采用了检查整个页面的方法，而不是断言页面中的每个元素并检查元素的属性。

自动化视觉测试有两种类型：

+   快照测试

+   视觉 AI 测试

让我们详细看看每一种。

#### 快照测试

快照测试是一种自动化视觉测试，当测试运行时，记录特定屏幕的光栅图形或位图。然后检查记录的位图与先前记录的基线位图（基线）是否一致。快照测试工具中的算法仅通过比较十六进制颜色代码来检查位图中是否存在像素差异。如果识别出任何颜色代码差异，则报告快照错误或生成显示视觉差异的图像。

与手动测试相比，快照测试是识别用户界面中的错误的一种更快的方法。如果应用程序在某种程度上是静态的，并且用户界面中没有太多的动态内容更改，那么快照测试是测试 Web 应用程序的首选方式。快照测试无法正确处理动态内容，因为算法将内容中的任何更改都视为视觉差异，由于像素更改。由于所有视觉变化都被识别为视觉差异或潜在的错误，因此在包含动态数据的页面上拥有一致的快照图像将是不可能的。

#### 视觉 AI 测试

视觉 AI 测试是自动化视觉测试的新一代，利用了人工智能（AI）。视觉 AI 测试的主要目标是改进快照测试的缺点，例如在测试应用程序时处理动态内容。通过使用计算机视觉，视觉 AI 算法可以识别图像和测试可以运行的区域，甚至在动态内容的情况下，它们可以识别内容允许动态的区域和应保持不变的区域。

视觉 AI 测试还使开发人员和测试人员更容易进行跨浏览器测试。对于跨浏览器应用程序，用户可以编写单个测试，然后在应用程序支持的不同视口中运行该测试。视口测试是一个方便的工具，因为它消除了开发人员或测试人员为每个设备编写快照测试的负担，以验证是否存在视觉变化。

## 回顾-视觉测试

在本节中，我们了解了什么是视觉测试，不同类型的视觉测试以及何时使用每种类型的视觉测试。我们了解了自动化视觉测试和手动视觉测试之间的区别，还了解了不同类型的自动化视觉测试。然后我们了解了为什么视觉测试是手动测试的首选方法，以及为什么有一种新一代的视觉测试工具改进了第一代视觉测试工具存在的缺点。现在我们已经了解了关于视觉测试的一切，在下一节中，我们将通过了解视口是什么以及如何测试它们来探索更多需要视觉测试的领域。

# 理解视口

视口是用户网页的可见区域。因此，视口这个术语用于测量用户设备上的矩形查看区域。当计算机首次发明时，只有少数可用的视口，但由于创建了更多的设备，这种情况已经显著增加。在撰写本文时，由折叠手机或翻转屏幕以及具有不同尺寸的智能电视等设备创建了新的视口，因此开发人员需要确保他们的应用与用户的设备兼容。使用不同的视口，会出现新的挑战，使应用与这些视口兼容，这对测试人员来说是一个更大的噩梦，因为几乎不可能通过每个可用的视口测试应用。

在这一部分，我们将探讨视口的重要性，如何在不同的视口中进行测试以及视口在视觉测试中的作用。

## 视口和测试

视口在测试网页应用程序时起着重要作用，因为它们显示了实际用户将如何查看正在测试的网页应用程序。在撰写本文时，移动视口是最常用的视口。这是因为手机已经发展成为最强大的便携式技术设备。为了为用户提供良好的体验，视口测试应该是首要任务。通过视口测试，我们可以检查网页应用对不同屏幕尺寸的响应性等特性。

开发响应式网页应用程序比非响应式网页应用程序具有优势，因为与独立的 iOS 或 Android 移动应用程序相比，它们需要更少的时间和资源来开发，并且执行相同的功能。

所有现代浏览器都允许我们在构建应用时检查和测试响应性。下面的截图显示了在 Chrome 浏览器上呈现的 iPhone 6 视口，显示了 Cypress 文档页面在手机上的呈现方式：

![图 12.2- iPhone 6 移动视口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_12.2_B15616.jpg)

图 12.2- iPhone 6 移动视口

我们可以在浏览器上使用**切换设备工具栏**在正常网页视图和移动设备视图之间切换。这使我们能够看到不同的网页应用在不同视口上的呈现方式。在网页应用响应的情况下，测试不同视口不会有问题，因为应用会自动适应不同的视口。然而，对于不响应的网页应用来说情况就不同了。在下面的截图中，您可以看到当前视口的选项，以及添加浏览器未定义的自定义视口的能力：

![图 12.3-浏览器视口选择](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_12.3_B15616.jpg)

图 12.3-浏览器视口选择

如前面的截图所示，可以添加 Chrome 浏览器设备列表中不存在的新测试视口。

在选择视口时，Chrome 网页区域会自动调整浏览器上可见的内容。作为开发人员或测试人员，很容易找出应用是否需要进行更改。

## 视口和自动化视觉测试

考虑到前面截图中显示的视口数量，手动测试每个单独的视口并验证是否有破坏应用用户界面或引入不必要的未预期变化的变化是很繁琐的。为了确保视口被测试，我们可以使用自动化视觉测试来检查应用在不同视口下的一致性。通过视觉测试，我们可以验证我们的应用在测试中配置的不同视口中是否发生了意外变化。

## 回顾-视口

视口是视觉测试的关键方面，特别是因为大多数关于 Web 应用响应性的主要问题都是由于视口错误造成的。在本节中，我们了解了不同类型的视口以及如何使用浏览器的切换选项来检查我们的 Web 应用的响应性，该选项可以在不同设备视口和正常计算机视口之间切换。我们还了解到，通过使用自动化视觉测试，我们可以为不同的视口自动化不同的测试用例，并自动知道应用程序是否发生了意外更改。在下一节中，我们将探讨如何使用 Cypress 编写自动化视觉测试，使用自动化视觉 AI 工具和 Percy，后者利用快照记录视觉测试。

# 自动化视觉测试工具

视觉测试是 Cypress 的重要组成部分，因为它是从我们熟悉的功能测试转变而来的。通过视觉测试，Cypress 为我们提供了一个新的机会，可以在不必为了断言页面上的单个元素而编写数百行功能代码的情况下测试用户界面。

在本节中，我们将深入研究如何通过将它们与 Cypress 集成来使用两个自动化视觉测试工具，然后学习如何使用它们来实现我们的视觉测试应用程序的目标。其中一个工具使用快照记录一个**基线位图**，并逐个比较位图图像像素，检查十六进制颜色是否存在任何差异。另一个工具使用 AI 算法来比较来自我们 Web 应用程序的快照。

到本节结束时，我们将了解使用什么工具，在什么时候以及 Cypress 如何在创建测试工具和测试本身的简单集成中发挥作用。我们将研究的两个工具是 Applitools Eyes SDK 和 Percy。

## Percy

Percy 是一个与测试工具集成的视觉测试和审查平台。这使开发人员和质量保证工程师能够识别视觉错误，否则这些错误将很难识别和报告。Percy 使视觉测试变得轻而易举 - 您只需要下载 Percy npm 模块，配置**BrowserStack**，并将 Percy 添加到您的测试中。完成所有必要的配置后，您可以复制 Percy 提供的**TOKEN**，该 TOKEN 将作为环境变量在您的机器上使用，如果您希望上传您的测试快照到 Browserstack 云以审查和识别可能存在的视觉差异。

重要提示

Browserstack 是一个视觉测试和审查工具，拥有**Percy**工具。要配置 Percy，您需要配置 Browserstack；所有配置将在两个平台之间同步。

Percy 主要依赖于 Firefox 和 Chrome 浏览器。为了测试应用程序，Percy 会在各种视口中运行一组浏览器，并记录各种视口的任何更改。当第一张图像被记录并保存时，Percy 会将图像作为您的测试**基线**，并在后续测试运行中使用该图像来检查类似图像的任何更改，然后突出显示可能发生的任何视觉差异。

### 设置 Percy

设置 Percy 并不复杂，涉及以下步骤：

1.  使用 BrowserStack 创建一个帐户（[`www.browserstack.com/`](https://www.browserstack.com/)）。

1.  验证您的 BrowserStack 电子邮件地址。

1.  在 Browserstack 仪表板中创建一个组织。

1.  使用您的 BrowserStack 帐户登录 Percy 仪表板。

1.  在 Percy 仪表板上创建一个项目。

1.  使用 Percy 网站上的说明在本地项目上配置 Percy（[`docs.percy.io/docs/cypress`](https://docs.percy.io/docs/cypress)）。

1.  将 Percy TOKEN 添加到您的本地机器作为环境变量。

1.  哇！您现在已经准备好编写您的测试了！

完成*步骤 1-4*后，Percy 会提供一个令牌，您必须在执行测试之前将其添加到机器环境变量中。您可以访问 Percy 文档（[`docs.percy.io/docs/cypress`](https://docs.percy.io/docs/cypress)）了解如何使用 Cypress 设置 Percy 的更多信息。

一切都设置好后，我们可以运行第一个测试，这将涉及检查当内容更改时我们的登录页面是否有视觉差异。如下截图所示，我们在登录页面上输入用户名和密码运行了我们的测试：

![图 12.4 – Percy – 新快照](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_12.4_B15616.jpg)

图 12.4 – Percy – 新快照

在这里，我们可以看到上传到 Percy 仪表板的快照图像。上传的快照是我们的登录页面。在上传快照后，Percy 让我们可以切换 Chrome 和 Firebox 浏览器，以便我们可以检查快照的一致性。在主 Percy 仪表板上，我们可以批准所有快照，拒绝和接受单个快照，甚至在桌面视口和移动视口之间切换。

重要提示

只有当测试执行结束并关闭运行测试的终端时，Percy 才会将快照上传到仪表板。这与 Applitools 工具不同，后者在测试执行结束后立即连续上传测试快照。

正如我们之前提到的，我们可以使用 Percy 来比较我们记录的基准图像和新生成的位图图像。然后涉及的算法逐像素检查差异，当基准图像与在测试应用程序的第二次运行中生成的新图像不相似时，这些差异被记录为视觉差异。以下截图显示了我们在 Percy 仪表板上测试的第二次构建。在这里，我们省略了用户名和密码字段中的一些字符，并且我们想检查 Percy 是否识别出这些差异：

![图 12.5 – Percy 像素差异](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_12.5_B15616.jpg)

图 12.5 – Percy 像素差异

如前面的截图所示，当我们运行第二个构建时，我们省略了用户名和密码字段中的一些字符。当快照上传到 Percy 时，程序通过检查不同图像的像素来识别视觉差异，并为我们提供识别出像素差异的区域。在我们的第二次运行中，当我们*批准*这些更改时，Percy 采用我们的第二个图像作为**基准**。如果我们在图像上*请求更改*，Percy 将保留我们的第一个图像作为此特定快照的基准。

仔细检查后，我们发现第一个快照的登录用户名是*Kathe*，而在第二个快照中，登录用户名是*Kat*。密码中的一些字符和用户名中的一些字符的省略是触发 Percy 显示这些视觉差异的原因。这使我们可以选择接受更改并更改我们的基准，或者如果更改与我们的期望不一致，则向开发人员请求更改。

提醒

要成功运行测试并将快照上传到 Percy 仪表板，您需要在 BrowserStack 上创建一个帐户，在 BrowserStack 中创建一个组织，在 Percy 仪表板上使用 Browserstack 登录，创建一个 Percy 项目，并将 Percy 项目仪表板上提供的令牌添加到机器的环境变量中。

Percy 在本地机器上和测试中都很容易设置。要调用 Percy，只需要在测试中添加一行代码。以下代码块显示了生成第一和第二快照，以及传递给`cy.percySnapshot()`命令的参数来命名快照：

```js
describe('Percy Login Snapshots', () => {
    it('percy: signin page snapshot - first build ', () => 
      {
        cy.visit('signin'); 
        cy.get('#username').type('Kathe');
        cy.get('#password').type('passwor');
        cy.percySnapshot('first');
    });
    it('percy: signin page snapshot - second build, () => {
        cy.visit('signin'); 
        cy.get('#username').type('Kat');
        cy.get('#password').type('passd');
        cy.percySnapshot('second');
    });  
});
```

在第一个构建中运行了前面代码块中的第一个测试，而第二个测试是在第二个构建中运行的，同时修改了用户名和密码详细信息，以提供我们登录页面中的像素差异。要自行运行这些测试，您只需要按照之前提到的 Percy 设置过程获取 Percy 令牌，并将您的 Percy 项目令牌添加为计算机的环境变量。这些测试的完整源代码可以从本书的 GitHub 存储库中的`chapter-12`目录中获取。

### 练习 1

在这个练习中，我们将练习之前学到的知识：学习如何使用 Percy 进行视觉测试，然后与 Percy 配置和仪表板进行交互。按照以下步骤：

1.  使用 Percy 和 Cypress，登录到我们的测试应用程序并导航到仪表板。然后，使用`Percy`命令，对公共交易页面进行快照。

1.  通过单击应用程序上的**新交易**按钮并添加交易详细信息来添加新交易。

1.  拍摄另一个快照，并使用 Percy 比较添加另一个交易时的交易页面差异。

重要提示

在运行测试之前，记得将您的 Percy **TOKEN**变量添加到本地计算机，以便 Percy 拍摄的快照可以成功上传到 Percy 仪表板。

此练习的解决方案可以在`chapter-12/cypress/integration/percy/percy-excercise.spec.js`目录中找到。

通过完成这个练习并能够在 Cypress 中正确设置 Percy，我相信你现在了解了如何使用 Percy 来识别测试中的视觉差异，以及在应用程序用户界面发生变化时快速识别差异。你可以通过对我们应用程序的位图图像进行逐像素比较来实现这一点。

## Applitools

Applitools 是一种利用人工智能来进行视觉测试和监控应用程序的工具。就像 Percy 一样，使用 Cypress 设置 Applitools 很容易，并专注于改进 Percy 等工具的不足之处。Percy 通过比较单个像素来识别视觉差异，而 Applitools 通过使用其 AI 算法来检查变化是否是预期的变化或错误来识别视觉差异。使用 Applitools，更容易测试动态变化，因为我们可以省略我们不希望 Applitools 检查视觉差异的区域。

通过指定应该检查的区域和应该忽略的区域来识别错误的能力，使 Applitools 成为测试涉及动态内容的应用程序时更好的工具。

### 设置 Applitools

就像 Percy 一样，使用 Cypress 设置 Applitools Eyes SDK 相对容易。可以通过以下步骤实现：

1.  使用 Applitools 创建一个帐户（[`auth.applitools.com/users/register`](https://auth.applitools.com/users/register)）。

1.  验证您的 Applitools 电子邮件地址。

1.  导航到 Applitools 仪表板以获取 API 密钥。

1.  在本地项目上配置 Applitools。

1.  将 Applitools 的**APPLITOOLS_API_KEY**添加到您的本地计算机作为环境变量。

1.  派对！

一旦*步骤 1*和*步骤 2*完成，Applitools 会为您提供一个**APPLITOOLS_API_KEY**，类似于 Percy 的**TOKEN**，您必须在执行测试之前将其添加为计算机的环境变量。您可以访问 Applitools 和 Cypress 文档（[`applitools.com/tutorials/cypress.html`](https://applitools.com/tutorials/cypress.html)）了解有关如何使用 Cypress 设置 Applitools Eyes SDK 的更多信息。

一切都设置好后，我们现在可以使用 Cypress 和 Applitools Eyes SDK 运行我们的第一个测试。Applitools 是一个非常丰富的工具，所以我们无法涵盖它捆绑的所有功能。相反，我们将专注于 Applitools 作为视觉测试工具的优势。在下面的屏幕截图中，我们有相同的登录测试，我们在 Percy 示例中运行了该测试，但修改为 Applitools Eyes 测试：

![图 12.6 – Applitools 登录页面快照](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_12.6_B15616.jpg)

图 12.6 – Applitools 登录页面快照

在这里，我们可以看到代表 Applitools Eyes SDK 拍摄并上传到 Applitools 仪表板的第一个登录页面快照的快照。Applitools 使用三个命令来控制 Cypress 测试。第一个命令`cy.eyesOpen()`用于初始化和启动测试，第二个命令`cy.eyesCheckWindow()`负责拍摄屏幕截图，就像前面的情况一样，第三个命令`eyesClose()`完成 Applitools Eyes 会话并将屏幕截图上传到仪表板。

我们的登录测试可以以以下格式编写。这会打开 Applitools Eyes SDK，拍摄屏幕截图，并在上传屏幕截图到 Applitools 仪表板之前关闭 SDK，以便 Applitools AI 算法可以通过视觉比较进行比较。以下代码块显示了前面屏幕截图中提供的第二个构建：

```js
it('applitools: can signin on login page - second build snapshot', () => {
    cy.eyesOpen({
      appName: 'SignIn Page',
      browser: { width: 1200, height: 720 },
    });
    cy.get('#username').type('Kat');
    cy.get('#password').type('passd');
    cy.eyesCheckWindow('loginPage');

    cy.eyesClose();
  });
```

在这里，我们可以观察到，为了运行测试，我们需要初始化 Applitools Eyes SDK，然后在关闭测试之前拍摄屏幕截图。Eyes SDK 使用的所有三种方法都可以具有配置参数，这些参数可以根据您的需求进行更改。例如，在我们的代码块中，我们已配置`cy.eyesOpen()`命令，以便我们有测试批次名称和浏览器窗口可见的配置。

在报告错误方面，Applitools 更进一步。在 Percy 中，我们发现由于其逐像素比较，用户界面的任何更改都被检测为视觉差异，可能是用户界面错误。在下面的屏幕截图中，我们可以看到，在使用不同用户界面渲染运行类似测试后，我们可以告诉 Applitools 忽略屏幕中的某些区域，并将我们的测试标记为通过：

![图 12.7 – Applitools 忽略区域选项](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_12.7_B15616.jpg)

图 12.7 – Applitools 忽略区域选项

在这里，我们可以看到 Applitools 提供的不同选项。即使不同区域有不同的视觉元素，如果它们不是视觉错误，或者它们是从动态内容生成的，也可以忽略这些区域。在忽略具有视觉差异的区域后，我们继续将屏幕截图标记为已接受。

重要提示

请记住在运行测试之前将**APPLITOOLS_API_KEY**变量添加到本地机器作为环境变量，该变量是从 Applitools 仪表板获取的。此令牌确保 Applitools Eyes SDK 拍摄的快照成功上传到 Applitools 仪表板。

下面的屏幕截图显示了 Cypress 重新运行测试并在本地通过测试。这是因为我们已指示 Applitools Eyes SDK 接受与我们基准快照相比存在的视觉变化：

![图 12.8 – 在 Applitools 仪表板中忽略测试区域后通过测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/e2e-web-test-cprs/img/Figure_12.8_B15616.jpg)

图 12.8 – 在 Applitools 仪表板中忽略测试区域后通过测试

哇，我们的测试通过了！对 Applitools 测试仪表板所做的任何更改都会反映在本地测试运行中。这是通过在运行 Applitools 视觉测试之前必须添加到环境变量中的 API 密钥实现的。您可以阅读更多关于 Applitools Eyes 的信息（[`applitools.com/tutorials/cypress.html`](https://applitools.com/tutorials/cypress.html)）以了解如何使用 Applitools 在动态现代网页上测试用户界面。

### 练习 2

在这个练习中，我们将测试我们对 Applitools Eyes SDK 工具的了解以及如何使用它进行视觉测试。这个练习将帮助我们实际实施本章的理论部分，并找出如何使用 Cypress 和 Applitools 编写视觉测试。执行以下步骤：

1.  使用 Applitools 和 Cypress，登录到我们的测试应用程序并导航到仪表板。然后，使用`Applitools Eyes SDK`的快照命令，对公共交易页面进行快照。

1.  通过单击应用程序上的新交易按钮并添加交易详细信息来添加另一个新交易。

1.  再次拍摄快照，并使用 Applitools 比较交易页面的差异，从新交易创建时起。

1.  忽略 Applitools 仪表板中新交易创建的区域，并使用忽略区域重新运行测试。

前面练习的解决方案可以在`chapter-12/cypress/integration/applitools/applitools-excercise.spec.js`目录中找到。

通过这样，我相信您已经学会了如何使用 Applitools 的自动化视觉测试，并且这个练习已经帮助您掌握了使用 Cypress 进行自动化视觉测试的技能和知识。通过这样，我们已经到达了本书的结尾，我宣布您是一名合格的“bug 猎手”！

## 总结-自动化视觉测试工具

在本节中，我们了解了两种自动化视觉测试工具，Percy 和 Applitools，以及它们如何与 Cypress 测试集成。然后，我们了解了 Percy 和 Applitools 之间的区别，以及 Percy 使用快照测试方式与 Applitools 使用 AI 分析测试中的视觉差异的不同之处。最后，我们了解了我们可以如何利用诸如 Applitools 之类的工具进行测试。我们通过了解浏览器上的内容随时间变化以及更多动态网站需要能够“适应”现代网页上动态内容的工具来实现这一点。

# 总结

在本章中，我们着手了解如何进行视觉测试及其重要性，以及我们可以使用的视口和工具来进行自动化视觉测试。在本章中，我们学习了如何正确进行视觉测试。这涉及理解如何创建视口，如何在不同的视口上进行测试，以及为什么我们需要在多个视口上运行自动化视觉测试。然后，我们探讨了两种测试工具，Percy 和 Applitools Eyes SDK，并广泛涵盖了它们的用例、设置过程以及如何使用它们编写 Cypress 测试。最后，我们进行了一些练习，以提高我们对这些工具的熟悉度和互动性。

通过这样，我们已经到达了本书的结尾。如果您一直在阅读本书的所有章节，我相信您现在对 Cypress 的了解比起开始时更加深入。我希望这本书挑战了您的思维方式，让您对 Cypress 作为测试工具产生了热爱，并且在成为更好的测试人员或开发人员方面也有所改变。
