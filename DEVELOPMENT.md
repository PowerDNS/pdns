PowerDNS Development Environment
--------------------------------

Thank you for you interest to contribute to the PowerDNS project.
This document will explain one way to set up a development environment based on the language server protocol (LSP) when working on PowerDNS.

# Introduction

The environment will consist of setting up the [`clangd`](https://clangd.llvm.org/) C/C++ language server to enable fancy IDE features for development.
[`ccls`](https://github.com/MaskRay/ccls) can also be used in place of `clangd`.

Furthermore, additional [on-the-fly checks using `clang-tidy`](#on-the-fly-clang-tidy) can be easily enabled.

On some systems, `clangd` and `clang-tidy` are available as packages separate from the `clang` package.
Ensure that you have all three binaries available and running on your system.

# Compilation Database

For projects with non-trivial build systems, like PowerDNS, `clangd` requires a [compilation database](https://clang.llvm.org/docs/JSONCompilationDatabase.html).

Since PowerDNS' autotools-based build system does not have native support for generating such a database, an external tool like [Bear (the Build EAR)](https://github.com/rizsotto/Bear) or [compiledb](https://pypi.org/project/compiledb) can be used.

## Using Bear
Once you have `bear` installed, configure a build of your choice (either the PowerDNS `auth`, `recursor` or `dnsdist`) using `clang` and `clang++`:

```sh
make distclean    # Ensure we rebuild all files so that bear can pick them up.
CC=clang CXX=clang++ ./configure --with-modules=gsqlite3 --disable-lua-records
```

We can now build PowerDNS using `bear` and `make` which produces a compilation database file named `compile_commands.json`:

```sh
bear --append -- make -j 8
```

## Using compiledb
Once you have `compiledb` installed, configure the build and run compiledb:

```sh
make distclean    # Ensure we rebuild all files so that bear can pick them up.
CC=clang CXX=clang++ ./configure ...
make -nwk  | /path/to/compiledb -o- > compile_commands.json
```

to generate the compilation database.
For the authoritative server, the configure command is run in the top level directory, while the compiledb command should be run in the `pdns` subdirectory.

# Setting up the LSP client

Once the compilation database is generated, you can now move onto setting up an LSP client in your editor or IDE.

Note that the process of generating the compilation database file only needs to be run when a file is added to the project or when build flags change (e.g. dependencies are added).

# Editors

## Emacs

This section explains how to set up [Emacs](https://www.gnu.org/software/emacs/) with [LSP Mode](https://emacs-lsp.github.io/) for C/C++ development using `clangd` which supports [on-the-fly checking](https://www.flycheck.org/en/latest/) and [auto-completion](https://company-mode.github.io/), among many other features.

Instructions for an alternative, more minimal, setup using [Eglot](https://github.com/joaotavora/eglot) [are also available](#minimal-emacs).

Code snippets below should be added to your Emacs init file (e.g. `~/.config/emacs/init`).

We'll start by enabling Emacs package repositories and declaring which packages we would like to have installed:

```elisp
(with-eval-after-load 'package
 (setq package-archives
  '(("gnu"   . "https://elpa.gnu.org/packages/")
    ("melpa" . "https://melpa.org/packages/")))
 (push 'company      package-selected-packages)
 (push 'flycheck     package-selected-packages)
 (push 'lsp-mode     package-selected-packages)
 (push 'lsp-ui       package-selected-packages)
 (push 'lsp-treemacs package-selected-packages))
```

To avoid restarting Emacs, you can evaluate that previous s-expression by pointing at the last parenthesis and using `C-x C-e` or selecting the block and using `M-x eval-region`.

Once done, run `M-x package-refresh-contents`, then `M-x package-install-selected-packages`.
This should install some packages for you.

Now let's set up our common programming mode, this enables the following features:

* Highlighting the current line.
* Displaying line numbers.
* Auto-inserting indentation.
* Auto-inserting closing parenthesis, bracket, etc...
* Auto-completion.
* On-the-fly code checking.
* On-the-fly spell checking.
* Highlighting matching parentheses, brackets, etc...
* Auto-displaying documentation briefs in the echo area.

```elisp
(with-eval-after-load 'prog-mode
 (add-hook 'prog-mode-hook #'hl-line-mode)
 (add-hook 'prog-mode-hook #'display-line-numbers-mode)
 (add-hook 'prog-mode-hook #'electric-layout-mode)
 (add-hook 'prog-mode-hook #'electric-pair-mode)
 (add-hook 'prog-mode-hook #'company-mode)
 (add-hook 'prog-mode-hook #'flycheck-mode)
 (add-hook 'prog-mode-hook #'flyspell-prog-mode)
 (add-hook 'prog-mode-hook #'show-paren-mode)
 (add-hook 'prog-mode-hook #'eldoc-mode))
```

Now let's set up `flycheck` for on-the-fly code checking, this adds the following key bindings:

* `M-n` to jump to the next error.
* `M-p` to jump to the previous error.

```elisp
(with-eval-after-load 'flycheck
 (define-key flycheck-mode-map (kbd "M-n") #'flycheck-next-error)
 (define-key flycheck-mode-map (kbd "M-p") #'flycheck-previous-error)
 (setq flycheck-checker-error-threshold nil)
 (setq flycheck-check-syntax-automatically
  '(idle-change new-line mode-enabled idle-buffer-switch))
 (setq flycheck-idle-change-delay 0.25)
 (setq flycheck-idle-buffer-switch-delay 0.25))
```

And set up `company-mode` for auto-completion:

```elisp
(with-eval-after-load 'company
 (setq company-backends '((company-capf company-files company-keywords)))
 (setq completion-ignore-case t)
 (setq company-minimum-prefix-length 1)
 (setq company-selection-wrap-around t)
 (define-key company-mode-map (kbd "<tab>") #'company-indent-or-complete-common))
```

Then set up `lsp-mode` to integrate everything together, which enables the following additional features:

* Header breadcrumbs showing the path to the current item under point.
* Semantic syntax highlighting as opposed to regex-based ones.

And adds the following key bindings:

* `F2` to switch between implementation and header file.
* `C-c f` to format the current file according to `clang-format`.
* `C-c g` to format the selected region according to `clang-format`.
* `C-c r` to reliably rename the item under point based on `clangd`.
* `C-c h` to show code documentation about the item under point.
* `C-c =` to expand selection outwards from the item under point.
* `M-RET` to list and run available language server code actions.
* `C-c x` to navigate to any symbol in the project.
* `C-c e` to show a navigation list of errors/warnings in the project.
* `C-c s` to show a navigation list of symbols in the project.
* `C-c c` to show the call hierarchy of a method or function.
* `C-c t` to show the type/inheritance hierarchy of a type.

```elisp
(with-eval-after-load 'lsp-mode
 (define-key lsp-mode-map (kbd "C-c f") #'lsp-format-buffer)
 (define-key lsp-mode-map (kbd "C-c g") #'lsp-format-region)
 (define-key lsp-mode-map (kbd "C-c r") #'lsp-rename)
 (define-key lsp-mode-map (kbd "C-c h") #'lsp-describe-thing-at-point)
 (define-key lsp-mode-map (kbd "C-="  ) #'lsp-extend-selection)
 (define-key lsp-mode-map (kbd "M-RET") #'lsp-execute-code-action)
 (define-key lsp-mode-map (kbd "C-c e") #'lsp-treemacs-errors-list)
 (define-key lsp-mode-map (kbd "C-c s") #'lsp-treemacs-symbols)
 (define-key lsp-mode-map (kbd "C-c c") #'lsp-treemacs-call-hierarchy)
 (define-key lsp-mode-map (kbd "C-c t") #'lsp-treemacs-type-hierarchy)
 (add-hook 'lsp-mode-hook #'lsp-treemacs-sync-mode)
 (setq lsp-progress-prefix "  Progress: ")
 (setq lsp-completion-provider :none) ; Company-capf is already set
 (setq lsp-headerline-breadcrumb-enable t)
 (setq lsp-restart 'auto-restart)
 (setq lsp-enable-snippet nil)
 (setq lsp-keymap-prefix "C-c")
 (setq lsp-idle-delay 0.1)
 (setq lsp-file-watch-threshold nil)
 (setq lsp-enable-semantic-highlighting t)
 (setq lsp-enable-indentation t)
 (setq lsp-enable-on-type-formatting t)
 (setq lsp-before-save-edits nil)
 (setq lsp-auto-configure t)
 (setq lsp-signature-render-documentation t)
 (setq lsp-modeline-code-actions-enable nil)
 (setq lsp-log-io nil)
 (setq lsp-enable-imenu nil))

(with-eval-after-load 'lsp-headerline
 (setq lsp-headerline-breadcrumb-icons-enable nil))

(with-eval-after-load 'lsp-semantic-tokens
 (setq lsp-semantic-tokens-apply-modifiers t))

(with-eval-after-load 'lsp-clangd
 (setq lsp-clients-clangd-args
  '("--header-insertion-decorators"
    "--all-scopes-completion"
    "--clang-tidy"
    "--completion-style=detailed"
    "--header-insertion=never"
    "--inlay-hints"
    "--limit-results=1000"
    "-j=4"
    "--malloc-trim"
    "--pch-storage=memory"))
 (with-eval-after-load 'cc-mode
  (define-key c-mode-base-map (kbd "<f2>") #'lsp-clangd-find-other-file)))

(with-eval-after-load 'treemacs-interface
 (global-set-key (kbd "<f12>") #'treemacs-delete-other-windows))

(with-eval-after-load 'treemacs-customization
 (setq treemacs-width 70))

(with-eval-after-load 'treemacs-mode
 (add-hook 'treemacs-mode-hook #'toggle-truncate-lines))
```

And now we set up `lsp-ui-mode` to provide a few more features and key bindings:

* `C-c d` to show rendered documentation.
* `M-.` to peek at the definition of the item under point.
* `M-?` to peek at references to the item under point.
* `M-I` to peek at implementations of virtual methods.
* `M-,` to jump back.

```elisp
(with-eval-after-load 'lsp-ui-flycheck
 (setq lsp-ui-flycheck-enable t))

(with-eval-after-load 'lsp-ui-doc
 ; Disable on-the-fly showing of rendered documentation.
 (setq lsp-ui-doc-enable nil)
 (setq lsp-ui-doc-alignment 'frame)
 (setq lsp-ui-doc-header t)
 (setq lsp-ui-doc-include-signature t)
 (setq lsp-ui-doc-max-height 30)
 (setq lsp-ui-doc-use-webkit t))

(with-eval-after-load 'lsp-ui-peek
 (setq lsp-ui-peek-list-width 30)
 (setq lsp-ui-peek-always-show t))

(with-eval-after-load 'lsp-ui-sideline
 (setq lsp-ui-sideline-enable nil))

(with-eval-after-load 'lsp-ui
 (define-key lsp-ui-mode-map (kbd "M-."    ) #'lsp-ui-peek-find-definitions)
 (define-key lsp-ui-mode-map (kbd "M-?"    ) #'lsp-ui-peek-find-references)
 (define-key lsp-ui-mode-map (kbd "M-I"    ) #'lsp-ui-peek-find-implementation)
 (define-key lsp-ui-mode-map (kbd "C-c d"  ) #'lsp-ui-doc-show)
 (define-key lsp-ui-mode-map (kbd "C-c ! l") #'lsp-ui-flycheck-list))
```

And finally, set up the C/C++ programming mode with a few settings:

* Indentation of 2 spaces.
* Simple auto-detection of coding style.
* Marking of badly-styled comments.
* Running the LSP client.

```elisp
(defmacro set-up-c-style-comments ()
 "Set up C-style /* ... */ comments."
 `(with-eval-after-load 'newcomment
   (setq-local comment-style 'extra-line)))

(with-eval-after-load 'cc-mode
 (add-hook 'c-mode-common-hook #'lsp))

(with-eval-after-load 'cc-vars
 (setq c-mark-wrong-style-of-comment t)
 (setq c-default-style '((other . "user")))
 (setq c-basic-offset 2)
 (add-hook 'c-mode-common-hook (lambda nil (progn (set-up-c-style-comments)))))
```

### TODO Items

* Whitespace cleanup on save.
* Snippet support with `yasnippet`.
* Add `which-key` support.
* Add `ivy` support.
* Add `company-prescient` for auto-completion ranking.

## Minimal Emacs

Code snippets below should be added to your Emacs init file (e.g. `~/.config/emacs/init`).

We'll start by enabling Emacs package repositories and declaring which packages we would like to have installed:

```elisp
(with-eval-after-load 'package
 (setq package-archives
  '(("gnu"   . "https://elpa.gnu.org/packages/")
    ("melpa" . "https://melpa.org/packages/")))
 (push 'company package-selected-packages)
 (push 'eglot   package-selected-packages))
```

To avoid restarting Emacs, you can evaluate that previous s-expression by pointing at the last parenthesis and using `C-x C-e` or selecting the block and using `M-x eval-region`.

Once done, run `M-x package-refresh-contents`, then `M-x package-install-selected-packages`.
This should install some packages for you.

Now, let's set up Eglot and Company:

```elisp
(require 'eglot)
(add-to-list 'eglot-server-programs '((c++-mode c-mode) "clangd"))
(add-hook 'c-mode-hook 'eglot-ensure)
(add-hook 'c++-mode-hook 'eglot-ensure)

(with-eval-after-load 'prog-mode
  (add-hook 'prog-mode-hook #'company-mode))
```

That's it.

# Code Checkers

## On-the-fly `clang-tidy`

`clangd` automatically integrates with `clang-tidy` if a `.clang-tidy` configuration file is available.
See [the "`clang-tidy`" section of the CONTRIBUTING document](CONTRIBUTING.md#clang-tidy) on how to set up `clang-tidy`.
