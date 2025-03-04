# Contributing to Kubernetes-Based Router/Firewall

Thank you for your interest in contributing to this project! We welcome contributions from everyone, whether it's in the form of bug reports, feature requests, documentation improvements, or code changes.

## Getting Started

Before you begin:

1. Make sure you have a [GitHub account](https://github.com/signup/free)
2. Check if your issue already exists in our [issue tracker](https://github.com/varuntirumala1/fos1/issues)
3. Fork the repository on GitHub

## Development Environment Setup

Please refer to [DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed instructions on setting up your development environment.

## Making Changes

1. Create a branch from where you want to base your work
   * This is usually the `main` branch
   * Name your branch according to the format: `feature/description` or `fix/description`
2. Make your changes in your branch
3. Add or update tests as appropriate
4. Update documentation as needed
5. Ensure the test suite passes
6. Commit your changes using a descriptive commit message
   * Start with a brief summary line (50 characters or less)
   * Followed by a blank line
   * Detailed explanatory text as needed
   * Use the present tense ("Add feature" not "Added feature")
   * Use the imperative mood ("Move cursor to..." not "Moves cursor to...")

## Submitting Changes

1. Push your changes to your fork
2. Submit a pull request to the main repository
3. The core team will review your pull request
4. Address any feedback and update your pull request as needed
5. Once approved, your changes will be merged

## Coding Conventions

* Follow standard Go coding conventions and [effective Go guidelines](https://golang.org/doc/effective_go.html)
* Use `gofmt` to format your code
* Include comments for exported functions, types, and constants
* Write tests for new functionality
* Use meaningful variable/function names
* Keep functions focused and reasonably small

## YAML Conventions

* Use 2-space indentation for all YAML files
* Follow Kubernetes best practices for manifest structure
* Group related resources in the same file when appropriate
* Use kebab-case for resource names

## Git Conventions

* Keep commits focused on a single change
* Squash multiple commits if they represent a single change
* Write clear commit messages
* Reference issues in commit messages and pull requests

## License

By contributing to this project, you agree that your contributions will be licensed under the project's [MIT License](LICENSE).

Thank you for your contributions!