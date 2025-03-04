# Command Applications

This directory contains the entry points for various command-line applications in the project:

## Directory Structure

- `talosctl/` - Custom talosctl commands and extensions
- `kubectl/` - Custom kubectl plugins for managing network resources

## Developing Command Applications

Each command application should follow a similar structure:

```
cmd/
└── command-name/
    ├── main.go       # Main entry point
    ├── app/          # Application logic
    └── cmd/          # Command line handling
```

Use [cobra](https://github.com/spf13/cobra) for command-line interfaces to maintain consistency across tools.