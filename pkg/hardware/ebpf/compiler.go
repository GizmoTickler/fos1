package ebpf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"k8s.io/klog/v2"
)

// CompileOptions configures BPF program compilation.
type CompileOptions struct {
	// IncludePaths are additional directories to search for headers.
	IncludePaths []string

	// Defines are preprocessor macros to define (e.g., {"DEBUG": "1"}).
	Defines map[string]string

	// TargetArch overrides the target architecture (default: current arch).
	TargetArch string

	// OptLevel sets the optimization level (default: 2).
	OptLevel int

	// ClangPath overrides the path to the clang binary.
	ClangPath string
}

// DefaultCompileOptions returns sensible defaults for BPF compilation.
func DefaultCompileOptions() CompileOptions {
	return CompileOptions{
		OptLevel: 2,
	}
}

// Compiler compiles BPF C source code into ELF objects loadable by cilium/ebpf.
type Compiler struct {
	clangPath    string
	templateDir  string
	outputDir    string
	kernelHeaders string
}

// NewCompiler creates a new BPF compiler.
func NewCompiler(templateDir, outputDir string) (*Compiler, error) {
	clang, err := findClang("")
	if err != nil {
		return nil, fmt.Errorf("clang not found: %w", err)
	}

	kernelHeaders, err := DetectKernelHeaders()
	if err != nil {
		klog.Warningf("Kernel headers not found: %v (compilation may fail)", err)
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}

	return &Compiler{
		clangPath:     clang,
		templateDir:   templateDir,
		outputDir:     outputDir,
		kernelHeaders: kernelHeaders,
	}, nil
}

// CompileBPF compiles a BPF C source file into an ELF object.
func (c *Compiler) CompileBPF(ctx context.Context, sourcePath string, outputPath string, opts CompileOptions) error {
	if opts.ClangPath != "" {
		c.clangPath = opts.ClangPath
	}

	args := []string{
		"-target", "bpf",
		fmt.Sprintf("-O%d", opts.OptLevel),
		"-g", // debug info for BTF
		"-c", sourcePath,
		"-o", outputPath,
		"-Wall",
		"-Werror",
	}

	// Add target architecture
	targetArch := opts.TargetArch
	if targetArch == "" {
		targetArch = goArchToBPF(runtime.GOARCH)
	}
	args = append(args, fmt.Sprintf("-D__TARGET_ARCH_%s", targetArch))

	// Add include paths
	if c.templateDir != "" {
		args = append(args, "-I", c.templateDir)
	}
	if c.kernelHeaders != "" {
		args = append(args, "-I", c.kernelHeaders)
		args = append(args, "-I", filepath.Join(c.kernelHeaders, "uapi"))
	}
	for _, inc := range opts.IncludePaths {
		args = append(args, "-I", inc)
	}

	// Add preprocessor defines
	for k, v := range opts.Defines {
		if v != "" {
			args = append(args, fmt.Sprintf("-D%s=%s", k, v))
		} else {
			args = append(args, fmt.Sprintf("-D%s", k))
		}
	}

	klog.V(4).Infof("Compiling BPF: %s %s", c.clangPath, strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, c.clangPath, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("clang compilation failed: %w\nOutput: %s", err, string(output))
	}

	klog.Infof("Compiled BPF program: %s -> %s", sourcePath, outputPath)
	return nil
}

// CompileTemplate compiles a named template from the templates directory.
func (c *Compiler) CompileTemplate(ctx context.Context, templateName string, opts CompileOptions) (string, error) {
	sourcePath := filepath.Join(c.templateDir, templateName)
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return "", fmt.Errorf("template %s not found at %s", templateName, sourcePath)
	}

	outputName := strings.TrimSuffix(templateName, ".c") + ".o"
	outputPath := filepath.Join(c.outputDir, outputName)

	if err := c.CompileBPF(ctx, sourcePath, outputPath, opts); err != nil {
		return "", err
	}

	return outputPath, nil
}

// ListTemplates returns available BPF template names.
func (c *Compiler) ListTemplates() ([]string, error) {
	entries, err := os.ReadDir(c.templateDir)
	if err != nil {
		return nil, fmt.Errorf("read template dir: %w", err)
	}

	var templates []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".c") {
			templates = append(templates, entry.Name())
		}
	}
	return templates, nil
}

// DetectKernelHeaders finds the kernel header directory.
func DetectKernelHeaders() (string, error) {
	// Try common locations
	candidates := []string{
		"/usr/include",
		"/usr/include/linux",
	}

	// Try kernel-specific headers
	uname, err := exec.Command("uname", "-r").Output()
	if err == nil {
		release := strings.TrimSpace(string(uname))
		candidates = append([]string{
			filepath.Join("/lib/modules", release, "build", "include"),
			filepath.Join("/lib/modules", release, "source", "include"),
			filepath.Join("/usr/src/linux-headers-"+release, "include"),
		}, candidates...)
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("no kernel headers found in standard locations")
}

// findClang locates the clang binary.
func findClang(preferred string) (string, error) {
	if preferred != "" {
		if _, err := exec.LookPath(preferred); err == nil {
			return preferred, nil
		}
	}

	candidates := []string{"clang", "clang-18", "clang-17", "clang-16", "clang-15", "clang-14"}
	for _, name := range candidates {
		if path, err := exec.LookPath(name); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("clang not found in PATH (tried: %s)", strings.Join(candidates, ", "))
}

// goArchToBPF maps Go architecture names to BPF target architecture defines.
func goArchToBPF(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86"
	case "arm64":
		return "arm64"
	case "arm":
		return "arm"
	default:
		return "x86"
	}
}
