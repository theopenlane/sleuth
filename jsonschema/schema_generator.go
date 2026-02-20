//go:build generate

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/invopop/jsonschema"
	iyaml "github.com/invopop/yaml"
	"github.com/mcuadros/go-defaults"

	"github.com/theopenlane/utils/envparse"

	"github.com/theopenlane/sleuth/config"
)

const (
	// tagName is the struct tag used for field naming in the schema
	tagName = "koanf"
	// skipper is the tag value that indicates a field should be skipped
	skipper = "-"
	// defaultTag is the struct tag used for default values
	defaultTag = "default"
	// sensitiveTag is the struct tag used to mark sensitive fields
	sensitiveTag = "sensitive"
	// varPrefix is the environment variable prefix
	varPrefix = "SLEUTH"
	// jsonSchemaPath is the output path for the JSON schema file
	jsonSchemaPath = "./jsonschema/sleuth.config.json"
	// yamlConfigPath is the output path for the example YAML config
	yamlConfigPath = "./config/config.example.yaml"
	// envConfigPath is the output path for the example env file
	envConfigPath = "./config/.env.example"
	// ownerReadWrite is the file permission for generated files
	ownerReadWrite = 0600
)

// commentPackages is the list of packages to parse for Go comments
var commentPackages = []string{
	"./config",
}

// main generates the JSON schema, YAML config, and env file from the config struct
func main() {
	cfg := buildDefaultConfig()

	commentMap, err := buildCommentMap(commentPackages)
	if err != nil {
		panic(err)
	}

	if err := generateJSONSchema(cfg, commentMap); err != nil {
		panic(err)
	}

	if err := generateYAMLConfig(cfg); err != nil {
		panic(err)
	}

	if err := generateEnvFile(cfg); err != nil {
		panic(err)
	}
}

// buildDefaultConfig returns a config struct populated with default values
func buildDefaultConfig() *config.Config {
	cfg := &config.Config{}
	defaults.SetDefaults(cfg)

	if len(cfg.Scanner.NucleiSeverity) == 0 {
		cfg.Scanner.NucleiSeverity = []string{"critical", "high", "medium", "low", "info"}
	}

	return cfg
}

// buildCommentMap parses Go comments from the specified packages for use in schema descriptions
func buildCommentMap(packages []string) (map[string]string, error) {
	r := &jsonschema.Reflector{}

	for _, pkg := range packages {
		if err := r.AddGoComments("github.com/theopenlane/sleuth/", pkg); err != nil {
			return nil, fmt.Errorf("failed to add go comments for package %s: %w", pkg, err)
		}
	}

	if r.CommentMap == nil {
		return map[string]string{}, nil
	}

	return r.CommentMap, nil
}

// generateJSONSchema creates the JSON schema file from the config structure
func generateJSONSchema(cfg *config.Config, commentMap map[string]string) error {
	r := jsonschema.Reflector{
		ExpandedStruct:             true,
		RequiredFromJSONSchemaTags: true,
		FieldNameTag:               tagName,
		CommentMap:                 commentMap,
	}

	s := r.Reflect(cfg)

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON schema: %w", err)
	}

	if err := os.WriteFile(jsonSchemaPath, data, ownerReadWrite); err != nil {
		return fmt.Errorf("failed to write JSON schema file: %w", err)
	}

	fmt.Printf("wrote %s\n", jsonSchemaPath)

	return nil
}

// generateYAMLConfig creates the example YAML configuration file with defaults populated
func generateYAMLConfig(cfg *config.Config) error {
	converted := structToMap(reflect.ValueOf(cfg).Elem())

	data, err := iyaml.Marshal(converted)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML config: %w", err)
	}

	if err := os.WriteFile(yamlConfigPath, data, ownerReadWrite); err != nil {
		return fmt.Errorf("failed to write YAML config file: %w", err)
	}

	fmt.Printf("wrote %s\n", yamlConfigPath)

	return nil
}

// structToMap converts a struct to a map, rendering time.Duration values as human-readable strings
func structToMap(v reflect.Value) map[string]any {
	v = reflect.Indirect(v)
	result := make(map[string]any)
	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		key := field.Tag.Get(tagName)
		if key == "" || key == skipper {
			continue
		}

		fieldVal := v.Field(i)
		result[key] = convertValue(fieldVal)
	}

	return result
}

// convertValue converts a reflect.Value to a YAML-friendly representation
func convertValue(v reflect.Value) any {
	if !v.IsValid() {
		return nil
	}

	for v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}

		v = v.Elem()
	}

	if isDuration(v.Type()) {
		return time.Duration(v.Int()).String()
	}

	switch v.Kind() {
	case reflect.Struct:
		return structToMap(v)
	case reflect.Slice, reflect.Array:
		items := make([]any, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			items = append(items, convertValue(v.Index(i)))
		}
		return items
	case reflect.Map:
		out := make(map[string]any)
		iter := v.MapRange()
		for iter.Next() {
			if iter.Key().Kind() == reflect.String {
				out[iter.Key().String()] = convertValue(iter.Value())
			}
		}
		return out
	default:
		return v.Interface()
	}
}

// generateEnvFile creates the example environment variable file from the config structure
func generateEnvFile(cfg *config.Config) error {
	cp := envparse.Config{
		FieldTagName: tagName,
		Skipper:      skipper,
	}

	vars, err := cp.GatherEnvInfo(varPrefix, cfg)
	if err != nil {
		return fmt.Errorf("failed to gather environment info: %w", err)
	}

	var b strings.Builder

	for _, v := range vars {
		if v.Tags.Get(sensitiveTag) == "true" {
			b.WriteString(fmt.Sprintf("# %s is sensitive and should be set securely\n", v.Key))
			b.WriteString(fmt.Sprintf("%s=\"\"\n", v.Key))

			continue
		}

		defaultVal := v.Tags.Get(defaultTag)

		if isDuration(v.Type) && defaultVal != "" {
			d, parseErr := time.ParseDuration(defaultVal)
			if parseErr == nil {
				defaultVal = d.String()
			}
		}

		b.WriteString(fmt.Sprintf("%s=\"%s\"\n", v.Key, defaultVal))
	}

	if err := os.WriteFile(envConfigPath, []byte(b.String()), ownerReadWrite); err != nil {
		return fmt.Errorf("failed to write env file: %w", err)
	}

	fmt.Printf("wrote %s\n", envConfigPath)

	return nil
}

// isDuration checks if the provided reflect.Type represents time.Duration
func isDuration(t reflect.Type) bool {
	return t == reflect.TypeOf(time.Duration(0))
}
