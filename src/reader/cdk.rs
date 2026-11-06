//! CDK cloud assemblies (`cdk.out`): every stack, including nested stacks and stage
//! assemblies, with the environment each stack was synthesized for.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::{Result, ScanError};
use crate::model::{DeployEnv, Template};

const MANIFEST: &str = "manifest.json";

/// Reads all stacks of the assembly at `dir`. Logical ids become `<stack>/<logical id>`.
pub fn read_assembly(dir: &Path) -> Result<Template> {
    let root = dir
        .canonicalize()
        .map_err(|e| ScanError::Input(format!("{}: {e}", dir.display())))?;
    let mut walk = Walk {
        root,
        visited: HashSet::new(),
        t: Template::default(),
    };
    walk.assembly(dir, 0)?;
    if walk.t.resources.is_empty() {
        return Err(ScanError::Input(format!(
            "{}: the cloud assembly contains no stack resources",
            dir.display()
        )));
    }
    Ok(walk.t)
}

/// The environment of `template` when it sits in a cloud assembly, else `None`.
pub fn env_of(template: &Path) -> Option<DeployEnv> {
    let dir = template.parent()?;
    let file = template.file_name()?.to_str()?;
    let manifest = read_manifest(dir).ok()?;
    stacks(&manifest)
        .find(|(_, a)| a["properties"]["templateFile"] == file)
        .and_then(|(_, a)| env(a))
}

/// Nesting deeper than this is not something CDK writes; it stops crafted input.
const MAX_DEPTH: usize = 32;

/// State of one assembly walk. Every path read must stay under `root`, and each file
/// or directory is read once, so a manifest or nested stack that points back at
/// itself or outside the assembly is rejected instead of recursing or leaking files.
struct Walk {
    root: PathBuf,
    visited: HashSet<PathBuf>,
    t: Template,
}

impl Walk {
    /// Resolves `name` under `dir`, inside the assembly root, and not seen before.
    fn enter(&mut self, dir: &Path, name: &str, depth: usize) -> Result<PathBuf> {
        let path = dir.join(name);
        if depth > MAX_DEPTH {
            return Err(ScanError::Input(format!(
                "{}: nested deeper than {MAX_DEPTH} levels",
                path.display()
            )));
        }
        let real = path
            .canonicalize()
            .map_err(|e| ScanError::Input(format!("{}: {e}", path.display())))?;
        if !real.starts_with(&self.root) {
            return Err(ScanError::Input(format!(
                "{}: points outside the cloud assembly",
                path.display()
            )));
        }
        if !self.visited.insert(real.clone()) {
            return Err(ScanError::Input(format!(
                "{}: referenced more than once, the assembly contains a cycle",
                path.display()
            )));
        }
        Ok(real)
    }

    fn assembly(&mut self, dir: &Path, depth: usize) -> Result<()> {
        let manifest = read_manifest(dir)?;
        for (id, a) in stacks(&manifest) {
            let file = a["properties"]["templateFile"]
                .as_str()
                .ok_or_else(|| ScanError::Input(format!("stack {id} has no templateFile")))?;
            self.stack(dir, file, id, &env(a), depth)?;
        }
        for (_, a) in artifacts(&manifest).filter(|(_, a)| a["type"] == "cdk:cloud-assembly") {
            if let Some(sub) = a["properties"]["directoryName"].as_str() {
                let sub = self.enter(dir, sub, depth + 1)?;
                self.assembly(&sub, depth + 1)?;
            }
        }
        Ok(())
    }

    /// Reads one stack template, and the nested stacks CDK wrote next to it as assets.
    fn stack(
        &mut self,
        dir: &Path,
        file: &str,
        id: &str,
        env: &Option<DeployEnv>,
        depth: usize,
    ) -> Result<()> {
        let path = self.enter(dir, file, depth)?;
        let text = std::fs::read_to_string(&path)
            .map_err(|e| ScanError::Input(format!("{}: {e}", path.display())))?;
        let doc: Value = serde_json::from_str(&text)
            .map_err(|e| ScanError::Input(format!("{}: {e}", path.display())))?;
        let parsed = super::from_value(&doc, env.clone())?;
        for (name, mut o) in parsed.outputs {
            let full = format!("{id}/{name}");
            o.logical_id.clone_from(&full);
            self.t.outputs.insert(full, o);
        }
        for (logical_id, mut r) in parsed.resources {
            let full = format!("{id}/{logical_id}");
            let nested = doc["Resources"][&logical_id]["Metadata"]["aws:asset:path"].as_str();
            match nested {
                Some(f) if r.resource_type == "AWS::CloudFormation::Stack" => {
                    self.stack(dir, f, &full, env, depth + 1)?;
                }
                _ => {
                    r.logical_id.clone_from(&full);
                    self.t.resources.insert(full, r);
                }
            }
        }
        Ok(())
    }
}

fn read_manifest(dir: &Path) -> Result<Value> {
    let path = dir.join(MANIFEST);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        ScanError::Input(format!("{}: not a CDK cloud assembly ({e})", dir.display()))
    })?;
    serde_json::from_str(&text).map_err(|e| ScanError::Input(format!("{}: {e}", path.display())))
}

fn artifacts(manifest: &Value) -> impl Iterator<Item = (&String, &Value)> {
    manifest["artifacts"].as_object().into_iter().flatten()
}

fn stacks(manifest: &Value) -> impl Iterator<Item = (&String, &Value)> {
    artifacts(manifest).filter(|(_, a)| a["type"] == "aws:cloudformation:stack")
}

/// `aws://<account>/<region>`; CDK writes `unknown-account`/`unknown-region` for
/// environment-agnostic stacks.
fn env(artifact: &Value) -> Option<DeployEnv> {
    let rest = artifact["environment"].as_str()?.strip_prefix("aws://")?;
    let (account, region) = rest.split_once('/')?;
    let known = |v: &str| (!v.starts_with("unknown-")).then(|| v.to_string());
    let e = DeployEnv {
        region: known(region),
        account: known(account),
    };
    (e != DeployEnv::default()).then_some(e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cdk.out")
    }

    #[test]
    fn reads_all_stacks_including_nested_stages() {
        let t = read_assembly(&fixture()).unwrap();
        assert!(t.resources.contains_key("AppStack/Bucket"));
        assert!(t.resources.contains_key("ProdApp/Queue"));
        assert!(
            t.resources.contains_key("AppStack/Data/Table"),
            "nested stack"
        );
        assert!(!t.resources.contains_key("AppStack/Data"));
        let env = t.resources["AppStack/Bucket"].env.clone().unwrap();
        assert_eq!(env.region.as_deref(), Some("eu-central-1"));
        assert_eq!(env.account.as_deref(), Some("111122223333"));
        assert_eq!(t.resources["ProdApp/Queue"].env, None, "env-agnostic stack");
    }

    #[test]
    fn single_template_inside_an_assembly_gets_its_env() {
        let env = env_of(&fixture().join("AppStack.template.json")).unwrap();
        assert_eq!(env.region.as_deref(), Some("eu-central-1"));
        assert_eq!(env_of(Path::new("/nonexistent/x.json")), None);
    }

    /// A per-test scratch directory under `target/`, not the shared system temp dir.
    fn scratch(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-scratch")
            .join(name)
    }

    /// Writes a throwaway assembly into a scratch directory.
    fn assembly(name: &str, manifest: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = scratch(name).join("assembly");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(MANIFEST), manifest).unwrap();
        for (f, body) in files {
            std::fs::write(dir.join(f), body).unwrap();
        }
        dir
    }

    const ONE_STACK: &str = r#"{"artifacts":{"S":{"type":"aws:cloudformation:stack","properties":{"templateFile":"S.template.json"}}}}"#;

    #[test]
    fn self_referencing_nested_stack_is_rejected() {
        let dir = assembly(
            "cycle",
            ONE_STACK,
            &[(
                "S.template.json",
                r#"{"Resources":{"N":{"Type":"AWS::CloudFormation::Stack","Metadata":{"aws:asset:path":"S.template.json"}}}}"#,
            )],
        );
        let err = read_assembly(&dir).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("cycle"), "{err}");
    }

    #[test]
    fn paths_outside_the_assembly_are_rejected() {
        let outside = scratch("escape").join("secret.json");
        std::fs::create_dir_all(outside.parent().unwrap()).unwrap();
        std::fs::write(
            &outside,
            r#"{"Resources":{"R":{"Type":"AWS::S3::Bucket"}}}"#,
        )
        .unwrap();
        let manifest = format!(
            r#"{{"artifacts":{{"S":{{"type":"aws:cloudformation:stack","properties":{{"templateFile":"../{}"}}}}}}}}"#,
            outside.file_name().unwrap().to_str().unwrap()
        );
        let dir = assembly("escape", &manifest, &[]);
        let err = read_assembly(&dir).unwrap_err();
        assert_eq!(err.exit_code(), 1);
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[test]
    fn stage_assembly_pointing_at_itself_is_rejected() {
        let dir = assembly(
            "stage",
            r#"{"artifacts":{"St":{"type":"cdk:cloud-assembly","properties":{"directoryName":"."}}}}"#,
            &[],
        );
        assert_eq!(read_assembly(&dir).unwrap_err().exit_code(), 1);
    }

    #[test]
    fn directory_without_manifest_is_rejected() {
        let err = read_assembly(Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap_err();
        assert_eq!(err.exit_code(), 1);
    }
}
