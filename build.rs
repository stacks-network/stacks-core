use std::process::Command;

fn current_git_hash() -> Option<String> {
    let commit = Command::new("git")
                         .arg("rev-parse")
                         .arg("HEAD")
                         .output();
    if let Ok(commit) = commit {
        if let Ok(commit) = String::from_utf8(commit.stdout) {
            return Some(commit)
        }
    }
    None
}

fn main() {
    if let Some(git) = current_git_hash() {
        println!("cargo:rustc-env=GIT_COMMIT={}", git);
    }
}
