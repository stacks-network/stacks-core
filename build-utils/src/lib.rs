use std::process::Command;

pub fn current_git_hash() -> Option<String> {
    if option_env!("GIT_COMMIT") == None {
        let commit = Command::new("git")
            .arg("log")
            .arg("-1")
            .arg("--pretty=format:%h") // Abbreviated commit hash
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output();

        if let Ok(commit) = commit {
            if let Ok(commit) = String::from_utf8(commit.stdout) {
                return Some(commit);
            }
        }
    } else {
        return option_env!("GIT_COMMIT").map(String::from);
    }

    None
}

pub fn current_git_branch() -> Option<String> {
    if option_env!("GIT_BRANCH") == None {
        let commit = Command::new("git")
            .arg("rev-parse")
            .arg("--abbrev-ref")
            .arg("HEAD")
            .output();
        if let Ok(commit) = commit {
            if let Ok(commit) = String::from_utf8(commit.stdout) {
                return Some(commit);
            }
        }
    } else {
        return option_env!("GIT_BRANCH").map(String::from);
    }

    None
}

pub fn is_working_tree_clean() -> bool {
    let status = Command::new("git")
        .arg("diff")
        .arg("--quiet")
        .arg("--exit-code")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status();

    if let Ok(status) = status {
        status.code() == Some(0)
    } else {
        true
    }
}
