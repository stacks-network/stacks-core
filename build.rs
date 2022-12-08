fn main() {
    if let Some(git) = build_utils::current_git_hash() {
        println!("cargo:rustc-env=GIT_COMMIT={}", git);
    }
    if let Some(git) = build_utils::current_git_branch() {
        println!("cargo:rustc-env=GIT_BRANCH={}", git);
    }
    if !build_utils::is_working_tree_clean() {
        println!("cargo:rustc-env=GIT_TREE_CLEAN=+");
    }
}
