#[ignore = "Currently not compatible with CI due to caching issues and the use of `--offline`"]
#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/trybuild/pass/*.rs");
    t.compile_fail("tests/trybuild/fail/*.rs");
}
