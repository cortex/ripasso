use std::{
    fmt::Display,
    path::{Path, PathBuf},
    str,
};

use chrono::{DateTime, Local, TimeZone};
use git2::{Oid, Repository};

use crate::{
    crypto::{Crypto, FindSigningFingerprintStrategy, VerificationError},
    error::{Error, Result},
    pass::{PasswordEntry, PasswordStore, RepositoryStatus, to_result},
    signature::SignatureStatus,
};

fn git_branch_name(repo: &Repository) -> Result<String> {
    let head = repo.find_reference("HEAD")?;
    let symbolic = head
        .symbolic_target()
        .ok_or(Error::Generic("no symbolic target"))?;

    let mut parts = symbolic.split('/');

    Ok(parts
        .nth(2)
        .ok_or(Error::Generic(
            "symbolic target name should be on format 'refs/heads/main'",
        ))?
        .to_owned())
}

/// Apply the changes to the git repository.
pub fn commit(
    repo: &Repository,
    signature: &git2::Signature,
    message: &str,
    tree: &git2::Tree,
    parents: &[&git2::Commit],
    crypto: &(dyn Crypto + Send),
) -> Result<Oid> {
    if should_sign(repo) {
        let commit_buf = repo.commit_create_buffer(
            signature, // author
            signature, // committer
            message,   // commit message
            tree,      // tree
            parents,   // parents
        )?;

        let commit_as_str = str::from_utf8(&commit_buf)?;

        let sig = crypto.sign_string(commit_as_str, &[], &FindSigningFingerprintStrategy::GIT)?;

        let commit = repo.commit_signed(commit_as_str, &sig, Some("gpgsig"))?;

        if let Ok(mut head) = repo.head() {
            head.set_target(commit, "added a signed commit using ripasso")?;
        } else {
            repo.branch(&git_branch_name(repo)?, &repo.find_commit(commit)?, false)?;
        }

        Ok(commit)
    } else {
        let commit = repo.commit(
            Some("HEAD"), //  point HEAD to our new commit
            signature,    // author
            signature,    // committer
            message,      // commit message
            tree,         // tree
            parents,      // parents
        )?;

        Ok(commit)
    }
}

pub fn find_last_commit(repo: &Repository) -> Result<git2::Commit<'_>> {
    let obj = repo.head()?.resolve()?.peel(git2::ObjectType::Commit)?;
    obj.into_commit()
        .map_err(|_| Error::Generic("Couldn't find commit"))
}

/// Returns if a git commit should be gpg signed or not.
fn should_sign(repo: &Repository) -> bool {
    repo.config()
        .is_ok_and(|config| config.get_bool("commit.gpgsign").unwrap_or(false))
}

/// returns true if the diff between the two commits contains the path that the `DiffOptions`
/// have been prepared with
pub fn match_with_parent(
    repo: &Repository,
    commit: &git2::Commit,
    parent: &git2::Commit,
    opts: &mut git2::DiffOptions,
) -> Result<bool> {
    let a = parent.tree()?;
    let b = commit.tree()?;
    let diff = repo.diff_tree_to_tree(Some(&a), Some(&b), Some(opts))?;
    Ok(diff.deltas().len() > 0)
}

/// Add a file to the store, and commit it to the supplied git repository.
pub fn add_and_commit_internal(
    repo: &Repository,
    paths: &[PathBuf],
    message: &str,
    crypto: &(dyn Crypto + Send),
) -> Result<Oid> {
    let mut index = repo.index()?;
    for path in paths {
        index.add_path(path)?;
        index.write()?;
    }
    let signature = repo.signature()?;

    let mut parents = vec![];
    let parent_commit;
    if let Ok(pc) = find_last_commit(repo) {
        parent_commit = pc;
        parents.push(&parent_commit);
    }
    let oid = index.write_tree()?;
    let tree = repo.find_tree(oid)?;

    let oid = commit(repo, &signature, message, &tree, &parents, crypto)?;

    Ok(oid)
}

/// Remove a file from the store, and commit the deletion to the supplied git repository.
pub fn remove_and_commit(store: &PasswordStore, paths: &[PathBuf], message: &str) -> Result<Oid> {
    let repo = store
        .repo()
        .map_err(|_| Error::Generic("must have a repository"))?;

    let mut index = repo.index()?;
    for path in paths {
        index.remove_path(path)?;
        index.write()?;
    }
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit_res = find_last_commit(&repo);
    let mut parents = vec![];
    let parent_commit;
    if parent_commit_res.is_ok() {
        parent_commit = parent_commit_res?;
        parents.push(&parent_commit);
    }
    index.write_tree()?;
    let tree = repo.find_tree(oid)?;

    let oid = commit(
        &repo,
        &signature,
        message,
        &tree,
        &parents,
        store.get_crypto(),
    )?;

    Ok(oid)
}

/// Move a file to a new place in the store, and commit the move to the supplied git repository.
pub fn move_and_commit(
    store: &PasswordStore,
    old_name: &Path,
    new_name: &Path,
    message: &str,
) -> Result<Oid> {
    let repo = store
        .repo()
        .map_err(|_| Error::Generic("must have a repository"))?;

    let mut index = repo.index()?;
    index.remove_path(old_name)?;
    index.add_path(new_name)?;
    index.write()?;
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit_res = find_last_commit(&repo);
    let mut parents = vec![];
    let parent_commit;
    if parent_commit_res.is_ok() {
        parent_commit = parent_commit_res?;
        parents.push(&parent_commit);
    }
    let tree = repo.find_tree(oid)?;

    let oid = commit(
        &repo,
        &signature,
        message,
        &tree,
        &parents,
        store.get_crypto(),
    )?;

    Ok(oid)
}

/// find the origin of the git repo, with the following strategy:
/// find the branch that HEAD points to, and read the remote configured for that branch
/// returns the remote and the name of the local branch
fn find_origin(repo: &Repository) -> Result<(git2::Remote<'_>, String)> {
    for branch in repo.branches(Some(git2::BranchType::Local))? {
        let b = branch?.0;
        if b.is_head() {
            let upstream_name_buf = repo.branch_upstream_remote(&format!(
                "refs/heads/{}",
                &b.name()?.ok_or("no branch name")?
            ))?;
            let upstream_name = upstream_name_buf
                .as_str()
                .ok_or("Can't convert to string")?;
            let origin = repo.find_remote(upstream_name)?;
            return Ok((origin, b.name()?.ok_or("no branch name")?.to_owned()));
        }
    }

    Err(Error::Generic("no remotes configured"))
}

/// function that can be used for callback handling of the ssh interaction in git2
fn cred(
    tried_sshkey: &mut bool,
    _url: &str,
    username: Option<&str>,
    allowed: git2::CredentialType,
) -> std::result::Result<git2::Cred, git2::Error> {
    let sys_username = whoami::username();
    let user: &str = username.map_or(&sys_username, |name| name);

    if allowed.contains(git2::CredentialType::USERNAME) {
        return git2::Cred::username(user);
    }

    if *tried_sshkey {
        return Err(git2::Error::from_str("no authentication available"));
    }
    *tried_sshkey = true;

    git2::Cred::ssh_key_from_agent(user)
}

/// Push your changes to the remote git repository.
/// # Errors
/// Returns an `Err` if the repository doesn't exist or if a git operation fails
pub fn push(store: &PasswordStore) -> Result<()> {
    let repo = store
        .repo()
        .map_err(|_| Error::Generic("must have a repository"))?;

    let mut ref_status = None;
    let (mut origin, branch_name) = find_origin(&repo)?;
    let res = {
        let mut callbacks = git2::RemoteCallbacks::new();
        let mut tried_ssh_key = false;
        callbacks.credentials(|_url, username, allowed| {
            cred(&mut tried_ssh_key, _url, username, allowed)
        });
        callbacks.push_update_reference(|_refname, status| {
            ref_status = status.map(std::borrow::ToOwned::to_owned);
            Ok(())
        });
        let mut opts = git2::PushOptions::new();
        opts.remote_callbacks(callbacks);
        origin.push(&[format!("refs/heads/{branch_name}")], Some(&mut opts))
    };
    match res {
        Ok(()) if ref_status.is_none() => Ok(()),
        Ok(()) => Err(Error::GenericDyn(format!(
            "failed to push a ref: {ref_status:?}",
        ))),
        Err(e) => Err(Error::GenericDyn(format!("failure to push: {e}"))),
    }
}

/// Pull new changes from the remote git repository.
/// # Errors
/// Returns an `Err` if the repository doesn't exist or if a git operation fails
pub fn pull(store: &PasswordStore) -> Result<()> {
    let repo = store
        .repo()
        .map_err(|_| Error::Generic("must have a repository"))?;

    let (mut origin, branch_name) = find_origin(&repo)?;

    let mut cb = git2::RemoteCallbacks::new();
    let mut tried_ssh_key = false;
    cb.credentials(|_url, username, allowed| cred(&mut tried_ssh_key, _url, username, allowed));

    let mut opts = git2::FetchOptions::new();
    opts.remote_callbacks(cb);
    origin.fetch(&[branch_name], Some(&mut opts), None)?;

    let remote_oid = repo.refname_to_id("FETCH_HEAD")?;
    let head_oid = repo.refname_to_id("HEAD")?;

    let (_, behind) = repo.graph_ahead_behind(head_oid, remote_oid)?;

    if behind == 0 {
        return Ok(());
    }

    let remote_annotated_commit = repo.find_annotated_commit(remote_oid)?;
    let remote_commit = repo.find_commit(remote_oid)?;
    repo.merge(&[&remote_annotated_commit], None, None)?;

    //commit it
    let mut index = repo.index()?;
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;
    let message = "pull and merge by ripasso";
    let _commit = repo.commit(
        Some("HEAD"), //  point HEAD to our new commit
        &signature,   // author
        &signature,   // committer
        message,      // commit message
        &tree,        // tree
        &[&parent_commit, &remote_commit],
    )?; // parents

    //cleanup
    repo.cleanup_state()?;
    Ok(())
}

fn triple<T: Display>(
    e: &T,
) -> (
    Result<DateTime<Local>>,
    Result<String>,
    Result<SignatureStatus>,
) {
    (
        Err(Error::GenericDyn(format!("{e}"))),
        Err(Error::GenericDyn(format!("{e}"))),
        Err(Error::GenericDyn(format!("{e}"))),
    )
}

pub fn read_git_meta_data(
    base: &Path,
    path: &Path,
    repo: &Repository,
    store: &PasswordStore,
) -> (
    Result<DateTime<Local>>,
    Result<String>,
    Result<SignatureStatus>,
) {
    let path_res = path.strip_prefix(base);
    if let Err(e) = path_res {
        return triple(&e);
    }

    let blame_res = repo.blame_file(path_res.unwrap(), None);
    if let Err(e) = blame_res {
        return triple(&e);
    }
    let blame = blame_res.unwrap();
    let id_res = blame
        .get_line(1)
        .ok_or(Error::Generic("no git history found"));

    if let Err(e) = id_res {
        return triple(&e);
    }
    let id = id_res.unwrap().orig_commit_id();

    let commit_res = repo.find_commit(id);
    if let Err(e) = commit_res {
        return triple(&e);
    }
    let commit = commit_res.unwrap();

    let time = commit.time();
    let time_return = to_result(Local.timestamp_opt(time.seconds(), 0));

    let name_return = name_from_commit(&commit);

    let signature_return = verify_git_signature(repo, &id, store);

    (time_return, name_return, signature_return)
}

pub fn verify_git_signature(
    repo: &Repository,
    id: &Oid,
    store: &PasswordStore,
) -> Result<SignatureStatus> {
    let (signature, signed_data) = repo.extract_signature(id, Some("gpgsig"))?;

    let signature_str = str::from_utf8(&signature)?.to_owned();
    let signed_data_str = str::from_utf8(&signed_data)?.to_owned();

    if store.get_valid_gpg_signing_keys().is_empty() {
        return Err(Error::Generic(
            "signature not checked as PASSWORD_STORE_SIGNING_KEY is not configured",
        ));
    }
    match store.get_crypto().verify_sign(
        &signed_data_str.into_bytes(),
        &signature_str.into_bytes(),
        store.get_valid_gpg_signing_keys(),
    ) {
        Ok(r) => Ok(r),
        Err(VerificationError::InfrastructureError(message)) => Err(Error::GenericDyn(message)),
        Err(VerificationError::SignatureFromWrongRecipient) => Err(Error::Generic(
            "the commit wasn't signed by one of the keys specified in the environmental variable PASSWORD_STORE_SIGNING_KEY",
        )),
        Err(VerificationError::BadSignature) => Err(Error::Generic("Bad signature for commit")),
        Err(VerificationError::MissingSignatures) => {
            Err(Error::Generic("Missing signature for commit"))
        }
        Err(VerificationError::TooManySignatures) => Err(Error::Generic(
            "If a git commit contains more than one signature, something is fishy",
        )),
    }
}

/// Initialize a git repository for the store.
/// # Errors
/// Returns an `Err` if the git init fails
pub fn init_git_repo(base: &Path) -> Result<Repository> {
    Ok(Repository::init(base)?)
}

pub fn push_password_if_match(
    target: &Path,
    found: &Path,
    commit: &git2::Commit,
    repo: &Repository,
    passwords: &mut Vec<PasswordEntry>,
    oid: &Oid,
    store: &PasswordStore,
) -> bool {
    if *target == *found {
        let time = commit.time();
        let time_return = to_result(Local.timestamp_opt(time.seconds(), 0));

        let name_return = name_from_commit(commit);

        let signature_return = verify_git_signature(repo, oid, store);

        passwords.push(PasswordEntry::new(
            &store.get_store_path(),
            target,
            time_return,
            name_return,
            signature_return,
            RepositoryStatus::InRepo,
        ));
        return false;
    }
    true
}

/// Find the name of the committer, or an error message
fn name_from_commit(commit: &git2::Commit) -> Result<String> {
    commit
        .committer()
        .name()
        .map_or(Err(Error::Generic("missing committer name")), |s| {
            Ok(s.to_owned())
        })
}

#[cfg(test)]
#[path = "tests/git.rs"]
mod git_tests;
