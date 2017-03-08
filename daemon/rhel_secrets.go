/*
 * suse-secrets: patch for Docker to implement SUSE secrets
 * Copyright (C) 2017 SUSE LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package daemon

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/container"
	"github.com/opencontainers/go-digest"

	swarmtypes "github.com/docker/docker/api/types/swarm"
	swarmexec "github.com/docker/swarmkit/agent/exec"
	swarmapi "github.com/docker/swarmkit/api"
)

func init() {
	// Output to tell us in logs that RHEL:secrets is enabled.
	logrus.Infof("RHEL:secrets :: enabled")
}

// Creating a fake file.
type RHELFakeFile struct {
	Path string
	Uid  int
	Gid  int
	Mode os.FileMode
	Data []byte
}

func (s RHELFakeFile) id() string {
	return fmt.Sprintf("rhel::%s:%s", digest.FromBytes(s.Data), s.Path)
}

func (s RHELFakeFile) toSecret() *swarmapi.Secret {
	return &swarmapi.Secret{
		ID:       s.id(),
		Internal: true,
		Spec: swarmapi.SecretSpec{
			Data: s.Data,
		},
	}
}

func (s RHELFakeFile) toSecretReference() *swarmtypes.SecretReference {
	return &swarmtypes.SecretReference{
		SecretID:   s.id(),
		SecretName: s.id(),
		File: &swarmtypes.SecretReferenceFileTarget{
			Name: s.Path,
			UID:  fmt.Sprintf("%d", s.Uid),
			GID:  fmt.Sprintf("%d", s.Gid),
			Mode: s.Mode,
		},
	}
}

// readDir will recurse into a directory prefix/dir, and return the set of secrets
// in that directory. The Path attribute of each has the prefix stripped. Symlinks
// are evaluated.
func readDir(prefix, dir string) ([]*RHELFakeFile, error) {
	var rhelFiles []*RHELFakeFile

	path := filepath.Join(prefix, dir)

	fi, err := os.Stat(path)
	if err != nil {
		// Ignore dangling symlinks.
		if os.IsNotExist(err) {
			logrus.Warnf("RHEL:secrets :: dangling symlink: %s", path)
			return rhelFiles, nil
		}
		return nil, err
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		logrus.Warnf("RHEL:secrets :: failed to cast directory stat_t: defaulting to owned by root:root: %s", path)
	}

	rhelFiles = append(rhelFiles, &RHELFakeFile{
		Path: dir,
		Uid:  int(stat.Uid),
		Gid:  int(stat.Gid),
		Mode: fi.Mode(),
	})

	files, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		subpath := filepath.Join(dir, f.Name())

		if f.IsDir() {
			secrets, err := readDir(prefix, subpath)
			if err != nil {
				return nil, err
			}
			rhelFiles = append(rhelFiles, secrets...)
		} else {
			secrets, err := readFile(prefix, subpath)
			if err != nil {
				return nil, err
			}
			rhelFiles = append(rhelFiles, secrets...)
		}
	}

	return rhelFiles, nil
}

// readFile returns a secret given a file under a given prefix.
func readFile(prefix, file string) ([]*RHELFakeFile, error) {
	var rhelFiles []*RHELFakeFile

	path := filepath.Join(prefix, file)
	fi, err := os.Stat(path)
	if err != nil {
		// Ignore dangling symlinks.
		if os.IsNotExist(err) {
			logrus.Warnf("RHEL:secrets :: dangling symlink: %s", path)
			return rhelFiles, nil
		}
		return nil, err
	}

	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		logrus.Warnf("RHEL:secrets :: failed to cast file stat_t: defaulting to owned by root:root: %s", path)
	}

	if fi.IsDir() {
		secrets, err := readDir(prefix, file)
		if err != nil {
			return nil, err
		}
		rhelFiles = append(rhelFiles, secrets...)
	} else {
		bytes, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
		rhelFiles = append(rhelFiles, &RHELFakeFile{
			Path: file,
			Uid:  int(stat.Uid),
			Gid:  int(stat.Gid),
			Mode: fi.Mode(),
			Data: bytes,
		})
	}

	return rhelFiles, nil
}

// getHostRHELSecretData returns the list of RHELFakeFiles the need to be added
// as RHEL secrets.
func getHostRHELSecretData() ([]*RHELFakeFile, error) {
	secrets := []*RHELFakeFile{}

	credentials, err := readDir("/usr/share/rhel", "secrets")
	if err != nil {
		if os.IsNotExist(err) {
			credentials = []*RHELFakeFile{}
		} else {
			logrus.Errorf("RHEL:secrets :: error while reading zypp credentials: %s", err)
			return nil, err
		}
	}
	secrets = append(secrets, credentials...)

	overrides, err := readDir("/etc/container/rhel", "secrets")
	if err != nil {
		if os.IsNotExist(err) {
			credentials = []*RHELFakeFile{}
		} else {
			logrus.Errorf("RHEL:secrets :: error while reading zypp credentials: %s", err)
			return nil, err
		}
	}
	secrets = append(secrets, overrides...)

	return secrets, nil
}

// In order to reduce the amount of code touched outside of this file, we
// implement the swarm API for SecretGetter. This asserts that this requirement
// will always be matched.
var _ swarmexec.SecretGetter = &rhelSecretGetter{}

type rhelSecretGetter struct {
	dfl     swarmexec.SecretGetter
	secrets map[string]*swarmapi.Secret
}

func (s *rhelSecretGetter) Get(id string) *swarmapi.Secret {
	logrus.Debugf("RHEL:secrets :: id=%s requested from rhelSecretGetter", id)

	secret, ok := s.secrets[id]
	if !ok {
		// fallthrough
		return s.dfl.Get(id)
	}

	return secret
}

func (daemon *Daemon) injectRHELSecretStore(c *container.Container) error {
	newSecretStore := &rhelSecretGetter{
		dfl:     c.SecretStore,
		secrets: make(map[string]*swarmapi.Secret),
	}

	secrets, err := getHostRHELSecretData()
	if err != nil {
		return err
	}

	for _, secret := range secrets {
		newSecretStore.secrets[secret.id()] = secret.toSecret()
		c.SecretReferences = append(c.SecretReferences, secret.toSecretReference())
	}

	c.SecretStore = newSecretStore
	return nil
}
