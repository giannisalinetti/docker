package daemon

import (
	"io"

	"github.com/docker/docker/distribution"
	"github.com/docker/docker/pkg/progress"
	"github.com/docker/docker/reference"
	"github.com/docker/engine-api/types"
	"golang.org/x/net/context"
)

// PushImage initiates a push operation on the repository named localName.
func (daemon *Daemon) PushImage(ctx context.Context, image, tag string, metaHeaders map[string][]string, authConfigs map[string]types.AuthConfig, outStream io.Writer) error {
	ref, err := reference.ParseNamed(image)
	if err != nil {
		return err
	}
	if tag != "" {
		// Push by digest is not supported, so only tags are supported.
		ref, err = reference.WithTag(ref, tag)
		if err != nil {
			return err
		}
	}

	// Include a buffer so that slow client connections don't affect
	// transfer performance.
	progressChan := make(chan progress.Progress, 100)

	writesDone := make(chan struct{})

	ctx, cancelFunc := context.WithCancel(ctx)

	go func() {
		writeDistributionProgress(cancelFunc, outStream, progressChan)
		close(writesDone)
	}()

	imagePushConfig := &distribution.ImagePushConfig{
		MetaHeaders:      metaHeaders,
		AuthConfigs:      authConfigs,
		ProgressOutput:   progress.ChanOutput(progressChan),
		RegistryService:  daemon.RegistryService,
		ImageEventLogger: daemon.LogImageEvent,
		MetadataStore:    daemon.distributionMetadataStore,
		LayerStore:       daemon.layerStore,
		ImageStore:       daemon.imageStore,
		ReferenceStore:   daemon.referenceStore,
		TrustKey:         daemon.trustKey,
		UploadManager:    daemon.uploadManager,
	}

	err = distribution.Push(ctx, ref, imagePushConfig)
	close(progressChan)
	<-writesDone
	return err
}
