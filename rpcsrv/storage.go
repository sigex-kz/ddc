package rpcsrv

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/sigex-kz/ddc"

	"github.com/patrickmn/go-cache"
)

const (
	constStorageCleanupInterval = 30
	constStorageEntryTTL        = 30 * 60
)

type builderEntry struct {
	di                 ddc.DocumentInfo
	embeddedFileName   string
	embeddedFileBuffer bytes.Buffer
	ddcFileBuffer      bytes.Buffer
}

type extractorEntry struct {
	ddcFileBuffer             bytes.Buffer
	documentOriginal          *ddc.AttachedFile
	documentOriginalBytesRead int
	signatures                []ddc.AttachedFile
}

type entry struct {
	created time.Time
	mutex   sync.Mutex
	be      *builderEntry
	ee      *extractorEntry
}

var store *cache.Cache = cache.New(time.Duration(constStorageEntryTTL)*time.Second, time.Duration(constStorageCleanupInterval)*time.Second)

func newStoreEntry(be *builderEntry, ee *extractorEntry) string {
	/* #nosec */
	id := fmt.Sprint(rand.Int())
	for _, used := store.Get(id); used; _, used = store.Get(id) {
		/* #nosec */
		id = fmt.Sprint(rand.Int())
	}

	store.Set(id, &entry{
		created: time.Now(),
		be:      be,
		ee:      ee,
	}, cache.DefaultExpiration)

	return id
}

func getStoreEntry(id string) (e *entry, err error) {
	o, ok := store.Get(id)

	if !ok {
		return nil, errors.New("unknown id")
	}

	e, ok = o.(*entry)
	if !ok {
		panic("unexpected storage issue: storage entry could not be converted to entry type")
	}

	return e, nil
}

func deleteStoreEntry(id string) {
	store.Delete(id)
}
