package sso

import (
	"fmt"
	"os"
	"testing"
	"time"

	yaml "github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type TagsListTestSuite struct {
	suite.Suite
	File TestTagsListFile
}

type TestTagsListFile struct {
}

const (
	TEST_TAGS_LIST_FILE = "./testdata/tags_list.yaml"
)

func TestTagsListSuite(t *testing.T) {
	info, err := os.Stat(TEST_TAGS_LIST_FILE)
	if err != nil {
		log.WithError(err).Fatalf("os.Stat %s", TEST_TAGS_LIST_FILE)
	}

	file, err := os.Open(TEST_TAGS_LIST_FILE)
	if err != nil {
		log.WithError(err).Fatalf("os.Open %s", TEST_TAGS_LIST_FILE)
	}

	defer file.Close()

	buf := make([]byte, info.Size())
	_, err = file.Read(buf)
	if err != nil {
		log.WithError(err).Fatalf("Error reading %d bytes from %s", info.Size(), TEST_TAGS_LIST_FILE)
	}

	s := &TagsListTestSuite{}
	err = yaml.Unmarshal(buf, &s.File)
	if err != nil {
		log.WithError(err).Fatalf("Failed parsing %s", TEST_TAGS_LIST_FILE)
	}

	suite.Run(t, s)
}

func (suite *TagsListTestSuite) TestAddGet() {
	t := suite.T()
	tl := NewTagsList()
	tl.Add("tag", "value")
	tl.Add("tag", "value_2")
	tl.Add("tag", "value_3")
	tl.Add("tag2", "value2")
	tl.Add("tag3", "value3")

	assert.ElementsMatch(t, []string{"value", "value_2", "value_3"}, tl.Get("tag"), "TestAdd_tag")
	assert.ElementsMatch(t, []string{"value2"}, tl.Get("tag2"), "TestAdd_tag2")
	assert.ElementsMatch(t, []string{"value3"}, tl.Get("tag3"), "TestAdd_tag3")
	assert.ElementsMatch(t, []string{}, tl.Get("missing_tag"), "TestAdd_missing_tag")
}

func (suite *TagsListTestSuite) TestAddTags() {
	t := suite.T()
	tl := NewTagsList()

	tags := map[string]string{
		"First":  "one",
		"Second": "two",
		"Third":  "three",
	}
	tl.AddTags(tags)
	assert.ElementsMatch(t, []string{"one"}, tl.Get("First"), "First")
	assert.ElementsMatch(t, []string{"two"}, tl.Get("Second"), "Second")
	assert.ElementsMatch(t, []string{"three"}, tl.Get("Third"), "Third")
}

func (suite *TagsListTestSuite) TestMerge() {
	t := suite.T()
	tl := NewTagsList()

	tl.AddTags(map[string]string{
		"First": "one",
	})

	tl2 := NewTagsList()
	tl2.AddTags(map[string]string{
		"Second": "two",
		"Third":  "three",
	})
	tl.Merge(tl2)

	assert.ElementsMatch(t, []string{"one"}, tl.Get("First"), "First")
	assert.ElementsMatch(t, []string{"two"}, tl.Get("Second"), "Second")
	assert.ElementsMatch(t, []string{"three"}, tl.Get("Third"), "Third")
	assert.ElementsMatch(t, []string{}, tl2.Get("First"), "MissingFirst")
}

func (suite *TagsListTestSuite) TestUniqueKeys() {
	t := suite.T()
	tl := NewTagsList()
	tl.Add("tag", "value")
	tl.Add("tag", "value_2")
	tl.Add("tag", "value_3")
	tl.Add("tag", "value_3")
	tl.Add("tag", "value_3")
	tl.Add("tag", "value_3")

	tl.Add("tag2", "value2")
	tl.Add("tag2", "a_value2")
	tl.Add("tag2", "b_value2")

	tl.Add("tag3", "value3")

	assert.ElementsMatch(t, []string{"tag", "tag2", "tag3"}, tl.UniqueKeys([]string{}), "All")
	assert.ElementsMatch(t, []string{}, tl.UniqueKeys([]string{"tag", "tag2", "tag3"}), "None")
	assert.ElementsMatch(t, []string{"tag2"}, tl.UniqueKeys([]string{"tag", "tag3"}), "Some")
}

func (suite *TagsListTestSuite) TestUniqueValues() {
	t := suite.T()
	tl := NewTagsList()
	tl.Add("tag", "value")
	tl.Add("tag", "value_2")
	tl.Add("tag", "value_3")
	tl.Add("tag", "value_3")
	tl.Add("tag", "value_3")
	tl.Add("tag", "value_3")

	tl.Add("tag2", "value2")
	tl.Add("tag2", "a_value2")
	tl.Add("tag2", "b_value2")

	tl.Add("tag3", "value3")

	assert.Equal(t, []string{"value", "value_2", "value_3"}, tl.UniqueValues("tag"))
	assert.Equal(t, []string{"a_value2", "b_value2", "value2"}, tl.UniqueValues("tag2"))
	assert.Equal(t, []string{"value3"}, tl.UniqueValues("tag3"))
}

func (suite *TagsListTestSuite) TestReformatHistory() {
	t := suite.T()

	// special case, has no timestamp
	assert.Equal(t, "foo", reformatHistory("foo"))

	invalidTS := []string{
		"fooo,",
		"foo,bar",
	}

	for _, x := range invalidTS {
		assert.Panics(t, func() { reformatHistory(x) })
	}

	// valid case
	ninetyMinAgo := time.Now().Add(time.Minute * -90)
	x := fmt.Sprintf("foo,%d", ninetyMinAgo.Unix())
	assert.Equal(t, "[1h30m0s] foo", reformatHistory(x))

	thirtyMinAgo := time.Now().Add(time.Minute * -30)
	x = fmt.Sprintf("foo,%d", thirtyMinAgo.Unix())
	assert.Equal(t, "[0h30m0s] foo", reformatHistory(x))

	// case with comma in account alias
	x = fmt.Sprintf("foo, bar,%d", thirtyMinAgo.Unix())
	assert.Equal(t, "[0h30m0s] foo, bar", reformatHistory(x))
}
