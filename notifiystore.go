/* {{{ Copyright (c) Dr. Stefan Schimanski <stefan.schimanski@gmail.com>, 2016
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE. }}} */

package main

import (
	"k8s.io/client-go/1.4/tools/cache"
)

// NotifyingStore notifies about changes.
type NotifyingStore struct {
	cache.Store
	NotifyFunc func()
}

// Assert that it implements the Store interface.
var _ cache.Store = &NotifyingStore{}

func (u *NotifyingStore) Add(obj interface{}) error {
	if err := u.Store.Add(obj); err != nil {
		return err
	}
	u.NotifyFunc()
	return nil
}

func (u *NotifyingStore) Update(obj interface{}) error {
	if err := u.Store.Update(obj); err != nil {
		return err
	}
	u.NotifyFunc()
	return nil
}

func (u *NotifyingStore) Delete(obj interface{}) error {
	if err := u.Store.Delete(obj); err != nil {
		return err
	}
	u.NotifyFunc()
	return nil
}

func (u *NotifyingStore) Replace(list []interface{}, resourceVersion string) error {
	if err := u.Store.Replace(list, resourceVersion); err != nil {
		return err
	}
	u.NotifyFunc()
	return nil
}
