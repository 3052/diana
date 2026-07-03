# extractsecrets

## amazon

~~~
> play -i com.amazon.avod.thirdpartyclient -abi armeabi-v7a
~~~

works:

~~~
lib\armeabi-v7a\libAIVPlayReadyLicensing.so
�r5�&wv���|(ʖDG�gF37B��ʾ���l�]�R�7yޙ������?��%o�.@@�J      �����S/Eι�d�U���f���\�`&BR�~ױ�@8���+?�^lǰ�=g�y�3
. h|.f}'w�@ޠW�`�Lm嗲�{�        y������q7     ��<��O����R�o�'K`��xQ~h��� ����r�_�|��8ee����:U��+��~�(8j���S3�;}��>��B&�)�V�����6�0��N�U�"��X7CHAI\CERT�,X�LA������4���/��Ч?eۦ�oF�4�EjTO��,�G�:O�y�������`5,��������_��^�_��(��3�
~~~

## hulu

fail:

https://apkmirror.com/apk/disney/hulu-hulu

pass:

https://apkmirror.com/apk/disney/hulu-android-tv

~~~
com.hulu.livingroomplus-config.armeabi_v7a-3009846\lib\armeabi-v7a\libwkf_support.so
163933:CHAI<CERT�
�U� ��?��^P�����N7䱣�k˱�/����l�RG�{��S4Hulu LLCWiiUWiiU�@`��ϡ-��s(�*��f���{��r!�#���g�DO��L��G��8��6�J�t���J���C��Lؓ��Lh#��C�ͪ�
�� �C�[��W'�o��YQy��h`M�X��,��
~~~
